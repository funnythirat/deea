import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import socket
import ssl
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import yara
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from google.auth.exceptions import TransportError
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field, field_validator
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai import summarize_findings
from app.config import (
    CLAMD_HOST,
    CLAMD_PORT,
    MAX_UPLOAD_BYTES,
    QUARANTINE_DIR,
    REDIS_URL,
    CORS_ORIGINS,
    FIREBASE_PROJECT_ID,
    YARA_RULES_PATH,
)
from app.database import Base, SessionLocal, engine
from app.models import ScanOutbox, VirusScan
from app.worker.celery_app import celery_app


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
STATIC_INDEX = Path(__file__).resolve().parents[2] / "index.html"
STATIC_LOGIN = Path(__file__).resolve().parents[2] / "login.html"
WIFI_HELPER = Path(__file__).resolve().parents[2] / "wifi-scan.ps1"
VIRUS_HELPER = Path(__file__).resolve().parents[2] / "virus-scan.ps1"
if not STATIC_INDEX.is_file():
    STATIC_INDEX = Path(__file__).resolve().parents[1] / "static" / "index.html"
if not STATIC_LOGIN.is_file():
    STATIC_LOGIN = Path(__file__).resolve().parents[1] / "static" / "login.html"
if not WIFI_HELPER.is_file():
    WIFI_HELPER = Path(__file__).resolve().parents[1] / "wifi-scan.ps1"
if not VIRUS_HELPER.is_file():
    VIRUS_HELPER = Path(__file__).resolve().parents[1] / "virus-scan.ps1"



@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="วิถีป้องกันรอบด้าน - File Scanner",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

FIREBASE_AUTH_DOMAIN = f"https://{FIREBASE_PROJECT_ID}.firebaseapp.com" if FIREBASE_PROJECT_ID else ""
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://www.gstatic.com",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self' https://identitytoolkit.googleapis.com "
        "https://securetoken.googleapis.com https://api.osv.dev",
        f"frame-src {FIREBASE_AUTH_DOMAIN}".strip() if FIREBASE_AUTH_DOMAIN else "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)
SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    (b"cross-origin-opener-policy", b"same-origin-allow-popups"),
]


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {key.lower() for key, _ in headers}
                for key, value in SECURITY_HEADERS:
                    if key not in present:
                        headers.append((key, value))
                content_type = next(
                    (value for key, value in headers if key.lower() == b"content-type"), b""
                )
                if content_type.startswith(b"text/html") and b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", CONTENT_SECURITY_POLICY.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class UploadRequestLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        is_upload = (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and scope["path"] == "/api/v1/virus-scans"
        )
        if is_upload:
            raw_length = next(
                (value for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
                None,
            )
            if raw_length is None:
                status, message = 411, "Content-Length is required for file uploads"
            else:
                try:
                    request_length = int(raw_length)
                except ValueError:
                    status, message = 400, "Invalid Content-Length"
                else:
                    if request_length < 0:
                        status, message = 400, "Invalid Content-Length"
                    elif request_length > MAX_UPLOAD_BYTES + 1024 * 1024:
                        status, message = 413, "Request exceeds the upload limit"
                    else:
                        status = 0
                        message = ""
            if status:
                body = json.dumps({"detail": message}).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": status,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


app.add_middleware(UploadRequestLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CORS_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Scan-Token"],
)


def get_db():
    with SessionLocal() as db:
        yield db


def safe_filename(filename: str | None) -> str:
    candidate = (filename or "uploaded-file").replace("\\", "/").split("/")[-1]
    cleaned = "".join(char for char in candidate if char.isprintable() and char not in "\r\n")
    return (cleaned[:255] or "uploaded-file")


def scan_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_firebase_user(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    return verify_firebase_user(authorization)


def optional_firebase_user(
    authorization: Annotated[str | None, Header()] = None,
) -> str | None:
    if authorization is None:
        return None
    return verify_firebase_user(authorization)


def verify_firebase_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Firebase authentication is required")
    if not FIREBASE_PROJECT_ID:
        logger.error("FIREBASE_PROJECT_ID is required for authenticated endpoints")
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Firebase authentication is required")
    try:
        claims = id_token.verify_firebase_token(
            token, GoogleAuthRequest(), FIREBASE_PROJECT_ID
        )
    except ValueError as error:
        raise HTTPException(status_code=401, detail="Firebase token is invalid") from error
    except TransportError as error:
        logger.exception("Could not verify Firebase token")
        raise HTTPException(status_code=503, detail="Authentication service is unavailable") from error
    uid = claims.get("user_id") or claims.get("sub")
    if not isinstance(uid, str) or not uid:
        raise HTTPException(status_code=401, detail="Firebase token has no user identity")
    return uid


_RATE_LIMIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


def enforce_rate_limit(scope: str, user_id: str, limit: int, window_seconds: int) -> None:
    user_key = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
    redis_client = Redis.from_url(
        REDIS_URL,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    try:
        count = redis_client.eval(
            _RATE_LIMIT_SCRIPT,
            1,
            f"rate-limit:{scope}:{user_key}",
            window_seconds,
        )
    except RedisError as error:
        logger.exception("Rate limiter unavailable for %s", scope)
        raise HTTPException(status_code=503, detail="Request limiter is unavailable") from error
    finally:
        redis_client.close()
    if count > limit:
        raise HTTPException(status_code=429, detail="Too many requests; try again later")


def require_scan_upload_user(
    user_id: str = Depends(require_firebase_user),
) -> str:
    enforce_rate_limit("virus-upload", user_id, limit=10, window_seconds=60 * 60)
    return user_id


def require_website_check_user(
    user_id: str = Depends(require_firebase_user),
) -> str:
    enforce_rate_limit("website-check", user_id, limit=30, window_seconds=60 * 60)
    return user_id


def require_wifi_report_user(
    user_id: str = Depends(require_firebase_user),
) -> str:
    enforce_rate_limit("wifi-report", user_id, limit=30, window_seconds=60 * 60)
    return user_id


class WifiReport(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int = Field(alias="schemaVersion", ge=1, le=1)
    captured_at_utc: datetime = Field(alias="capturedAtUtc")
    interface_name: str = Field(alias="interfaceName", min_length=1, max_length=64)
    ssid: str = Field(min_length=1, max_length=128)
    signal_quality_percent: int = Field(alias="signalQualityPercent", ge=0, le=100)
    authentication: str = Field(min_length=1, max_length=64)
    cipher: str = Field(min_length=1, max_length=64)
    security_enabled: bool = Field(alias="securityEnabled")
    enterprise_authentication: bool = Field(alias="enterpriseAuthentication")

    @field_validator("captured_at_utc")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("capturedAtUtc must include a timezone")
        return value


LEGACY_WIFI_AUTHENTICATION = frozenset({"SHARED", "WPA-NONE"})
WPA1_AUTHENTICATION = frozenset({"WPA", "WPA-PSK", "WPA-PERSONAL", "WPA-ENTERPRISE"})


def assess_wifi_report(report: WifiReport) -> list[dict[str, str]]:
    authentication = report.authentication.upper()
    cipher = report.cipher.upper()
    findings: list[dict[str, str]] = []
    is_open = (
        not report.security_enabled
        or authentication in {"OPEN", "NONE"}
        or cipher == "NONE"
    )
    is_legacy = authentication in LEGACY_WIFI_AUTHENTICATION or cipher.startswith("WEP")
    if is_open:
        findings.append(
            {
                "level": "high",
                "title": "เครือข่ายเปิดหรือไม่เข้ารหัส",
                "detail": "ควรตั้งค่า WPA2-AES หรือ WPA3 ที่เราเตอร์",
            }
        )
    elif is_legacy:
        findings.append(
            {
                "level": "high",
                "title": "พบการยืนยันตัวตน/การเข้ารหัสแบบเก่า",
                "detail": "ควรเปลี่ยนเป็น WPA2-AES หรือ WPA3",
            }
        )
    if not is_open and not is_legacy:
        if authentication in WPA1_AUTHENTICATION:
            findings.append(
                {
                    "level": "medium",
                    "title": "ใช้ WPA รุ่นเก่า",
                    "detail": "ควรเปลี่ยนการตั้งค่าเราเตอร์เป็น WPA2-AES หรือ WPA3",
                }
            )
        if cipher == "TKIP":
            findings.append(
                {
                    "level": "medium",
                    "title": "พบการเข้ารหัส TKIP",
                    "detail": "ควรใช้ AES/CCMP หรือ GCMP",
                }
            )
    known_authentication = {
        "OPEN", "WPA2", "WPA2-PSK", "WPA3", "WPA3-SAE", "WPA3-ENT", "WPA3-ENT-192",
    }
    known_authentication.update(LEGACY_WIFI_AUTHENTICATION)
    known_authentication.update(WPA1_AUTHENTICATION)
    known_authentication.update(
        value
        for value in (authentication,)
        if value.startswith(("WPA2-", "WPA3-"))
    )
    known_ciphers = {
        "NONE", "WEP", "WEP40", "WEP104", "TKIP", "AES-CCMP", "GCMP", "GCMP-256",
        "CCMP", "CCMP-256", "BIP", "BIP-GMAC-128", "BIP-GMAC-256", "BIP-CMAC-256",
    }
    if authentication not in known_authentication or cipher not in known_ciphers:
        findings.append(
            {
                "level": "info",
                "title": "ข้อมูลความปลอดภัยบางส่วนยังประเมินไม่ได้",
                "detail": "ไม่รู้จักชนิดการยืนยันตัวตนหรือการเข้ารหัสที่รายงาน จึงไม่สรุปว่าเครือข่ายปลอดภัย",
            }
        )
    elif not is_open and not is_legacy and not findings:
        findings.append(
            {
                "level": "info",
                "title": "ไม่พบสัญญาณการตั้งค่าล้าสมัยจากข้อมูลที่อ่านได้",
                "detail": "เป็นเพียงการประเมินค่าที่รายงาน ไม่ใช่การรับรองความปลอดภัยทั้งหมด",
            }
        )
    if report.signal_quality_percent < 40:
        signal_label = "สัญญาณอ่อน"
    elif report.signal_quality_percent < 60:
        signal_label = "สัญญาณปานกลาง"
    elif report.signal_quality_percent < 80:
        signal_label = "สัญญาณดี"
    else:
        signal_label = "สัญญาณดีมาก"
    findings.append(
        {
            "level": "info",
            "title": f"{signal_label} ({report.signal_quality_percent}%)",
            "detail": "คุณภาพสัญญาณไม่ใช่การประเมินความเสี่ยงด้านความปลอดภัย",
        }
    )
    return findings


def public_scan(scan: VirusScan) -> dict:
    return {
        "id": scan.id,
        "filename": scan.filename,
        "size_bytes": scan.size_bytes,
        "sha256": scan.sha256,
        "mode": scan.mode,
        "status": scan.status,
        "result": scan.result,
        "error_code": scan.error_code,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


def _resolve_public_addresses(hostname: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except OSError as error:
            raise HTTPException(status_code=502, detail="Website hostname could not be resolved") from error
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    else:
        addresses = [str(literal)]

    if not addresses:
        raise HTTPException(status_code=502, detail="Website hostname has no usable addresses")
    try:
        parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
    except ValueError as error:
        raise HTTPException(status_code=502, detail="Website hostname resolved to an invalid address") from error
    if any(not address.is_global for address in parsed_addresses):
        raise HTTPException(status_code=422, detail="Private or non-public targets are not allowed")
    return addresses


def _head_public_url(target) -> tuple[int, dict[str, str]]:
    hostname = target.hostname.rstrip(".")
    port = target.port or (443 if target.scheme == "https" else 80)
    address = _resolve_public_addresses(hostname, port)[0]
    connection = None
    try:
        raw_socket = socket.create_connection((address, port), timeout=12)
        if target.scheme == "https":
            raw_socket = ssl.create_default_context().wrap_socket(
                raw_socket, server_hostname=hostname
            )
            connection = http.client.HTTPSConnection(hostname, port, timeout=12)
        else:
            connection = http.client.HTTPConnection(hostname, port, timeout=12)
        connection.sock = raw_socket
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        host_header = f"[{hostname}]" if ":" in hostname else hostname
        if target.port is not None:
            host_header += f":{target.port}"
        connection.putrequest("HEAD", path, skip_host=True)
        connection.putheader("Host", host_header)
        connection.putheader("User-Agent", "SecurityScanner/1.0")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, headers
    except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as error:
        raise HTTPException(
            status_code=502, detail="Website check failed: target did not respond or rejected HEAD"
        ) from error
    finally:
        if connection is not None:
            connection.close()
        elif "raw_socket" in locals():
            raw_socket.close()


def initialize_database() -> None:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(QUARANTINE_DIR, 0o700)
    Base.metadata.create_all(bind=engine)
    cutoff = datetime.now(timezone.utc).timestamp() - 24 * 60 * 60
    for path in QUARANTINE_DIR.iterdir():
        if path.is_file() and path.stat().st_mtime < cutoff:
            try:
                path.unlink()
                logger.warning("Removed stale quarantine file %s", path.name)
            except OSError:
                logger.exception("Could not remove stale quarantine file %s", path.name)


@app.get("/", include_in_schema=False)
def index():
    if not STATIC_INDEX.is_file():
        raise HTTPException(status_code=404, detail="Frontend is not installed")
    return FileResponse(STATIC_INDEX)


@app.get("/login.html", include_in_schema=False)
def login():
    if not STATIC_LOGIN.is_file():
        raise HTTPException(status_code=404, detail="Login page is not installed")
    return FileResponse(STATIC_LOGIN)


@app.get("/wifi-scan.ps1", include_in_schema=False)
def download_wifi_helper():
    if not WIFI_HELPER.is_file():
        raise HTTPException(status_code=404, detail="Wi-Fi helper is not installed")
    return FileResponse(
        WIFI_HELPER,
        media_type="application/octet-stream",
        filename="wifi-scan.ps1",
    )


@app.get("/virus-scan.ps1", include_in_schema=False)
def download_virus_helper():
    if not VIRUS_HELPER.is_file():
        raise HTTPException(status_code=404, detail="Virus scan helper is not installed")
    return FileResponse(
        VIRUS_HELPER,
        media_type="application/octet-stream",
        filename="virus-scan.ps1",
    )


WEBSITE_SECURITY_HEADERS = (
    ("Content-Security-Policy", "medium", "กำหนด Content-Security-Policy เพื่อลดความเสี่ยงจากสคริปต์และเนื้อหาที่ไม่คาดหมาย"),
    ("Strict-Transport-Security", "medium", "สำหรับเว็บไซต์ HTTPS ให้ตั้งค่า Strict-Transport-Security หลังตรวจสอบการรองรับโดเมนย่อย"),
    ("X-Content-Type-Options", "low", "ตั้งค่า X-Content-Type-Options: nosniff เพื่อป้องกันการเดาชนิด MIME"),
    ("Referrer-Policy", "low", "กำหนด Referrer-Policy เพื่อลดการส่ง URL อ้างอิงไปยังเว็บไซต์อื่น"),
    ("Permissions-Policy", "low", "กำหนด Permissions-Policy เพื่อจำกัดการใช้ความสามารถของ browser"),
)
REPORTED_WEBSITE_HEADERS = tuple(name.lower() for name, _, _ in WEBSITE_SECURITY_HEADERS) + (
    "x-frame-options",
    "server",
    "content-type",
    "location",
)


@app.post("/api/v1/website-headers")
def website_headers(
    payload: dict,
    _user_id: str = Depends(require_website_check_user),
) -> dict:
    raw_url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise HTTPException(status_code=422, detail="A valid website URL is required")
    target = urlparse(raw_url.strip())
    if target.scheme not in {"http", "https"} or target.username or target.password or not target.hostname:
        raise HTTPException(status_code=422, detail="Only http/https URLs without credentials are allowed")
    if target.port not in {None, 80, 443}:
        raise HTTPException(status_code=422, detail="Only standard HTTP/HTTPS ports are allowed")
    host = target.hostname.rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host.lower() in {"localhost", "localhost.localdomain"}:
            raise HTTPException(status_code=422, detail="Private or local targets are not allowed")
    else:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
            raise HTTPException(status_code=422, detail="Private or local targets are not allowed")
    try:
        status_code, headers = _head_public_url(target)
    except HTTPException:
        raise
    findings = [
        {"level": level, "title": "ไม่พบ " + name, "detail": advice, "recommendation": advice}
        for name, level, advice in WEBSITE_SECURITY_HEADERS
        if name.lower() not in headers
        and not (name == "Strict-Transport-Security" and target.scheme != "https")
    ]
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get(
        "content-security-policy", ""
    ).lower():
        findings.append(
            {
                "level": "medium",
                "title": "ไม่พบการป้องกันการฝังหน้าเว็บ",
                "detail": "ตั้งค่า X-Frame-Options หรือ directive frame-ancestors ใน Content-Security-Policy เพื่อช่วยลดความเสี่ยง clickjacking",
            }
        )
    if "server" in headers:
        findings.append(
            {
                "level": "low",
                "title": "เปิดเผยข้อมูล Server header",
                "detail": "พบค่า Server: " + headers["server"][:200] + " พิจารณาลดข้อมูลรุ่นหรือรายละเอียดที่เปิดเผย",
            }
        )
    if not findings:
        findings.append(
            {
                "level": "info",
                "title": "ไม่พบ header ที่ขาดจากรายการที่ตรวจ",
                "detail": "ตรวจด้วยคำขอ HEAD จาก Backend หนึ่งครั้ง ไม่ใช่การรับรองว่าเว็บไซต์ปลอดภัย",
            }
        )
    return {
        "url": target.geturl(),
        "status": status_code,
        "headers": {name: headers[name] for name in REPORTED_WEBSITE_HEADERS if name in headers},
        "findings": findings,
    }


@app.post("/api/v1/wifi-reports")
def receive_wifi_report(
    report: WifiReport,
    _user_id: str = Depends(require_wifi_report_user),
) -> dict:
    return {
        "schemaVersion": report.schema_version,
        "capturedAtUtc": report.captured_at_utc.isoformat(),
        "ssid": report.ssid,
        "signalQualityPercent": report.signal_quality_percent,
        "authentication": report.authentication,
        "cipher": report.cipher,
        "securityEnabled": report.security_enabled,
        "findings": assess_wifi_report(report),
        "stored": False,
    }


@app.get("/api/v1/health")
def health(db: Session = Depends(get_db)) -> dict:
    services = {"database": False, "redis": False, "worker": False, "clamav": False, "yara": False}
    try:
        db.execute(text("SELECT 1"))
        services["database"] = True
    except Exception:
        logger.exception("Health check: database unavailable")

    try:
        from redis import Redis

        redis_client = Redis.from_url(REDIS_URL, socket_connect_timeout=1)
        try:
            services["redis"] = bool(redis_client.ping())
        finally:
            redis_client.close()
    except Exception:
        logger.exception("Health check: Redis unavailable")

    try:
        services["worker"] = bool(celery_app.control.ping(timeout=0.5))
    except Exception:
        logger.exception("Health check: Celery worker unavailable")

    try:
        with socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=1) as connection:
            connection.sendall(b"zPING\0")
            services["clamav"] = connection.recv(64).strip(b"\0").endswith(b"PONG")
    except OSError:
        logger.warning("Health check: ClamAV unavailable")

    try:
        yara.compile(filepath=str(YARA_RULES_PATH))
        services["yara"] = True
    except (yara.Error, OSError):
        logger.exception("Health check: YARA rules unavailable or invalid")

    return {
        "status": "ready" if all(services.values()) else "degraded",
        "services": services,
        "virus_scan_ready": all(services.values()),
    }


@app.get("/api/v1/ai/status")
def ai_status(
    _user_id: str = Depends(require_firebase_user),
) -> dict:
    summary = summarize_findings([])
    return {
        "enabled": summary["enabled"],
        "status": summary["status"],
        "summary_method": summary["summary_method"],
        "threat_feed_status": summary["threat_feed_status"],
        "language": summary["language"],
        "source": summary["source"],
        "description": "Thai summaries use a rule-based template, not an AI model. A configured CVE feed is fetched on request, not on a daily schedule.",
    }


@app.post("/api/v1/ai/summary")
def summarize_scan_report(
    payload: dict,
    _user_id: str = Depends(require_firebase_user),
) -> dict:
    details = payload or {}
    findings = details.get("findings")
    if findings is None and "result" in details:
        findings = details["result"].get("findings") if isinstance(details["result"], dict) else None
    if findings is None and "report" in details:
        findings = details["report"].get("findings") if isinstance(details["report"], dict) else None
    return summarize_findings(findings if findings is not None else [])


@app.post("/api/v1/virus-scans", status_code=202)
async def create_virus_scan(
    file: Annotated[UploadFile, File()],
    mode: Annotated[str, Form()],
    consent: Annotated[bool, Form()],
    user_id: str = Depends(require_scan_upload_user),
    db: Session = Depends(get_db),
) -> dict:
    if mode not in {"standard", "deep"}:
        raise HTTPException(status_code=422, detail="Mode must be standard or deep")
    if not consent:
        raise HTTPException(status_code=400, detail="Consent is required")

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = str(uuid.uuid4())
    file_path = QUARANTINE_DIR / scan_id
    digest = hashlib.sha256()
    size = 0
    try:
        with file_path.open("xb") as destination:
            os.chmod(file_path, 0o600)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File exceeds the 20 MiB upload limit")
                digest.update(chunk)
                destination.write(chunk)
    except HTTPException:
        file_path.unlink(missing_ok=True)
        raise
    except OSError as error:
        file_path.unlink(missing_ok=True)
        logger.exception("Could not write uploaded file into quarantine")
        raise HTTPException(status_code=500, detail="Could not store uploaded file safely") from error
    finally:
        await file.close()

    if size == 0:
        file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Empty files cannot be scanned")

    scan = VirusScan(
        id=scan_id,
        token_hash=None,
        owner_uid=user_id,
        filename=safe_filename(file.filename),
        file_path=str(file_path),
        sha256=digest.hexdigest(),
        size_bytes=size,
        mode=mode,
        status="queued",
    )
    outbox = ScanOutbox(
        id=scan_id,
        scan_id=scan_id,
        task_name="virus_scanner.scan_file",
        status="pending",
    )
    db.add(scan)
    db.add(outbox)
    try:
        db.commit()
    except Exception as error:
        db.rollback()
        file_path.unlink(missing_ok=True)
        logger.exception("Could not persist virus scan request")
        raise HTTPException(status_code=503, detail="Could not persist the scan request") from error

    return {"scan": public_scan(scan)}


@app.get("/api/v1/virus-scans/{scan_id}")
def get_virus_scan(
    scan_id: str,
    user_id: str | None = Depends(optional_firebase_user),
    token: Annotated[str | None, Header(alias="X-Scan-Token")] = None,
    db: Session = Depends(get_db),
) -> dict:
    scan = db.get(VirusScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.owner_uid is not None:
        if user_id is None or not hmac.compare_digest(scan.owner_uid, user_id):
            raise HTTPException(status_code=404, detail="Scan not found")
    elif (
        token is None
        or scan.token_hash is None
        or not hmac.compare_digest(scan.token_hash, scan_token_hash(token))
    ):
        raise HTTPException(status_code=404, detail="Scan not found")
    return public_scan(scan)
