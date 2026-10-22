import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.database import Base
from app.models import ScanOutbox, VirusScan
from app.scanner import ScannerUnavailableError
from app.worker import tasks


class VirusScanApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=cls.db_engine)
        cls.TestSession = sessionmaker(
            bind=cls.db_engine, autoflush=False, expire_on_commit=False
        )

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.db_engine)
        cls.db_engine.dispose()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.quarantine = Path(self.tempdir.name)
        self.client = TestClient(main.app)

        with self.TestSession() as db:
            db.query(ScanOutbox).delete()
            db.query(VirusScan).delete()
            db.commit()

        def override_db():
            with self.TestSession() as db:
                yield db

        main.app.dependency_overrides[main.get_db] = override_db
        main.app.dependency_overrides[main.require_firebase_user] = lambda: "test-user"
        self.quarantine_patch = patch.object(main, "QUARANTINE_DIR", self.quarantine)
        self.quarantine_patch.start()
        self.rate_limit_patch = patch.object(main, "enforce_rate_limit")
        self.rate_limit_patch.start()

    def tearDown(self):
        with self.TestSession() as db:
            db.query(ScanOutbox).delete()
            db.query(VirusScan).delete()
            db.commit()
        main.app.dependency_overrides.clear()
        self.rate_limit_patch.stop()
        self.quarantine_patch.stop()
        self.tempdir.cleanup()

    def test_upload_requires_firebase_authentication(self):
        main.app.dependency_overrides.pop(main.require_firebase_user)
        response = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("sample.txt", b"safe test content", "text/plain")},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_upload_binds_scan_to_authenticated_user(self):
        response = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("..\\private.txt", b"safe test content", "text/plain")},
        )

        self.assertEqual(response.status_code, 202)
        payload = response.json()
        self.assertEqual(payload["scan"]["filename"], "private.txt")
        self.assertEqual(payload["scan"]["status"], "queued")
        self.assertNotIn("file_path", payload["scan"])
        self.assertNotIn("access_token", payload)

        scan_id = payload["scan"]["id"]
        unauthorized = self.client.get(f"/api/v1/virus-scans/{scan_id}")
        self.assertEqual(unauthorized.status_code, 404)
        with patch.object(main, "verify_firebase_user", return_value="test-user"):
            authorized = self.client.get(
                f"/api/v1/virus-scans/{scan_id}",
                headers={"Authorization": "Bearer valid-test-token"},
            )
        self.assertEqual(authorized.status_code, 200)
        self.assertEqual(authorized.json()["sha256"], payload["scan"]["sha256"])
        with self.TestSession() as db:
            scan = db.get(VirusScan, scan_id)
            self.assertEqual(scan.owner_uid, "test-user")
            self.assertIsNone(scan.token_hash)
        self.assertEqual(len(list(self.quarantine.iterdir())), 1)

    def test_scan_results_are_not_visible_to_another_firebase_user(self):
        response = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("sample.txt", b"safe test content", "text/plain")},
        )
        scan_id = response.json()["scan"]["id"]

        with patch.object(main, "verify_firebase_user", return_value="different-user"):
            denied = self.client.get(
                f"/api/v1/virus-scans/{scan_id}",
                headers={"Authorization": "Bearer another-valid-token"},
            )

        self.assertEqual(denied.status_code, 404)

    def test_upload_requires_consent_and_valid_scan_mode(self):
        no_consent = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "false"},
            files={"file": ("sample.txt", b"sample", "text/plain")},
        )
        self.assertEqual(no_consent.status_code, 400)

        invalid_mode = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "aggressive", "consent": "true"},
            files={"file": ("sample.txt", b"sample", "text/plain")},
        )
        self.assertEqual(invalid_mode.status_code, 422)
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_upload_rejects_empty_and_oversized_files(self):
        empty = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("empty.txt", b"", "text/plain")},
        )
        self.assertEqual(empty.status_code, 400)

        with patch.object(main, "MAX_UPLOAD_BYTES", 4):
            oversized = self.client.post(
                "/api/v1/virus-scans",
                data={"mode": "standard", "consent": "true"},
                files={"file": ("large.txt", b"12345", "text/plain")},
            )
        self.assertEqual(oversized.status_code, 413)
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_upload_persists_pending_outbox_without_waiting_for_queue(self):
        response = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("sample.txt", b"sample", "text/plain")},
        )

        self.assertEqual(response.status_code, 202)
        scan_id = response.json()["scan"]["id"]
        with self.TestSession() as db:
            scan = db.get(VirusScan, scan_id)
            outbox = db.get(ScanOutbox, scan_id)
            self.assertEqual(scan.status, "queued")
            self.assertEqual(outbox.status, "pending")
            self.assertEqual(outbox.task_name, "virus_scanner.scan_file")

    def test_outbox_dispatches_pending_task_and_marks_it_dispatched(self):
        scan_id = "outbox-test-scan"
        with self.TestSession() as db:
            db.add(
                VirusScan(
                    id=scan_id,
                    token_hash="0" * 64,
                    filename="sample.txt",
                    file_path=str(self.quarantine / scan_id),
                    sha256="0" * 64,
                    size_bytes=6,
                    mode="standard",
                    status="queued",
                )
            )
            db.add(
                ScanOutbox(
                    id=scan_id,
                    scan_id=scan_id,
                    task_name="virus_scanner.scan_file",
                    status="pending",
                )
            )
            db.commit()

        with (
            patch.object(tasks, "SessionLocal", self.TestSession),
            patch.object(tasks.celery_app, "send_task") as send_task,
        ):
            dispatched = tasks.dispatch_pending_scans()

        self.assertEqual(dispatched, 1)
        send_task.assert_called_once_with(
            "virus_scanner.scan_file", args=[scan_id], task_id=scan_id
        )
        with self.TestSession() as db:
            self.assertEqual(db.get(ScanOutbox, scan_id).status, "dispatched")

    def test_transient_scanner_failure_retries_without_deleting_quarantined_file(self):
        scan_id = "retry-test-scan"
        file_path = self.quarantine / scan_id
        file_path.write_bytes(b"sample")
        with self.TestSession() as db:
            db.add(
                VirusScan(
                    id=scan_id,
                    token_hash="0" * 64,
                    filename="sample.txt",
                    file_path=str(file_path),
                    sha256="0" * 64,
                    size_bytes=6,
                    mode="standard",
                    status="queued",
                )
            )
            db.commit()

        with (
            patch.object(tasks, "SessionLocal", self.TestSession),
            patch.object(
                tasks,
                "scan_file",
                side_effect=ScannerUnavailableError("ClamAV is unavailable"),
            ),
            patch.object(
                tasks.scan_virus_file,
                "retry",
                side_effect=RuntimeError("retry scheduled"),
            ) as retry,
        ):
            with self.assertRaisesRegex(RuntimeError, "retry scheduled"):
                tasks.scan_virus_file.run(scan_id)

        retry.assert_called_once()
        self.assertTrue(file_path.exists())
        with self.TestSession() as db:
            self.assertEqual(db.get(VirusScan, scan_id).status, "running")

    def test_retry_attempt_can_resume_a_running_scan(self):
        scan_id = "retry-resume-test-scan"
        file_path = self.quarantine / scan_id
        file_path.write_bytes(b"sample")
        with self.TestSession() as db:
            db.add(
                VirusScan(
                    id=scan_id,
                    token_hash="0" * 64,
                    filename="sample.txt",
                    file_path=str(file_path),
                    sha256="0" * 64,
                    size_bytes=6,
                    mode="standard",
                    status="running",
                )
            )
            db.commit()

        task = tasks.scan_virus_file
        task.push_request(retries=1, delivery_info={})
        try:
            with (
                patch.object(tasks, "SessionLocal", self.TestSession),
                patch.object(tasks, "scan_file", return_value={"verdict": "no_detection"}),
            ):
                task.run(scan_id)
        finally:
            task.pop_request()

        with self.TestSession() as db:
            self.assertEqual(db.get(VirusScan, scan_id).status, "completed")
        self.assertFalse(file_path.exists())

    def test_website_headers_rejects_private_targets(self):
        response = self.client.post("/api/v1/website-headers", json={"url": "http://127.0.0.1:8000"})
        self.assertEqual(response.status_code, 422)

    def test_website_headers_requires_firebase_authentication(self):
        main.app.dependency_overrides.pop(main.require_firebase_user)
        response = self.client.post(
            "/api/v1/website-headers",
            json={"url": "https://example.com"},
        )
        self.assertEqual(response.status_code, 401)

    def test_website_headers_uses_backend_request(self):
        class FakeResponse:
            status = 200
            headers = {"Content-Type": "text/html", "Server": "test"}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        with patch.object(main, "_head_public_url", return_value=(200, FakeResponse.headers)):
            response = self.client.post("/api/v1/website-headers", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["findings"])

    def test_website_headers_rejects_hostnames_resolving_to_private_addresses(self):
        private_address = [(2, 1, 6, "", ("127.0.0.1", 80))]
        with patch.object(main.socket, "getaddrinfo", return_value=private_address):
            response = self.client.post(
                "/api/v1/website-headers", json={"url": "http://example.test"}
            )

        self.assertEqual(response.status_code, 422)

    def test_website_headers_does_not_follow_redirects(self):
        with patch.object(
            main, "_head_public_url", return_value=(302, {"location": "http://127.0.0.1"})
        ) as request:
            response = self.client.post(
                "/api/v1/website-headers", json={"url": "https://example.com"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], 302)
        request.assert_called_once()

    def test_wifi_report_requires_firebase_authentication(self):
        main.app.dependency_overrides.pop(main.require_firebase_user)
        response = self.client.post(
            "/api/v1/wifi-reports",
            json={
                "schemaVersion": 1,
                "capturedAtUtc": "2026-10-19T12:00:00Z",
                "interfaceName": "netsh wlan",
                "ssid": "test-network",
                "signalQualityPercent": 80,
                "authentication": "WPA2-Personal",
                "cipher": "CCMP",
                "securityEnabled": True,
                "enterpriseAuthentication": False,
            },
        )

        self.assertEqual(response.status_code, 401)

    def test_wifi_report_validates_and_returns_findings_without_storing_ssid(self):
        report = {
            "schemaVersion": 1,
            "capturedAtUtc": "2026-10-19T12:00:00Z",
            "interfaceName": "netsh wlan",
            "ssid": "test-network",
            "signalQualityPercent": 80,
            "authentication": "OPEN",
            "cipher": "NONE",
            "securityEnabled": False,
            "enterpriseAuthentication": False,
        }

        response = self.client.post("/api/v1/wifi-reports", json=report)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["stored"])
        self.assertEqual(payload["ssid"], "test-network")
        self.assertEqual(payload["findings"][0]["level"], "high")

    def test_authenticated_endpoints_apply_per_user_rate_limits(self):
        with patch.object(main, "enforce_rate_limit") as rate_limit:
            response = self.client.post(
                "/api/v1/virus-scans",
                data={"mode": "standard", "consent": "true"},
                files={"file": ("sample.txt", b"safe test content", "text/plain")},
            )

        self.assertEqual(response.status_code, 202)
        rate_limit.assert_called_once_with(
            "virus-upload", "test-user", limit=10, window_seconds=3600
        )
    def test_health_reports_all_scanner_services(self):
        redis_client = Mock()
        redis_client.ping.return_value = True

        class FakeClamd:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def sendall(self, _data):
                pass

            def recv(self, _size):
                return b"PONG\0"

        with (
            patch.object(Redis, "from_url", return_value=redis_client),
            patch.object(
                main.celery_app.control,
                "ping",
                return_value=[{"worker": {"ok": "pong"}}],
            ),
            patch.object(main.socket, "create_connection", return_value=FakeClamd()),
            patch.object(main.yara, "compile", return_value=Mock()),
        ):
            response = self.client.get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ready")
        self.assertTrue(response.json()["virus_scan_ready"])
        self.assertTrue(all(response.json()["services"].values()))
        redis_client.close.assert_called_once()

    def test_pages_origin_can_poll_scan_results_but_other_origins_are_not_allowed(self):
        allowed = self.client.options(
            "/api/v1/virus-scans/test-scan",
            headers={
                "Origin": "https://funnythirat.github.io",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-scan-token",
            },
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(
            allowed.headers["access-control-allow-origin"],
            "https://funnythirat.github.io",
        )
        self.assertIn("x-scan-token", allowed.headers["access-control-allow-headers"].lower())

        denied = self.client.options(
            "/api/v1/virus-scans/test-scan",
            headers={
                "Origin": "https://untrusted.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertNotIn("access-control-allow-origin", denied.headers)

    def test_root_serves_the_frontend(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("สแกนไวรัส", response.text)
        self.assertIn("ตรวจสอบ Wi-Fi", response.text)

    def test_login_page_is_served_separately(self):
        response = self.client.get("/login.html")

        self.assertEqual(response.status_code, 200)
        self.assertIn("เข้าสู่ระบบ", response.text)
        self.assertIn("createAccountForm", response.text)

    def test_wifi_helper_is_downloadable(self):
        response = self.client.get("/wifi-scan.ps1")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=\"wifi-scan.ps1\"", response.headers["content-disposition"])
        self.assertIn("netsh wlan show interfaces", response.text)

    def test_local_virus_helper_is_downloadable(self):
        response = self.client.get("/virus-scan.ps1")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=\"virus-scan.ps1\"", response.headers["content-disposition"])
        self.assertIn("Start-MpScan", response.text)

    def test_upload_middleware_rejects_missing_or_oversized_content_length(self):
        async def app_must_not_run(_scope, _receive, _send):
            self.fail("Upload limit middleware should reject the request")

        middleware = main.UploadRequestLimitMiddleware(app_must_not_run)

        async def check(headers):
            messages = []

            async def send(message):
                messages.append(message)

            await middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/api/v1/virus-scans",
                    "headers": headers,
                },
                lambda: None,
                send,
            )
            return messages[0]["status"]

        missing_length_status = asyncio.run(check([]))
        large_length_status = asyncio.run(check([(b"content-length", b"999999999")]))
        self.assertEqual(missing_length_status, 411)
        self.assertEqual(large_length_status, 413)


if __name__ == "__main__":
    unittest.main()
