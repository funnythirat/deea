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

    def test_website_headers_reports_only_checked_headers_in_thai(self):
        target_headers = {
            "content-type": "text/html",
            "server": "test",
            "set-cookie": "session=secret",
            "location": "https://example.com/next?token=secret",
            "x-content-type-options": "nosniff",
        }
        with patch.object(main, "_head_public_url", return_value=(200, target_headers)):
            response = self.client.post("/api/v1/website-headers", json={"url": "http://example.com"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("set-cookie", payload["headers"])
        self.assertNotIn("location", payload["headers"])
        self.assertEqual(payload["headers"]["x-content-type-options"], "nosniff")
        titles = [finding["title"] for finding in payload["findings"]]
        self.assertIn("ไม่พบ Content-Security-Policy", titles)
        self.assertIn("ไม่พบการป้องกันการฝังหน้าเว็บ", titles)
        self.assertNotIn("ไม่พบ Strict-Transport-Security", titles)
        self.assertNotIn("ไม่พบ X-Content-Type-Options", titles)

    def test_wifi_report_flags_windows_wpa_personal_as_legacy_wpa(self):
        report = {
            "schemaVersion": 1,
            "capturedAtUtc": "2026-10-19T12:00:00Z",
            "interfaceName": "netsh wlan",
            "ssid": "test-network",
            "signalQualityPercent": 80,
            "authentication": "WPA-Personal",
            "cipher": "CCMP",
            "securityEnabled": True,
            "enterpriseAuthentication": False,
        }

        response = self.client.post("/api/v1/wifi-reports", json=report)

        self.assertEqual(response.status_code, 200)
        findings = response.json()["findings"]
        self.assertEqual(findings[0]["level"], "medium")
        self.assertEqual(findings[0]["title"], "ใช้ WPA รุ่นเก่า")
        self.assertNotIn("ข้อมูลความปลอดภัยบางส่วนยังประเมินไม่ได้", [f["title"] for f in findings])

    def test_pages_include_security_headers(self):
        response = self.client.get("/")

        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        csp = response.headers["content-security-policy"]
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("https://www.gstatic.com", csp)

        api_response = self.client.get("/api/v1/virus-scans/missing")
        self.assertEqual(api_response.headers["x-content-type-options"], "nosniff")
        self.assertNotIn("content-security-policy", api_response.headers)

    def test_reaper_fails_stale_scans_and_removes_orphaned_files(self):
        old = main.datetime.now(main.timezone.utc).replace(year=2020)
        stale_file = self.quarantine / "stale-scan"
        stale_file.write_bytes(b"stale")
        orphan = self.quarantine / "orphan"
        orphan.write_bytes(b"orphan")
        os_times = (old.timestamp(), old.timestamp())
        main.os.utime(orphan, os_times)
        active_file = self.quarantine / "active-scan"
        active_file.write_bytes(b"active")
        main.os.utime(active_file, os_times)
        legacy_file = self.quarantine / "legacy-running"
        legacy_file.write_bytes(b"legacy")
        recent_file = self.quarantine / "recently-started"
        recent_file.write_bytes(b"recent")
        now = main.datetime.now(main.timezone.utc)
        with self.TestSession() as db:
            for scan_id, status, created_at, started_at, path in (
                ("stale-scan", "running", old, old, stale_file),
                ("legacy-running", "running", old, None, legacy_file),
                ("recently-started", "running", old, now, recent_file),
                ("active-scan", "queued", now, None, active_file),
            ):
                db.add(
                    VirusScan(
                        id=scan_id,
                        owner_uid="test-user",
                        filename="sample.txt",
                        file_path=str(path),
                        sha256="0" * 64,
                        size_bytes=5,
                        mode="standard",
                        status=status,
                        created_at=created_at,
                        started_at=started_at,
                    )
                )
            db.commit()

        with (
            patch.object(tasks, "SessionLocal", self.TestSession),
            patch.object(tasks, "QUARANTINE_DIR", self.quarantine),
        ):
            reaped = tasks.reap_stale_scans.run()

        self.assertEqual(reaped, 2)
        with self.TestSession() as db:
            stale = db.get(VirusScan, "stale-scan")
            self.assertEqual(stale.status, "failed")
            self.assertEqual(stale.error_code, "scan_timeout")
            self.assertEqual(db.get(VirusScan, "legacy-running").status, "failed")
            self.assertEqual(db.get(VirusScan, "recently-started").status, "running")
            self.assertEqual(db.get(VirusScan, "active-scan").status, "queued")
        self.assertFalse(stale_file.exists())
        self.assertFalse(legacy_file.exists())
        self.assertTrue(recent_file.exists())
        self.assertFalse(orphan.exists())
        self.assertTrue(active_file.exists())

    def test_reaper_keeps_upload_when_commit_fails(self):
        old = main.datetime.now(main.timezone.utc).replace(year=2020)
        upload = self.quarantine / "commit-fails"
        upload.write_bytes(b"sample")
        with self.TestSession() as db:
            db.add(
                VirusScan(
                    id="commit-fails",
                    owner_uid="test-user",
                    filename="sample.txt",
                    file_path=str(upload),
                    sha256="0" * 64,
                    size_bytes=6,
                    mode="standard",
                    status="queued",
                    created_at=old,
                )
            )
            db.commit()

        with (
            patch.object(tasks, "SessionLocal", self.TestSession),
            patch.object(tasks, "QUARANTINE_DIR", self.quarantine),
            patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("db down")),
        ):
            with self.assertRaisesRegex(RuntimeError, "db down"):
                tasks.reap_stale_scans.run()

        self.assertTrue(upload.exists())
        with self.TestSession() as db:
            self.assertEqual(db.get(VirusScan, "commit-fails").status, "queued")

    def test_scan_result_is_not_saved_over_reaped_status(self):
        scan_id = "reaped-during-scan"
        file_path = self.quarantine / scan_id
        file_path.write_bytes(b"sample")
        with self.TestSession() as db:
            db.add(
                VirusScan(
                    id=scan_id,
                    owner_uid="test-user",
                    filename="sample.txt",
                    file_path=str(file_path),
                    sha256="0" * 64,
                    size_bytes=6,
                    mode="standard",
                    status="queued",
                )
            )
            db.commit()

        def reaped_while_scanning(path, mode):
            with self.TestSession() as db:
                scan = db.get(VirusScan, scan_id)
                self.assertIsNotNone(scan.started_at)
                scan.status = "failed"
                scan.error_code = "scan_timeout"
                db.commit()
            return {"verdict": "no_detection"}

        with (
            patch.object(tasks, "SessionLocal", self.TestSession),
            patch.object(tasks, "scan_file", side_effect=reaped_while_scanning),
        ):
            tasks.scan_virus_file.run(scan_id)

        with self.TestSession() as db:
            scan = db.get(VirusScan, scan_id)
            self.assertEqual(scan.status, "failed")
            self.assertEqual(scan.error_code, "scan_timeout")
            self.assertIsNone(scan.result)

    def test_started_at_column_is_added_to_existing_table(self):
        legacy_engine = create_engine("sqlite://")
        with legacy_engine.begin() as connection:
            connection.execute(main.text("CREATE TABLE virus_scans (id VARCHAR(36) PRIMARY KEY)"))

        main.ensure_virus_scan_columns(legacy_engine)
        main.ensure_virus_scan_columns(legacy_engine)

        columns = {column["name"] for column in main.inspect(legacy_engine).get_columns("virus_scans")}
        self.assertIn("started_at", columns)

    def test_pages_load_scripts_and_styles_from_same_origin_assets(self):
        for page, assets in (
            ("/", ("assets/index.css", "assets/app.js", "assets/auth-guard.js")),
            ("/login.html", ("assets/login.css", "assets/login.js")),
        ):
            html = self.client.get(page).text
            self.assertNotIn("<style>", html)
            self.assertNotIn('<script type="module">', html)
            self.assertNotIn('style="', html)
            for asset in assets:
                self.assertIn(asset, html)
                response = self.client.get("/" + asset)
                self.assertEqual(response.status_code, 200, asset)
                self.assertTrue(response.text.strip())

        self.assertTrue(self.client.get("/assets/app.js").headers["content-type"].startswith("text/javascript"))
        self.assertTrue(self.client.get("/assets/index.css").headers["content-type"].startswith("text/css"))
        self.assertEqual(self.client.get("/assets/missing.js").status_code, 404)
        self.assertEqual(self.client.get("/assets/..%2Fbackend%2Fapp%2Fmain.py").status_code, 404)
        self.assertEqual(self.client.get("/assets/notes.txt").status_code, 404)

    def test_api_docs_get_their_own_content_security_policy(self):
        page_csp = self.client.get("/").headers["content-security-policy"]
        self.assertNotIn("unsafe-inline", page_csp)

        docs = self.client.get("/api/docs")
        self.assertEqual(docs.status_code, 200)
        docs_csp = docs.headers["content-security-policy"]
        self.assertIn("https://cdn.jsdelivr.net", docs_csp)
        self.assertIn("frame-ancestors 'none'", docs_csp)
        self.assertEqual(docs.headers["x-frame-options"], "DENY")

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

    def test_wifi_scan_live_endpoint(self):
        response = self.client.get("/api/wifi/scan-live")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("success", data)
        self.assertIn("availableNetworks", data)
        self.assertIsInstance(data["availableNetworks"], list)


if __name__ == "__main__":
    unittest.main()

