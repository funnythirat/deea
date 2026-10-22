import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import ai, main


class AiFeatureTests(unittest.TestCase):
    def test_summary_identifies_rule_based_template_and_missing_feed(self):
        with patch.object(ai, "AI_THREAT_FEED_URL", ""):
            result = ai.summarize_findings([
                {"level": "high", "recommendation": "Disable the suspicious process"},
                {"level": "medium", "recommendation": "Review affected machine"},
            ])
        self.assertFalse(result["enabled"])
        self.assertEqual(result["status"], "template_only")
        self.assertEqual(result["summary_method"], "rule_based_template")
        self.assertEqual(result["threat_feed_status"], "not_configured")
        self.assertIn("executive_summary", result)
        self.assertGreater(len(result["recommended_actions"]), 0)

    def test_summary_does_not_label_empty_findings_as_suspicious(self):
        with patch.object(ai, "AI_THREAT_FEED_URL", ""):
            result = ai.summarize_findings([])
        self.assertEqual(result["findings_count"], 0)
        self.assertIn("ไม่ใช่การรับรอง", result["recommended_actions"][0])

    def test_threat_feed_requires_https(self):
        with patch.object(ai, "AI_THREAT_FEED_URL", "http://example.test/feed"):
            findings, status = ai.fetch_cve_feed()
        self.assertEqual(findings, [])
        self.assertEqual(status, "invalid_configuration")

    def test_threat_feed_reports_fetch_failure(self):
        with (
            patch.object(ai, "AI_THREAT_FEED_URL", "https://example.test/feed"),
            patch.object(ai.requests, "get", side_effect=ai.requests.Timeout("timeout")),
        ):
            findings, status = ai.fetch_cve_feed()
        self.assertEqual(findings, [])
        self.assertEqual(status, "unavailable")

    def test_threat_feed_accepts_a_valid_empty_feed(self):
        response = unittest.mock.Mock()
        response.json.return_value = {"vulnerabilities": []}
        with (
            patch.object(ai, "AI_THREAT_FEED_URL", "https://example.test/feed"),
            patch.object(ai.requests, "get", return_value=response),
        ):
            findings, status = ai.fetch_cve_feed()
        self.assertEqual(findings, [])
        self.assertEqual(status, "available")

    def test_ai_status_endpoint_requires_authentication(self):
        client = TestClient(main.app)
        response = client.get("/api/v1/ai/status")
        self.assertEqual(response.status_code, 401)

    def test_ai_status_endpoint_describes_current_capability(self):
        dependency = main.require_firebase_user
        main.app.dependency_overrides[dependency] = lambda: "test-user"
        try:
            response = TestClient(main.app).get("/api/v1/ai/status")
        finally:
            main.app.dependency_overrides.pop(dependency)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["enabled"])
        self.assertEqual(response.json()["status"], "template_only")
        self.assertEqual(response.json()["threat_feed_status"], "not_configured")


if __name__ == "__main__":
    unittest.main()
