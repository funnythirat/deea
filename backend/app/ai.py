import logging
from typing import Any
from urllib.parse import urlparse

import requests

from app.config import AI_THREAT_FEED_URL

logger = logging.getLogger(__name__)


def _normalise_findings(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("findings", [])
    if not isinstance(value, list):
        return []
    findings: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        findings.append(item)
    return findings


def fetch_cve_feed(limit: int = 5) -> tuple[list[dict[str, Any]], str]:
    if not AI_THREAT_FEED_URL:
        return [], "not_configured"
    parsed_url = urlparse(AI_THREAT_FEED_URL)
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password:
        logger.error("Configured threat feed URL must be HTTPS and cannot contain credentials")
        return [], "invalid_configuration"
    try:
        response = requests.get(AI_THREAT_FEED_URL, timeout=10)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as error:
        logger.warning("Could not fetch AI threat feed: %s", error)
        return [], "unavailable"

    items: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        candidates = payload.get("vulnerabilities") or payload.get("cves") or payload.get("items") or []
    elif isinstance(payload, list):
        candidates = payload
    else:
        logger.warning("Configured threat feed returned an unsupported JSON structure")
        return [], "invalid_response"
    if not isinstance(candidates, list):
        logger.warning("Configured threat feed entries are not a list")
        return [], "invalid_response"

    for item in candidates[:limit]:
        if isinstance(item, dict):
            items.append({
                "id": item.get("id") or item.get("cve") or item.get("name") or "unknown",
                "summary": item.get("summary") or item.get("description") or "No summary available",
                "severity": item.get("severity") or item.get("cvss") or "unknown",
            })
    return items, "available"


def summarize_findings(raw: Any) -> dict[str, Any]:
    findings = _normalise_findings(raw)
    critical = sum(1 for item in findings if str(item.get("level", "")).lower() in {"critical", "high"})
    warnings = sum(1 for item in findings if str(item.get("level", "")).lower() in {"medium", "high", "critical"})

    recommendations: list[str] = []
    for item in findings:
        recommendation = item.get("recommendation")
        if isinstance(recommendation, str) and recommendation.strip():
            recommendations.append(recommendation.strip())
    if not recommendations:
        recommendations = [
            "ผลสรุปนี้เป็น template ไม่ใช่การรับรองว่าไฟล์หรือระบบปลอดภัย",
            "ตรวจสอบแหล่งที่มาและใช้เครื่องมือป้องกันของระบบปฏิบัติการต่อไป",
        ]

    cves, feed_status = fetch_cve_feed(limit=5)
    summary_text = (
        f"ผลการประเมินพบปัญหาที่ต้องพิจารณา {critical} รายการที่มีความเสี่ยงสูง "
        f"และ {warnings} รายการที่ควรตรวจสอบหรือปรับปรุง"
    )

    return {
        "enabled": False,
        "status": "template_only",
        "summary_method": "rule_based_template",
        "threat_feed_status": feed_status,
        "language": "th",
        "executive_summary": summary_text,
        "findings_count": len(findings),
        "high_risk_findings": critical,
        "recommended_actions": recommendations[:5],
        "cve_feed": cves,
        "source": "configured_feed" if feed_status == "available" else "local-template",
    }
