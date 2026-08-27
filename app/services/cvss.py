"""RedPulse - CVSS v4.0 Scoring Service.

Controlled Pentesting: deterministic scoring from severity/confidence/asset_criticality,
no destructive exploits. Maps Finding attributes to CVSS v4.0 base score (0.0-10.0).
"""

from typing import Tuple


_SEVERITY_BASE = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "INFO": 0.5,
}


def _normalize_severity(severity: str) -> str:
    return severity.strip().upper()


def classify_severity(score: float) -> str:
    """Classify CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"


def calculate_cvss_v4(severity: str, confidence: int, asset_criticality: int = 50) -> Tuple[float, str]:
    """Calculate deterministic CVSS v4.0 base score.

    Formula (controlled, non-exploitative):
      base = SEVERITY_BASE[severity]  (HIGH=8.0, MEDIUM=5.5, LOW=2.5, CRITICAL=9.5)
      confidence_factor = 0.85 + (confidence / 100) * 0.30  # 0.85-1.15
      criticality_factor = 0.90 + (asset_criticality / 100) * 0.20  # 0.90-1.10
      score = base * confidence_factor * criticality_factor
      clamped to 0.0-10.0, rounded to 1 decimal

    Returns:
        (score, vector_string) where vector is CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/...
    """
    sev = _normalize_severity(severity)
    base = _SEVERITY_BASE.get(sev, 5.0)
    confidence = max(0, min(100, confidence))
    asset_criticality = max(0, min(100, asset_criticality))

    confidence_factor = 0.85 + (confidence / 100) * 0.30
    criticality_factor = 0.90 + (asset_criticality / 100) * 0.20
    score = base * confidence_factor * criticality_factor
    score = max(0.0, min(10.0, round(score, 1)))

    # Deterministic vector mapping from severity
    vector_map = {
        "CRITICAL": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "HIGH": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "MEDIUM": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "LOW": "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "INFO": "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    }
    vector = vector_map.get(classify_severity(score), vector_map["MEDIUM"])
    return score, vector


def priority_from_cvss(score: float) -> int:
    """Map CVSS 0-10 to priority 0-100 deterministic."""
    return int(round((score / 10.0) * 100))
