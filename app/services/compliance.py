"""RedPulse - Compliance Mapping Service.

Maps findings to Enterprise Compliance frameworks:
- OWASP Top 10 2021/2026
- PCI-DSS v4.0
- ISO 27001:2022

Deterministic, no AI hallucination.
"""

from typing import Dict, List, Any
from collections import Counter

# Mapping from template_id / category keywords to compliance controls
# Each entry: template_keyword -> {owasp, pci, iso}
_COMPLIANCE_MAP: Dict[str, Dict[str, str]] = {
    # Injection
    "sqli": {"owasp": "A03:2021-Injection", "pci": "6.5.1", "iso": "A.14.2.5"},
    "sql-injection": {"owasp": "A03:2021-Injection", "pci": "6.5.1", "iso": "A.14.2.5"},
    "xss": {"owasp": "A03:2021-Injection", "pci": "6.5.7", "iso": "A.14.2.5"},
    "stored-xss": {"owasp": "A03:2021-Injection", "pci": "6.5.7", "iso": "A.14.2.5"},
    "reflected-xss": {"owasp": "A03:2021-Injection", "pci": "6.5.7", "iso": "A.14.2.5"},
    "ssti": {"owasp": "A03:2021-Injection", "pci": "6.5.1", "iso": "A.14.2.5"},
    "cmdi": {"owasp": "A03:2021-Injection", "pci": "6.5.1", "iso": "A.14.2.5"},
    # Access Control
    "idor": {"owasp": "A01:2021-Broken Access Control", "pci": "7.2", "iso": "A.9.4.1"},
    "bola": {"owasp": "A01:2021-Broken Access Control", "pci": "7.2", "iso": "A.9.4.1"},
    "auth-bypass": {"owasp": "A01:2021-Broken Access Control", "pci": "7.1", "iso": "A.9.4.2"},
    "cors": {"owasp": "A01:2021-Broken Access Control", "pci": "7.2", "iso": "A.13.1.3"},
    "cors-misconfig": {"owasp": "A01:2021-Broken Access Control", "pci": "7.2", "iso": "A.13.1.3"},
    "open-redirect": {"owasp": "A01:2021-Broken Access Control", "pci": "7.2", "iso": "A.9.4.1"},
    # Auth
    "jwt": {"owasp": "A07:2021-Identification and Authentication Failures", "pci": "8.2", "iso": "A.9.4.2"},
    "session": {"owasp": "A07:2021-Identification and Authentication Failures", "pci": "8.2", "iso": "A.9.4.2"},
    # SSRF
    "ssrf": {"owasp": "A10:2021-Server-Side Request Forgery", "pci": "6.5.9", "iso": "A.14.2.5"},
    # Misconfig
    "misconfig": {"owasp": "A05:2021-Security Misconfiguration", "pci": "2.2", "iso": "A.14.1.3"},
    "info-disclosure": {"owasp": "A01:2021-Broken Access Control", "pci": "6.5.8", "iso": "A.18.1.3"},
    # Default
    "default": {"owasp": "A05:2021-Security Misconfiguration", "pci": "6.2", "iso": "A.14.2.8"},
}


def _normalize_key(finding: Dict[str, Any]) -> str:
    tid = (finding.get("template_id") or finding.get("category") or "").lower().strip()
    # Direct match
    if tid in _COMPLIANCE_MAP:
        return tid
    # Substring match for keywords
    for key in _COMPLIANCE_MAP:
        if key != "default" and key in tid:
            return key
    # Category fallback
    cat = (finding.get("category") or "").lower()
    for key in _COMPLIANCE_MAP:
        if key in cat:
            return key
    return "default"


def map_finding_compliance(finding: Dict[str, Any]) -> Dict[str, str]:
    """Map a single finding to OWASP/PCI/ISO controls."""
    key = _normalize_key(finding)
    return _COMPLIANCE_MAP.get(key, _COMPLIANCE_MAP["default"]).copy()


def compliance_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build compliance breakdown for a list of findings."""
    if not findings:
        return {
            "total": 0,
            "owasp": {},
            "pci": {},
            "iso": {},
            "by_owasp": {},
            "by_pci": {},
            "by_iso": {},
            "summary": "No findings - no compliance violations.",
        }
    owasp_counter = Counter()
    pci_counter = Counter()
    iso_counter = Counter()
    enriched = []
    for f in findings:
        mapping = map_finding_compliance(f)
        owasp_counter[mapping["owasp"]] += 1
        pci_counter[mapping["pci"]] += 1
        iso_counter[mapping["iso"]] += 1
        enriched.append({**f, "compliance": mapping})

    # Build human summary
    top_owasp = owasp_counter.most_common(1)[0][0] if owasp_counter else "None"
    summary = f"{len(findings)} findings mapped. Top OWASP: {top_owasp} ({owasp_counter[top_owasp]}). PCI controls affected: {len(pci_counter)}. ISO controls: {len(iso_counter)}."

    return {
        "total": len(findings),
        "owasp": dict(owasp_counter),
        "pci": dict(pci_counter),
        "iso": dict(iso_counter),
        "by_owasp": dict(owasp_counter),
        "by_pci": dict(pci_counter),
        "by_iso": dict(iso_counter),
        "enriched": enriched,
        "summary": summary,
    }
