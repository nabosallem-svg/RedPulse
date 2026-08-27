"""RedPulse - Attack Path Chaining & CVSS Aggregation.

Controlled Pentesting: deterministic chaining of separate findings into a single
attack path (e.g., weak CORS + XSS â†’ account takeover). No exploitation,
only correlation and CVSS v4.0 scoring for prioritization.
"""

from typing import List, Dict, Any
import hashlib

from app.services.cvss import calculate_cvss_v4, classify_severity, priority_from_cvss


# Simple chaining rules: which template combinations form a path
_CHAIN_RULES = [
    ({"cors", "cors-misconfig"}, {"xss", "reflected-xss", "stored-xss"}, "CORS + XSS â†’ Account Takeover"),
    ({"open-redirect"}, {"xss"}, "Open Redirect + XSS â†’ Phishing"),
    ({"idor", "bola"}, {"auth-bypass"}, "IDOR/BOLA + Auth Bypass â†’ Data Access"),
    ({"ssrf"}, {"internal-exposure"}, "SSRF â†’ Internal Exposure"),
]


def _normalize_template(tid: str) -> str:
    return tid.lower().strip() if tid else ""


def chain_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Chain separate findings into attack paths.

    Groups findings by host, then checks _CHAIN_RULES for combinations.
    Returns list of CorrelationGroup-like dicts.
    """
    if len(findings) < 2:
        return []

    # Group by host
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        host = f.get("host") or f.get("location") or "unknown"
        by_host.setdefault(host, []).append(f)

    paths = []
    for host, host_findings in by_host.items():
        tids = {_normalize_template(f.get("template_id", "")) for f in host_findings}
        for left_set, right_set, root_cause in _CHAIN_RULES:
            left = tids & left_set
            right = tids & right_set
            if left and right:
                # Find actual finding objects for those tids
                left_findings = [f for f in host_findings if _normalize_template(f.get("template_id", "")) in left_set]
                right_findings = [f for f in host_findings if _normalize_template(f.get("template_id", "")) in right_set]
                affected = left_findings + right_findings
                # Deterministic ID from sorted finding fingerprints
                fps = sorted([f.get("fingerprint") or f.get("template_id", "") for f in affected])
                path_id = hashlib.sha256("|".join(fps).encode()).hexdigest()[:12]
                paths.append({
                    "id": path_id,
                    "host": host,
                    "root_cause": root_cause,
                    "affected_findings": [f.get("template_id") for f in affected],
                    "affected_findings_ids": [f.get("fingerprint") for f in affected],
                    "affected_assets": [host],
                    "severity": _aggregate_severity(affected),
                })
    return paths


def _aggregate_severity(findings: List[Dict[str, Any]]) -> str:
    """Highest severity among findings."""
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    max_sev = "LOW"
    max_rank = -1
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        rank = order.get(sev, 0)
        if rank > max_rank:
            max_rank = rank
            max_sev = sev
    return max_sev


def score_path(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate CVSS for a path: max CVSS + chaining bonus (+0.5 if chained)."""
    if not findings:
        return {"score": 0.0, "vector": "", "severity": "INFO", "priority": 0}

    scores = []
    for f in findings:
        if "cvss_score" in f:
            scores.append(f["cvss_score"])
        else:
            s, _ = calculate_cvss_v4(f.get("severity", "MEDIUM"), f.get("confidence", 70), f.get("asset_criticality", 50))
            scores.append(s)

    max_score = max(scores) if scores else 0.0
    # Chaining bonus: +0.5 if path has 2+ findings from different categories, capped at 10
    bonus = 0.5 if len(findings) >= 2 and len({f.get("template_id") for f in findings}) > 1 else 0.0
    agg_score = min(10.0, round(max_score + bonus, 1))
    _, vector = calculate_cvss_v4(classify_severity(agg_score), 90, 70)
    return {
        "score": agg_score,
        "vector": vector,
        "severity": classify_severity(agg_score),
        "priority": priority_from_cvss(agg_score),
        "is_chained": bonus > 0,
    }


def explain_path(path: Dict[str, Any]) -> Dict[str, Any]:
    """Generate deterministic explanation for a path (flagged non-AI)."""
    return {
        "path_id": path.get("id"),
        "host": path.get("host"),
        "root_cause": path.get("root_cause"),
        "explanation": f"Chained {', '.join(path.get('affected_findings', []))} on {path.get('host')} â†’ {path.get('root_cause')}. Validate each finding's PoC separately; combined impact is {path.get('severity')}.",
        "is_ai": False,
        "is_chained": True,
    }
