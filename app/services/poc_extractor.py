"""RedPulse - Safe PoC Extractor (Passive, Non-Destructive).

Controlled Pentesting: only stores Request/Response dumps from already-validated
findings. Never executes destructive payloads. PoC is marked as passive.
"""

from typing import Dict, Any, Optional
import hashlib
import datetime


def extract_poc(
    finding: Dict[str, Any],
    request_dump: Optional[str] = None,
    response_dump: Optional[str] = None,
) -> Dict[str, Any]:
    """Extract and normalize safe PoC from finding.

    Args:
        finding: Finding dict with host, template_id, severity, etc.
        request_dump: Raw HTTP request (optional, sanitized)
        response_dump: Raw HTTP response (optional, truncated)

    Returns:
        PoC dict with fingerprint, request/response, is_passive flag
    """
    # Sanitize: truncate to avoid storing huge bodies, strip secrets
    def _sanitize(text: Optional[str], limit: int = 2048) -> Optional[str]:
        if not text:
            return None
        # Basic secret redaction
        for secret in ["Authorization:", "Cookie:", "X-Api-Key:"]:
            if secret.lower() in text.lower():
                text = text[: text.lower().find(secret.lower()) + len(secret)] + " [REDACTED]"
                break
        return text[:limit]

    host = finding.get("host") or finding.get("location") or "unknown"
    template_id = finding.get("template_id") or "unknown"

    poc = {
        "finding_id": finding.get("finding_id") or finding.get("uuid"),
        "host": host,
        "template_id": template_id,
        "severity": finding.get("severity", "info"),
        "request": _sanitize(request_dump or finding.get("raw_request") or f"GET / HTTP/1.1\nHost: {host}"),
        "response": _sanitize(response_dump or finding.get("raw_output") or finding.get("response") or ""),
        "is_passive": True,
        "is_ai": False,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    # Stable fingerprint for PoC dedup
    key = f"{host}|{template_id}|{poc['request'][:100]}"
    poc["poc_fingerprint"] = hashlib.sha256(key.encode()).hexdigest()[:16]
    return poc
