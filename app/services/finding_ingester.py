"""RedPulse - Finding Ingestion Service.

Ingests Nuclei scan results into the Finding model with fingerprint-based
deduplication. Maps each finding to the correct Asset and Project.

Phase 5 enhancements:
  - Triage tags for critical/high findings (access control, IDOR, auth bypass, etc.)
  - Auto-generated PoC curl commands and reproduction steps
  - Sensitive object-ID parameter detection
  - Enhanced categorization for business logic & access control flaws
  - Prioritization of Critical and High severity findings

Flow:
  Nuclei raw output -> parse -> generate fingerprint -> classify triage tags
  -> build PoC -> upsert Finding -> link Asset
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, List
from urllib.parse import urlparse, parse_qs, urlencode

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding, FindingSeverity, FindingStatus, FindingCategory, TriageTag,
    Asset, VulnerabilityScan, VulnScanStatus, ReconTool, AssetType,
)

logger = logging.getLogger("redpulse.finding_ingester")

# Object-ID parameter names that indicate potential IDOR / access-control vectors
_IDOR_PARAM_NAMES = {
    "user_id", "account_id", "uid", "id", "doc_id", "document_id",
    "file_id", "order_id", "invoice_id", "profile_id", "patient_id",
    "customer_id", "member_id", "record_id", "item_id", "product_id",
    "group_id", "org_id", "tenant_id", "company_id", "project_id",
    "ticket_id", "message_id", "post_id", "comment_id", "attachment_id",
    "resource_id", "object_id", "target_id", "ref", "key", "token",
    "session", "sid", "cid", "oid",
}

# Template-ID keywords that indicate access control / auth bypass issues
_ACCESS_CONTROL_KEYWORDS = {
    "idor": TriageTag.INSECURE_DIRECT_OBJECT,
    "access-control": TriageTag.BROKEN_ACCESS_CONTROL,
    "privilege": TriageTag.PRIVILEGE_ESCALATION,
    "auth-bypass": TriageTag.AUTH_BYPASS,
    "authentication": TriageTag.AUTH_BYPASS,
    "unauth": TriageTag.AUTH_BYPASS,
    "missing-auth": TriageTag.AUTH_BYPASS,
    "no-auth": TriageTag.AUTH_BYPASS,
    "cors": TriageTag.CORS_MISCONFIG,
    "csrf": TriageTag.CSRF,
    "session": TriageTag.SESSION_HIJACKING,
    "cookie": TriageTag.COOKIE_SECURITY,
    "redirect": TriageTag.OPEN_REDIRECT,
    "secret": TriageTag.SENSITIVE_SECRET,
    "api-key": TriageTag.SENSITIVE_SECRET,
    "token-exposure": TriageTag.SENSITIVE_SECRET,
    "jwt": TriageTag.SENSITIVE_SECRET,
    "hardcoded": TriageTag.SENSITIVE_SECRET,
    "javascript": TriageTag.JAVASCRIPT_SECRETS,
    "js-secret": TriageTag.JAVASCRIPT_SECRETS,
    "env-exposure": TriageTag.JAVASCRIPT_SECRETS,
}

# Template-ID keywords that map to FindingCategory
_CATEGORY_KEYWORDS = {
    "idor": FindingCategory.IDOR,
    "access-control": FindingCategory.ACCESS_CONTROL,
    "auth-bypass": FindingCategory.AUTH_BYPASS,
    "authentication": FindingCategory.AUTH_BYPASS,
    "unauth": FindingCategory.AUTH_BYPASS,
    "business-logic": FindingCategory.BUSINESS_LOGIC,
    "sensitive": FindingCategory.SENSITIVE_DATA,
    "secret": FindingCategory.SENSITIVE_DATA,
    "xss": FindingCategory.XSS,
    "cross-site": FindingCategory.XSS,
    "sqli": FindingCategory.SQLI,
    "sql-injection": FindingCategory.SQLI,
    "ssrf": FindingCategory.SSRF,
    "lfi": FindingCategory.FILE_INCLUSION,
    "rfi": FindingCategory.FILE_INCLUSION,
    "file-inclusion": FindingCategory.FILE_INCLUSION,
    "cors": FindingCategory.MISCONFIGURATION,
    "takeover": FindingCategory.TAKEOVER_INDICATORS,
    "exposure": FindingCategory.EXPOSURE,
    "exposed": FindingCategory.EXPOSURE,
    "leak": FindingCategory.EXPOSURE,
    "misconfig": FindingCategory.MISCONFIGURATION,
    "default": FindingCategory.MISCONFIGURATION,
    "weak": FindingCategory.MISCONFIGURATION,
    "cve": FindingCategory.KNOWN_VULNERABILITIES,
    "vu": FindingCategory.KNOWN_VULNERABILITIES,
}


def _severity_from_nuclei(severity_str: str) -> FindingSeverity:
    """Convert Nuclei severity string to FindingSeverity enum."""
    mapping = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFO,
    }
    return mapping.get(severity_str.lower(), FindingSeverity.INFO)


def _category_from_template(template_id: str) -> str:
    """Infer finding category from Nuclei template ID."""
    tid = template_id.lower()
    # Check ordered by specificity
    for keyword, category in _CATEGORY_KEYWORDS.items():
        if keyword in tid:
            return category.value
    return FindingCategory.TECHNOLOGY_SPECIFIC.value


def _infer_triage_tags(
    template_id: str,
    severity: FindingSeverity,
    matched_at: str,
    raw_finding: dict,
) -> List[str]:
    """Infer triage tags based on template ID, severity, and matched URL.

    Tags help triage teams quickly identify high-impact findings like
    IDOR, broken access control, auth bypass, and sensitive data exposure.
    """
    tid = template_id.lower()
    tags: List[str] = []

    # Always tag critical/high severity
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        tags.append(TriageTag.CRITICAL_RISK.value)

    # Template-based classification
    for keyword, tag in _ACCESS_CONTROL_KEYWORDS.items():
        if keyword in tid:
            tags.append(tag.value)

    # Check matched-at URL for IDOR-like parameters
    idor_params = _extract_idor_params(matched_at)
    if idor_params:
        tags.append(TriageTag.INSECURE_DIRECT_OBJECT.value)
        tags.append(TriageTag.BROKEN_ACCESS_CONTROL.value)

    # Deduplicate and return
    return sorted(set(tags))


def _extract_idor_params(matched_at: str) -> List[str]:
    """Extract object-ID parameter names from the matched-at URL.

    Scans both path segments and query parameters for names that indicate
    potential IDOR / access-control vectors.
    """
    if not matched_at:
        return []

    found = set()
    try:
        parsed = urlparse(matched_at)
        qs = parse_qs(parsed.query)
        for key in qs:
            if key.lower() in _IDOR_PARAM_NAMES:
                found.add(key)
    except Exception:
        pass

    # Also scan path segments for patterns like /users/123 or /docs/{id}
    path_parts = matched_at.split("/")
    for part in path_parts:
        lower = part.lower()
        for param in _IDOR_PARAM_NAMES:
            if param in lower:
                found.add(param)

    return sorted(found)


def generate_fingerprint(
    engagement_id: str,
    template_id: str,
    matched_at: str,
    host: str,
) -> str:
    """Generate a stable fingerprint for finding deduplication.

    Based on: engagement + template + matched endpoint + host.
    Returns first 64 chars of SHA-256 hex digest.
    """
    key = f"{engagement_id}|{template_id}|{matched_at}|{host}"
    return hashlib.sha256(key.encode()).hexdigest()[:64]


def _generate_poc_curl(
    host: str,
    matched_at: str,
    severity: FindingSeverity,
    template_id: str,
    auth_headers: Optional[dict] = None,
) -> str:
    """Auto-generate a PoC curl command for reproduction.

    Constructs a clear, copy-pasteable curl command that reproduces the
    finding. Includes auth headers when available for authenticated findings.
    """
    # Determine target URL
    if matched_at and matched_at.startswith("http"):
        target_url = matched_at
    elif matched_at:
        target_url = f"https://{host}{matched_at}" if matched_at.startswith("/") else f"https://{host}/{matched_at}"
    else:
        target_url = f"https://{host}"

    parts = ["curl", "-v", "-k"]

    # Add auth headers for authenticated scan findings
    if auth_headers:
        for key, value in auth_headers.items():
            parts.append(f'-H "{key}: {value}"')

    # Add common security-testing headers
    parts.append('-H "User-Agent: RedPulse-PoC/1.0"')
    parts.append('-H "Accept: */*"')

    # For severity-critical/high, add verbose output flags
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        parts.append("-w '\\nHTTP_CODE:%{http_code}\\nSIZE:%{size_download}\\n'")

    parts.append(f'"{target_url}"')

    return " \\\n  ".join(parts)


def _generate_poc_steps(
    title: str,
    template_id: str,
    severity: FindingSeverity,
    matched_at: str,
    host: str,
    category: str,
    description: str,
    sensitive_params: List[str],
) -> str:
    """Generate human-readable reproduction steps for high-severity findings.

    Produces structured, step-by-step instructions suitable for manual
    verification by a security reviewer.
    """
    steps = []

    steps.append(f"## PoC: {title}")
    steps.append(f"**Severity:** {severity.value.upper()}")
    steps.append(f"**Category:** {category}")
    steps.append(f"**Template:** {template_id}")
    steps.append("")

    steps.append("### Reproduction Steps")

    if category in ("idor", "access_control", "auth_bypass"):
        steps.append("1. Authenticate as User A and note the target URL/parameters")
        steps.append("2. Extract the object identifiers from the request (see flagged parameters below)")
        if sensitive_params:
            steps.append(f"3. Flagged sensitive parameters: `{', '.join(sensitive_params)}`")
            steps.append("4. Replace the parameter values with identifiers belonging to User B")
            steps.append("5. Observe that the application returns User B's data without authorization checks")
        else:
            steps.append("3. Modify object-ID parameters to reference resources belonging to another user")
            steps.append("4. Verify the application does not enforce ownership verification")
    elif category == "xss":
        steps.append(f"1. Navigate to the vulnerable endpoint: `{matched_at or host}`")
        steps.append("2. Inject a benign probe payload: `<script>alert(document.domain)</script>`")
        steps.append("3. Observe the payload is reflected without sanitization")
    elif category == "sqli":
        steps.append(f"1. Send a request to: `{matched_at or host}`")
        steps.append("2. Append a time-based blind payload: `' OR SLEEP(5)--`")
        steps.append("3. Observe a delay in the response confirming injection")
    elif category == "sensitive_data":
        steps.append(f"1. Access the endpoint: `{matched_at or host}`")
        steps.append("2. Review the response body for exposed secrets, tokens, or credentials")
        steps.append("3. Document the sensitive data found")
    else:
        steps.append(f"1. Access the vulnerable endpoint: `{matched_at or host}`")
        steps.append("2. Follow the attack vector described in the finding description")
        steps.append("3. Verify the vulnerability is exploitable")

    if description:
        steps.append("")
        steps.append("### Description")
        steps.append(description[:500])

    return "\n".join(steps)


async def ingest_nuclei_finding(
    db: AsyncSession,
    engagement_id: str,
    project_id: str,
    user_id: str,
    scan_id: Optional[str],
    raw_finding: dict,
    asset_id: Optional[str] = None,
    auth_headers: Optional[dict] = None,
) -> Finding:
    """Ingest a single Nuclei finding into the Finding table.

    Handles deduplication via fingerprint: if a finding with the same fingerprint
    exists, updates last_seen instead of creating a duplicate.

    Phase 5: For Critical/High severity findings, automatically generates
    triage tags, PoC curl commands, and reproduction steps.

    Args:
        db: AsyncSession
        engagement_id: The engagement UUID
        project_id: The project UUID
        user_id: The user UUID
        scan_id: The VulnerabilityScan UUID (optional)
        raw_finding: Nuclei finding dict with keys:
            template_id, severity, host, matched-at, status-code, etc.
        asset_id: Pre-resolved Asset UUID (optional, will try to resolve if not provided)
        auth_headers: Auth headers used for the scan (for PoC generation)

    Returns:
        The Finding record (new or updated)
    """
    host = raw_finding.get("host", "")
    template_id = raw_finding.get("template_id", "unknown")
    matched_at = raw_finding.get("matched-at", raw_finding.get("matched_at", ""))
    severity_str = raw_finding.get("severity", "info")

    # Resolve asset_id if not provided
    if not asset_id and host:
        asset_result = await db.execute(
            select(Asset).where(
                Asset.engagement_id == engagement_id,
                Asset.value == host,
            )
        )
        asset = asset_result.scalar_one_or_none()
        if asset:
            asset_id = asset.id

    # Generate fingerprint
    fingerprint = generate_fingerprint(engagement_id, template_id, matched_at, host)

    # Check for existing finding with same fingerprint
    result = await db.execute(
        select(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.fingerprint == fingerprint,
        )
    )
    existing = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if existing:
        existing.last_seen = now
        existing.updated_at = now
        # If previously resolved, reopen it (regression)
        if existing.status == FindingStatus.RESOLVED:
            existing.status = FindingStatus.REOPENED
            logger.info(f"Finding {existing.id} reopened (regression detected)")
        await db.flush()
        return existing

    # Create new finding
    severity = _severity_from_nuclei(severity_str)
    category = _category_from_template(template_id)

    # Phase 5: Infer triage tags
    triage_tags = _infer_triage_tags(template_id, severity, matched_at, raw_finding)

    # Phase 5: Extract sensitive parameters (IDOR vectors)
    sensitive_params = _extract_idor_params(matched_at)

    # Phase 5: Generate PoC for high-severity findings
    poc_curl = None
    poc_steps = None
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        poc_curl = _generate_poc_curl(host, matched_at, severity, template_id, auth_headers)
        title = raw_finding.get("info", {}).get("name", template_id) if isinstance(raw_finding.get("info"), dict) else template_id
        description = _build_description(raw_finding)
        poc_steps = _generate_poc_steps(
            title=title or template_id,
            template_id=template_id,
            severity=severity,
            matched_at=matched_at,
            host=host,
            category=category,
            description=description,
            sensitive_params=sensitive_params,
        )

    # Build title from template
    title = raw_finding.get("info", {}).get("name", template_id) if isinstance(raw_finding.get("info"), dict) else template_id
    if not title or title == "unknown":
        title = f"Nuclei finding: {template_id}"

    finding = Finding(
        engagement_id=engagement_id,
        project_id=project_id,
        asset_id=asset_id,
        scan_id=scan_id,
        user_id=user_id,
        title=title[:500],
        template_id=template_id[:200] if template_id else None,
        severity=severity,
        confidence=_confidence_from_severity(severity),
        category=category,
        description=_build_description(raw_finding),
        evidence=raw_finding.get("raw_output", raw_finding.get("matcher-name", "")),
        endpoint=matched_at[:500] if matched_at else None,
        matched_at=matched_at[:500] if matched_at else None,
        impact=_infer_impact(severity, category),
        remediation=raw_finding.get("info", {}).get("remediation", None) if isinstance(raw_finding.get("info"), dict) else None,
        # Phase 5 fields
        triage_tags=triage_tags if triage_tags else None,
        poc_curl=poc_curl,
        poc_steps=poc_steps,
        sensitive_params=sensitive_params if sensitive_params else None,
        # Dedup & lifecycle
        fingerprint=fingerprint,
        status=FindingStatus.NEW,
        first_seen=now,
        last_seen=now,
        raw_output=raw_finding.get("raw_output", "")[:10000] if raw_finding.get("raw_output") else None,
    )

    db.add(finding)
    await db.flush()
    logger.info(f"Ingested finding: {finding.title} [{finding.severity.value}] -> asset={asset_id}"
                f" tags={triage_tags}")
    return finding


def _confidence_from_severity(severity: FindingSeverity) -> int:
    """Map severity to confidence score."""
    return {
        FindingSeverity.CRITICAL: 95,
        FindingSeverity.HIGH: 85,
        FindingSeverity.MEDIUM: 70,
        FindingSeverity.LOW: 50,
        FindingSeverity.INFO: 30,
    }.get(severity, 30)


def _build_description(raw_finding: dict) -> str:
    """Extract description from Nuclei finding."""
    info = raw_finding.get("info", {})
    if isinstance(info, dict):
        return info.get("description", "")[:2000]
    return ""


def _infer_impact(severity: FindingSeverity, category: str) -> str:
    """Infer impact string from severity and category."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        if category in ("idor", "access_control", "auth_bypass"):
            return "Critical access control vulnerability could allow unauthorized data access or privilege escalation"
        if category == "sensitive_data":
            return "Sensitive data exposure could lead to credential theft or account compromise"
        return f"High-severity {category} vulnerability could lead to significant security impact"
    if severity == FindingSeverity.MEDIUM:
        return f"Medium-severity {category} issue that should be addressed"
    return f"Low-severity {category} finding for awareness"


async def ingest_nuclei_findings_batch(
    db: AsyncSession,
    engagement_id: str,
    project_id: str,
    user_id: str,
    scan_id: Optional[str],
    raw_findings: list[dict],
    asset_id: Optional[str] = None,
    auth_headers: Optional[dict] = None,
) -> list[Finding]:
    """Ingest a batch of Nuclei findings.

    Phase 5: Passes auth_headers through for PoC generation of high-severity findings.

    Args:
        db: AsyncSession
        engagement_id: The engagement UUID
        project_id: The project UUID
        user_id: The user UUID
        scan_id: The VulnerabilityScan UUID (optional)
        raw_findings: List of Nuclei finding dicts
        asset_id: Pre-resolved Asset UUID (optional)
        auth_headers: Auth headers used for the scan (for PoC generation)

    Returns:
        List of Finding records (new or updated)
    """
    findings = []
    for raw in raw_findings:
        try:
            finding = await ingest_nuclei_finding(
                db=db,
                engagement_id=engagement_id,
                project_id=project_id,
                user_id=user_id,
                scan_id=scan_id,
                raw_finding=raw,
                asset_id=asset_id,
                auth_headers=auth_headers,
            )
            findings.append(finding)
        except Exception as e:
            logger.warning(f"Failed to ingest finding: {e}")
            continue

    await db.commit()
    logger.info(f"Batch ingest complete: {len(findings)}/{len(raw_findings)} findings ingested")
    return findings
