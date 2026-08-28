"""RedPulse - Nuclei Vulnerability Scanner.

Wraps the Nuclei template engine for HTTP-based vulnerability scanning.
Scans are scoped through scope_validator to ensure only in-scope targets
are probed. Persists findings to the Finding model via finding_ingester.

Supports authenticated scanning: pass auth_headers / auth_cookies to scan
behind login portals (Phase 5).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
import logging
import json
import re
import shutil
import subprocess

from app.core.config import settings

logger = logging.getLogger("redpulse.vuln_scanner")

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


class VulnScanner:
    """Nuclei-based vulnerability scanner integration.

    Wraps the Nuclei template engine for fast HTTP-based vulnerability scanning.
    Scans are scoped through the existing scope_validator to ensure only in-scope
    targets are probed.

    Supports authenticated scanning via optional auth_headers / auth_cookies
    parameters, which are passed as Nuclei CLI flags (-H for headers, -cookie
    for cookies).

    Usage:
        scanner = VulnScanner(db, current_user, engagement_id)
        findings = await scanner.scan_targets(hosts)
        findings = await scanner.scan_targets(
            hosts,
            auth_headers={"Authorization": "Bearer xxx"},
            auth_cookies="session=abc123",
        )
    """

    def __init__(self, db, current_user, engagement_id: str):
        self.db = db
        self.current_user = current_user
        self.engagement_id = engagement_id

    async def scan_targets(
        self,
        hosts: List[str],
        template_path: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Scan a list of hosts using Nuclei templates.

        Args:
            hosts: List of host:port or host URLs to scan
            template_path: Optional path to custom Nuclei template directory.
                          Uses default templates if not specified.
            auth_headers: Optional dict of HTTP headers for authenticated scanning.
            auth_cookies: Optional cookie string for authenticated crawling.

        Returns:
            List of finding dictionaries with severity, template ID, and evidence.
        """
        # Filter hosts through scope validator first
        valid_hosts: List[str] = []
        for host in hosts:
            try:
                await self._validate_target(host)
                valid_hosts.append(host)
            except Exception as e:
                logger.info(f"Skipping target {host}: {e}")

        if not valid_hosts:
            logger.warning("No valid in-scope targets to scan")
            return []

        # Run Nuclei scans in parallel with thread pool
        findings: List[Dict[str, Any]] = []
        max_workers = getattr(settings, "SCANNER_MAX_WORKERS", None) or 4

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._run_nuclei, host, template_path, auth_headers, auth_cookies
                ): host
                for host in valid_hosts
            }
            for future in as_completed(futures):
                try:
                    scan_findings = future.result()
                    findings.extend(scan_findings)
                except Exception as exc:
                    host = futures[future]
                    logger.error(f"Nuclei scan failed for {host}: {exc}")

        # Deduplicate findings by fingerprint
        seen_fingerprints = set()
        unique_findings: List[Dict[str, Any]] = []
        for finding in findings:
            fp = finding.get("fingerprint")
            if fp and fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                unique_findings.append(finding)
            elif not fp:
                dedupe_key = (
                    finding.get("severity"),
                    finding.get("template_id"),
                    finding.get("host"),
                )
                if dedupe_key not in [f.get("dedupe_key") for f in unique_findings]:
                    unique_findings.append(finding)

        logger.info(f"Nuclei scan completed: {len(valid_hosts)} hosts scanned, "
                     f"{len(unique_findings)} unique findings")
        return unique_findings

    async def _validate_target(self, host: str) -> None:
        """Validate target scope via scope_validator."""
        from app.services.scope_validator import validate_target
        await validate_target(
            engagement_id=self.engagement_id,
            host_or_url=host,
            db=self.db,
            current_user=self.current_user,
        )

    @staticmethod
    async def _validate_target_static(engagement_id: str, host_or_url: str, db, current_user) -> None:
        """Static wrapper for scope validation - always via scope_validator.validate_target."""
        from app.services.scope_validator import validate_target
        await validate_target(
            engagement_id=engagement_id,
            host_or_url=host_or_url,
            db=db,
            current_user=current_user,
        )

    @staticmethod
    def _extract_idor_params(matched_at: str) -> List[str]:
        """Extract object-ID parameter names from the matched-at URL/query string.

        Scans both path segments and query parameters for names that indicate
        potential IDOR / access-control vectors (e.g. user_id, doc_id, account_id).
        """
        if not matched_at:
            return []

        found = set()
        try:
            from urllib.parse import urlparse, parse_qs
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

    def _run_nuclei(
        self,
        host: str,
        template_path: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Run Nuclei against a single host.

        Executes the Nuclei binary as a subprocess with proper scoping.
        Optionally passes auth headers/cookies for authenticated scanning.
        Returns list of finding dicts.
        """
        nuclei_bin = shutil.which("nuclei") or getattr(settings, "NUCLEI_BIN", "nuclei")
        if not nuclei_bin or not shutil.which(nuclei_bin):
            logger.warning(f"Nuclei binary not found at {nuclei_bin}, skipping scan for {host}")
            return []

        cmd = [nuclei_bin, "-host", host, "-silent"]
        if template_path:
            cmd.extend(["-templates", template_path])

        # Authenticated scanning: pass headers and cookies to Nuclei
        if auth_headers:
            for key, value in auth_headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        if auth_cookies:
            cmd.extend(["-cookie", auth_cookies])

        timeout = getattr(settings, "SCANNER_TIMEOUT", None) or 60

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            findings: List[Dict[str, Any]] = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    matched_at = data.get("matched-at", "")
                    finding = {
                        "host": host,
                        "template_id": data.get("template-id", "unknown"),
                        "severity": data.get("severity", "info"),
                        "status_code": data.get("status-code"),
                        "length": data.get("length"),
                        "matched-at": matched_at,
                        "email": data.get("email"),
                        "uuid": data.get("uuid"),
                        "location": data.get("location"),
                        "info": data.get("info", {}),
                        "raw_output": line,
                        "authenticated_scan": bool(auth_headers or auth_cookies),
                    }
                    finding["fingerprint"] = self._generate_fingerprint(finding)
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.debug(f"Non-JSON nuclei output for {host}: {line[:100]}")

            return findings

        except subprocess.TimeoutExpired:
            logger.warning(f"Nuclei scan timed out for {host}")
            return []
        except Exception as e:
            logger.error(f"Nuclei execution error for {host}: {e}")
            return []

    @staticmethod
    def _generate_fingerprint(finding: Dict[str, Any]) -> str:
        """Generate stable fingerprint for finding deduplication."""
        import hashlib
        key_parts = [
            finding.get("host", ""),
            finding.get("template_id", ""),
            finding.get("location", finding.get("matched-at", "")),
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    @staticmethod
    def _classify_advanced_vuln(template_id: str, matched_at: str = "") -> Dict[str, Any]:
        """Classify advanced high-impact vulnerability from Nuclei template ID.

        Phase 8: Identifies RCE, SSRF cloud metadata, JWT, race condition,
        mass assignment, and business logic bypass from template patterns.

        Returns dict with: category, severity_boost, tags, description_hint
        """
        tid = template_id.lower()
        result = {
            "category": None,
            "severity_boost": False,
            "tags": [],
            "description_hint": "",
        }

        # JWT Vulnerabilities — checked before RCE to avoid "bruteforce" → "rce" false match
        if any(kw in tid for kw in ("jwt-none", "jwt-algorithm", "jwt-confusion", "jwt-signing", "jwt-secret")):
            result["category"] = "jwt_vulnerability"
            result["severity_boost"] = True
            result["tags"] = ["jwt_attack", "critical_risk", "auth_bypass"]
            result["description_hint"] = "JWT vulnerability allows authentication bypass or token forgery"

        # RCE / Command Injection
        elif any(kw in tid for kw in ("rce", "remote-code", "command-injection", "os-command", "code-injection")):
            result["category"] = "rce"
            result["severity_boost"] = True
            result["tags"] = ["remote_code_execution", "critical_risk"]
            result["description_hint"] = "Remote code execution allows arbitrary command execution on the server"

        # SSRF Cloud Metadata
        elif any(kw in tid for kw in ("cloud-metadata", "aws-metadata", "gcp-metadata", "azure-metadata", "imds")):
            result["category"] = "ssrf_cloud_metadata"
            result["severity_boost"] = True
            result["tags"] = ["ssrf_cloud_metadata", "critical_risk", "data_exfiltration"]
            result["description_hint"] = "SSRF to cloud metadata endpoint exposes instance credentials and configuration"

        # Race Condition
        elif any(kw in tid for kw in ("race-condition", "race")):
            result["category"] = "race_condition"
            result["tags"] = ["race_condition", "business_logic_flaw"]
            result["description_hint"] = "Race condition allows inconsistent state through concurrent requests"

        # Mass Assignment
        elif any(kw in tid for kw in ("mass-assignment", "property-injection", "over-posting")):
            result["category"] = "mass_assignment"
            result["severity_boost"] = True
            result["tags"] = ["mass_account_takeover", "privilege_escalation"]
            result["description_hint"] = "Mass assignment allows injection of privileged fields"

        # Business Logic Bypass
        elif any(kw in tid for kw in ("business-logic-bypass", "logic-bypass", "negative-amount", "price-manipulation")):
            result["category"] = "business_logic_bypass"
            result["tags"] = ["business_logic_bypass", "business_logic_flaw"]
            result["description_hint"] = "Business logic flaw allows bypassing intended workflow"

        return result

    async def start_scan_job(
        self,
        targets: List[str],
        template_path: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a full vulnerability scan job.

        Validates scope, runs Nuclei, and returns findings.
        """
        findings = await self.scan_targets(targets, template_path, auth_headers, auth_cookies)

        return {
            "engagement_id": self.engagement_id,
            "targets_scanned": len(targets),
            "findings_count": len(findings),
            "findings": findings,
            "summary": f"Scanned {len(targets)} targets, found {len(findings)} unique vulnerabilities",
        }
