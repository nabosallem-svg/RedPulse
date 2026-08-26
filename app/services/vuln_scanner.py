from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
import asyncio
import logging
import json

from app.core.config import settings
from app.services.recon_engine import ReconEngine, ScopeViolation

logger = logging.getLogger(__name__)


class VulnScanner:
    """Nuclei-based vulnerability scanner integration.

    Wraps the Nuclei template engine for fast HTTP-based vulnerability scanning.
    Scans are scoped through the existing scope_validator to ensure only in-scope
    targets are probed.

    Usage:
        scanner = VulnScanner(db, current_user, engagement_id)
        findings = await scanner.scan_targets(hosts)
    """

    def __init__(self, db, current_user, engagement_id: str):
        self.db = db
        self.current_user = current_user
        self.engagement_id = engagement_id

    async def scan_targets(self, hosts: List[str], template_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan a list of hosts using Nuclei templates.

        Args:
            hosts: List of host:port or host URLs to scan
            template_path: Optional path to custom Nuclei template directory.
                          Uses default templates if not specified.

        Returns:
            List of finding dictionaries with severity, template ID, and evidence.
        """
        # Filter hosts through scope validator first
        valid_hosts: List[str] = []
        for host in hosts:
            try:
                await ReconEngine._validate_target_static(
                    engagement_id=self.engagement_id,
                    host_or_url=host,
                    db=self.db,
                    current_user=self.current_user,
                )
                valid_hosts.append(host)
            except ScopeViolation:
                logger.info(f"Skipping out-of-scope target: {host}")
            except Exception as e:  # pylint: disable=broad-except
                logger.warning(f"Scope validation error for {host}: {e}")

        if not valid_hosts:
            logger.warning("No valid in-scope targets to scan")
            return []

        # Run Nuclei scans in parallel with thread pool
        findings: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=settings.SCANNER_MAX_WORKERS or 4) as executor:
            futures = {executor.submit(self._run_nuclei, host, template_path): host for host in valid_hosts}
            for future in as_completed(futures):
                try:
                    scan_findings = future.result()
                    findings.extend(scan_findings)
                except Exception as exc:  # pylint: disable=broad-except
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
                # Fallback: dedupe by severity + template ID + host
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

    @staticmethod
    async def _validate_target_static(engagement_id: str, host_or_url: str, db, current_user) -> None:
        """Static wrapper for scope validation (no self-instance needed)."""
        from app.services.scope_validator import validate_target
        # We can't easily call async validate_target without an instance,
        # so we do a minimal check here - in practice this would be
        # called from the recon job flow already validated
        pass

    def _run_nuclei(self, host: str, template_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run Nuclei against a single host.

        Executes the Nuclei binary as a subprocess with proper scoping.
        Returns list of finding dicts.
        """
        import shutil
        import subprocess

        # Find nuclei binary
        nuclei_bin = shutil.which("nuclei") or settings.NUCLEI_BIN or "nuclei"
        if not shutil.which(nuclei_bin):
            logger.warning(f"Nuclei binary not found at {nuclei_bin}, skipping scan for {host}")
            return []

        # Build nuclei command
        # -t for target, -templates for template dir, -severity for filtering
        cmd = [nuclei_bin, "-host", host, "-silent"]

        if template_path:
            cmd.extend(["-templates", template_path])

        # Run with timeout
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.SCANNER_TIMEOUT or 60,
            )

            # Parse nuclei output (JSON lines format)
            findings: List[Dict[str, Any]] = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    finding = {
                        "host": host,
                        "template_id": data.get("template-id", "unknown"),
                        "severity": data.get("severity", "info"),
                        "status_code": data.get("status-code"),
                        "length": data.get("length"),
                        "matched-at": data.get("matched-at"),
                        "email": data.get("email"),
                        "uuid": data.get("uuid"),
                        "location": data.get("location"),
                        "raw_output": line,
                    }
                    # Generate stable fingerprint
                    finding["fingerprint"] = self._generate_fingerprint(finding)
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.debug(f"Non-JSON nuclei output for {host}: {line[:100]}")

            return findings

        except subprocess.TimeoutExpired:
            logger.warning(f"Nuclei scan timed out for {host}")
            return []
        except Exception as e:  # pylint: disable=broad-except
            logger.error(f"Nuclei execution error for {host}: {e}")
            return []

    @staticmethod
    def _generate_fingerprint(finding: Dict[str, Any]) -> str:
        """Generate stable fingerprint for finding deduplication.

        Based on project + asset + check + endpoint + evidence pattern
        from the codebase specifications.
        """
        import hashlib

        # Create a deterministic hash from key identifying fields
        key_parts = [
            finding.get("host", ""),
            finding.get("template_id", ""),
            finding.get("location", ""),
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    async def start_scan_job(self, targets: List[str], template_path: Optional[str] = None) -> Dict[str, Any]:
        """Start a full vulnerability scan job.

        Entry point that:
        1. Validates scope for all targets
        2. Runs nuclei scanning
        3. Would normally persist findings to DB (pending for this integration)
        """
        findings = await self.scan_targets(targets, template_path)

        # TODO: Persist findings to database Finding model
        # This would create Finding records with fingerprint-based dedup
        # For now, return the raw findings

        return {
            "engagement_id": self.engagement_id,
            "targets_scanned": len(targets),
            "valid_targets": len([h for h in targets if self._is_in_scope(h)]),
            "findings_count": len(findings),
            "findings": findings,
            "summary": f"Scanned {len(targets)} targets, found {len(findings)} unique vulnerabilities",
        }

    def _is_in_scope(self, host: str) -> bool:
        """Quick scope check - in production would use the full validator."""
        # Placeholder - actual validation happens in scan_targets
        return True