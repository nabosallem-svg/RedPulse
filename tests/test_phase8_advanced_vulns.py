"""Phase 8: Advanced High-Impact Vulnerability Engine Tests.

Tests for:
- New FindingCategory enum values
- New TriageTag enum values
- Specialized PoC generators (RCE, SSRF cloud metadata, JWT, race condition, mass assignment)
- VulnScanner advanced vuln classification
- Ingestion of advanced vuln types
- AlertService integration with new vuln categories
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import select
from datetime import datetime, timedelta, timezone

from app.db.models import (
    Finding, FindingSeverity, FindingStatus, FindingCategory, TriageTag,
    User, Project, ScopeRule, WebhookConfig,
)
from app.services.finding_ingester import (
    ingest_nuclei_finding,
    _generate_poc_curl_rce,
    _generate_poc_curl_ssrf_metadata,
    _generate_poc_curl_jwt,
    _generate_poc_curl_race_condition,
    _generate_poc_curl_mass_assignment,
    _generate_poc_steps_specialized,
    _generate_poc_curl,
    _category_from_template,
    _infer_triage_tags,
)
from app.services.vuln_scanner import VulnScanner
from app.services.alert_service import AlertService


# --- Enum Tests ---


class TestAdvancedEnums:
    """Test that new enum values exist and are accessible."""

    def test_new_finding_categories(self):
        assert FindingCategory.RCE.value == "rce"
        assert FindingCategory.SSRF_CLOUD_METADATA.value == "ssrf_cloud_metadata"
        assert FindingCategory.JWT_VULNERABILITY.value == "jwt_vulnerability"
        assert FindingCategory.RACE_CONDITION.value == "race_condition"
        assert FindingCategory.MASS_ASSIGNMENT.value == "mass_assignment"
        assert FindingCategory.BUSINESS_LOGIC_BYPASS.value == "business_logic_bypass"

    def test_new_triage_tags(self):
        assert TriageTag.REMOTE_CODE_EXECUTION.value == "remote_code_execution"
        assert TriageTag.SSRF_CLOUD_METADATA.value == "ssrf_cloud_metadata"
        assert TriageTag.JWT_ATTACK.value == "jwt_attack"
        assert TriageTag.RACE_CONDITION.value == "race_condition"
        assert TriageTag.MASS_ACCOUNT_TAKEOVER.value == "mass_account_takeover"
        assert TriageTag.BUSINESS_LOGIC_BYPASS.value == "business_logic_bypass"

    def test_all_existing_categories_still_work(self):
        assert FindingCategory.IDOR.value == "idor"
        assert FindingCategory.ACCESS_CONTROL.value == "access_control"
        assert FindingCategory.XSS.value == "xss"
        assert FindingCategory.SSRF.value == "ssrf"

    def test_all_existing_triage_tags_still_work(self):
        assert TriageTag.CRITICAL_RISK.value == "critical_risk"
        assert TriageTag.INSECURE_DIRECT_OBJECT.value == "insecure_direct_object"
        assert TriageTag.CORS_MISCONFIG.value == "cors_misconfig"


# --- VulnScanner Classification Tests ---


class TestVulnScannerClassification:
    """Test VulnScanner._classify_advanced_vuln()."""

    def test_rce_classification(self):
        result = VulnScanner._classify_advanced_vuln("technologies/apache/apache-struts-rce")
        assert result["category"] == "rce"
        assert result["severity_boost"] is True
        assert "remote_code_execution" in result["tags"]

    def test_command_injection_classification(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/command-injection-detect")
        assert result["category"] == "rce"
        assert result["severity_boost"] is True

    def test_ssrf_cloud_metadata_aws(self):
        result = VulnScanner._classify_advanced_vuln("cloud/aws-metadata-exposure")
        assert result["category"] == "ssrf_cloud_metadata"
        assert result["severity_boost"] is True
        assert "ssrf_cloud_metadata" in result["tags"]
        assert "data_exfiltration" in result["tags"]

    def test_ssrf_cloud_metadata_gcp(self):
        result = VulnScanner._classify_advanced_vuln("cloud/gcp-metadata-ssrf")
        assert result["category"] == "ssrf_cloud_metadata"
        assert result["severity_boost"] is True

    def test_ssrf_cloud_metadata_imds(self):
        result = VulnScanner._classify_advanced_vuln("cloud/imds-ssrf-detect")
        assert result["category"] == "ssrf_cloud_metadata"

    def test_jwt_none_algorithm(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/jwt-none-algorithm")
        assert result["category"] == "jwt_vulnerability"
        assert result["severity_boost"] is True
        assert "jwt_attack" in result["tags"]
        assert "auth_bypass" in result["tags"]

    def test_jwt_confusion(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/jwt-algorithm-confusion")
        assert result["category"] == "jwt_vulnerability"
        assert result["severity_boost"] is True

    def test_jwt_weak_secret(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/jwt-secret-bruteforce")
        assert result["category"] == "jwt_vulnerability"

    def test_race_condition(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/race-condition-bypass")
        assert result["category"] == "race_condition"
        assert "race_condition" in result["tags"]

    def test_mass_assignment(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/mass-assignment")
        assert result["category"] == "mass_assignment"
        assert result["severity_boost"] is True
        assert "privilege_escalation" in result["tags"]

    def test_over_posting(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/over-posting-detect")
        assert result["category"] == "mass_assignment"

    def test_business_logic_bypass(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/business-logic-bypass")
        assert result["category"] == "business_logic_bypass"

    def test_price_manipulation(self):
        result = VulnScanner._classify_advanced_vuln("vulnerabilities/negative-amount-bypass")
        assert result["category"] == "business_logic_bypass"

    def test_unknown_template_returns_none(self):
        result = VulnScanner._classify_advanced_vuln("technologies/nginx/nginx-version")
        assert result["category"] is None
        assert result["severity_boost"] is False
        assert result["tags"] == []


# --- Specialized PoC Generator Tests ---


class TestSpecializedPoCGenerators:
    """Test specialized PoC curl generators for each advanced vuln type."""

    def test_rce_poc_curl(self):
        poc = _generate_poc_curl_rce(
            host="target.com",
            matched_at="/api/exec?cmd=test",
            template_id="vulnerabilities/command-injection",
        )
        assert "curl" in poc
        assert "target.com" in poc
        assert "id" in poc  # Safe detection payload

    def test_rce_poc_curl_os_command(self):
        poc = _generate_poc_curl_rce(
            host="target.com",
            matched_at="/api/run",
            template_id="vulnerabilities/os-command-injection",
        )
        assert "curl" in poc
        assert "id" in poc

    def test_ssrf_metadata_poc_curl(self):
        poc = _generate_poc_curl_ssrf_metadata(
            host="target.com",
            matched_at="/api/proxy?url=http://example.com",
            template_id="cloud/aws-metadata-exposure",
        )
        assert "curl" in poc
        assert "169.254.169.254" in poc  # AWS metadata endpoint

    def test_jwt_poc_curl_none_algorithm(self):
        poc = _generate_poc_curl_jwt(
            host="target.com",
            matched_at="/api/auth/verify",
            template_id="vulnerabilities/jwt-none-algorithm",
        )
        assert "curl" in poc
        assert "Authorization" in poc
        # JWT header encodes "none" algorithm (base64 of {"alg":"none",...})
        assert "eyJ" in poc  # base64 JWT header start

    def test_jwt_poc_curl_confusion(self):
        poc = _generate_poc_curl_jwt(
            host="target.com",
            matched_at="/api/auth/verify",
            template_id="vulnerabilities/jwt-confusion-rsa-hmac",
        )
        assert "curl" in poc
        assert "Authorization" in poc

    def test_jwt_poc_curl_weak_secret(self):
        poc = _generate_poc_curl_jwt(
            host="target.com",
            matched_at="/api/auth/verify",
            template_id="vulnerabilities/jwt-secret-bruteforce",
        )
        assert "curl" in poc
        assert "Authorization" in poc

    def test_race_condition_poc_curl(self):
        poc = _generate_poc_curl_race_condition(
            host="target.com",
            matched_at="/api/checkout",
            template_id="vulnerabilities/race-condition",
        )
        assert "curl" in poc
        assert "target.com" in poc

    def test_mass_assignment_poc_curl(self):
        poc = _generate_poc_curl_mass_assignment(
            host="target.com",
            matched_at="/api/users/update",
            template_id="vulnerabilities/mass-assignment",
        )
        assert "curl" in poc
        assert "admin" in poc  # Should include admin role injection
        assert "price" in poc.lower()  # Price manipulation payload

    def test_poc_curl_dispatches_to_rce(self):
        poc = _generate_poc_curl(
            host="target.com",
            matched_at="/api/exec",
            severity=FindingSeverity.CRITICAL,
            template_id="vulnerabilities/rce-detect",
            category="rce",
        )
        assert "curl" in poc
        assert "target.com" in poc

    def test_poc_curl_dispatches_to_ssrf_metadata(self):
        poc = _generate_poc_curl(
            host="target.com",
            matched_at="/api/proxy",
            severity=FindingSeverity.CRITICAL,
            template_id="cloud/aws-metadata",
            category="ssrf_cloud_metadata",
        )
        assert "curl" in poc
        assert "169.254.169.254" in poc

    def test_poc_curl_dispatches_to_jwt(self):
        poc = _generate_poc_curl(
            host="target.com",
            matched_at="/api/auth",
            severity=FindingSeverity.HIGH,
            template_id="vulnerabilities/jwt-none",
            category="jwt_vulnerability",
        )
        assert "curl" in poc
        assert "Authorization" in poc

    def test_poc_curl_dispatches_to_race(self):
        poc = _generate_poc_curl(
            host="target.com",
            matched_at="/api/balance",
            severity=FindingSeverity.HIGH,
            template_id="vulnerabilities/race-condition",
            category="race_condition",
        )
        assert "curl" in poc

    def test_poc_curl_dispatches_to_mass_assignment(self):
        poc = _generate_poc_curl(
            host="target.com",
            matched_at="/api/user",
            severity=FindingSeverity.HIGH,
            template_id="vulnerabilities/mass-assignment",
            category="mass_assignment",
        )
        assert "curl" in poc
        assert "admin" in poc


# --- Specialized PoC Steps Tests ---


class TestSpecializedPoCSteps:
    """Test specialized PoC steps generation for advanced vuln types."""

    def test_rce_steps(self):
        steps = _generate_poc_steps_specialized(
            title="RCE in API",
            template_id="vulnerabilities/rce",
            severity=FindingSeverity.CRITICAL,
            matched_at="/api/exec",
            host="target.com",
            category="rce",
            description="Command injection found",
            sensitive_params=[],
        )
        assert "RCE" in steps or "remote code" in steps.lower()
        assert "id" in steps  # Safe detection payload
        assert "sleep" in steps

    def test_ssrf_cloud_metadata_steps(self):
        steps = _generate_poc_steps_specialized(
            title="SSRF to AWS Metadata",
            template_id="cloud/aws-metadata",
            severity=FindingSeverity.CRITICAL,
            matched_at="/api/proxy",
            host="target.com",
            category="ssrf_cloud_metadata",
            description="SSRF allows accessing cloud metadata",
            sensitive_params=[],
        )
        assert "169.254.169.254" in steps
        assert "metadata" in steps.lower()
        assert "iam" in steps.lower()

    def test_jwt_steps_none_algorithm(self):
        steps = _generate_poc_steps_specialized(
            title="JWT None Algorithm",
            template_id="vulnerabilities/jwt-none-algorithm",
            severity=FindingSeverity.HIGH,
            matched_at="/api/auth",
            host="target.com",
            category="jwt_vulnerability",
            description="JWT allows none algorithm",
            sensitive_params=[],
        )
        assert "none" in steps.lower()
        assert "JWT" in steps or "jwt" in steps

    def test_jwt_steps_confusion(self):
        steps = _generate_poc_steps_specialized(
            title="JWT Algorithm Confusion",
            template_id="vulnerabilities/jwt-confusion",
            severity=FindingSeverity.HIGH,
            matched_at="/api/auth",
            host="target.com",
            category="jwt_vulnerability",
            description="JWT algorithm confusion",
            sensitive_params=[],
        )
        assert "confusion" in steps.lower() or "HS256" in steps

    def test_race_condition_steps(self):
        steps = _generate_poc_steps_specialized(
            title="Race Condition in Checkout",
            template_id="vulnerabilities/race-condition",
            severity=FindingSeverity.HIGH,
            matched_at="/api/checkout",
            host="target.com",
            category="race_condition",
            description="Race condition in payment",
            sensitive_params=[],
        )
        assert "parallel" in steps.lower() or "concurrent" in steps.lower()
        assert "curl" in steps.lower() or "intruder" in steps.lower()

    def test_mass_assignment_steps(self):
        steps = _generate_poc_steps_specialized(
            title="Mass Assignment",
            template_id="vulnerabilities/mass-assignment",
            severity=FindingSeverity.HIGH,
            matched_at="/api/users/update",
            host="target.com",
            category="mass_assignment",
            description="Mass assignment allows role escalation",
            sensitive_params=[],
        )
        assert "role" in steps.lower() or "admin" in steps.lower()
        assert "is_admin" in steps

    def test_business_logic_bypass_steps(self):
        steps = _generate_poc_steps_specialized(
            title="Business Logic Bypass",
            template_id="vulnerabilities/logic-bypass",
            severity=FindingSeverity.HIGH,
            matched_at="/api/checkout",
            host="target.com",
            category="business_logic_bypass",
            description="Logic bypass allows skipping steps",
            sensitive_params=[],
        )
        assert "skip" in steps.lower() or "bypass" in steps.lower()


# --- Finding Ingestion Integration Tests ---


class TestAdvancedVulnIngestion:
    """Test ingesting advanced vuln types through the full ingestion pipeline."""

    def _make_raw(self, template_id, severity="critical", matched_at="/api/test"):
        return {
            "template-id": template_id,
            "template-url": f"https://github.com/projectdiscovery/nuclei-templates/blob/master/{template_id}.yaml",
            "info": {
                "name": f"Test: {template_id}",
                "severity": severity,
                "author": "test",
                "description": f"Automated test for {template_id}",
                "classification": {"cvss-score": 9.8},
                "tags": ["test", "auto"],
            },
            "type": "http",
            "host": "target.com",
            "matched-at": matched_at,
            "ip": "10.0.0.1",
            "timestamp": "2025-01-15T12:00:00Z",
        }

    def test_rce_fingerprint(self):
        from app.services.vuln_scanner import VulnScanner
        raw = self._make_raw("vulnerabilities/rce-detect")
        fp = VulnScanner._generate_fingerprint(raw)
        assert len(fp) == 16
        assert fp == VulnScanner._generate_fingerprint(raw)  # Deterministic

    def test_ssrf_metadata_fingerprint(self):
        from app.services.vuln_scanner import VulnScanner
        raw = self._make_raw("cloud/aws-metadata-exposure")
        fp = VulnScanner._generate_fingerprint(raw)
        assert len(fp) == 16

    def test_jwt_fingerprint(self):
        from app.services.vuln_scanner import VulnScanner
        raw = self._make_raw("vulnerabilities/jwt-none-algorithm")
        fp = VulnScanner._generate_fingerprint(raw)
        assert len(fp) == 16

    def test_classify_finding_rce(self):
        category = _category_from_template("vulnerabilities/rce-detect")
        assert category == FindingCategory.RCE.value

    def test_classify_finding_ssrf_cloud(self):
        category = _category_from_template("cloud/aws-metadata-exposure")
        assert category == FindingCategory.SSRF_CLOUD_METADATA.value

    def test_classify_finding_jwt(self):
        category = _category_from_template("vulnerabilities/jwt-none-algorithm")
        assert category == FindingCategory.JWT_VULNERABILITY.value

    def test_classify_finding_race_condition(self):
        category = _category_from_template("vulnerabilities/race-condition-bypass")
        assert category == FindingCategory.RACE_CONDITION.value

    def test_classify_finding_mass_assignment(self):
        category = _category_from_template("vulnerabilities/mass-assignment")
        assert category == FindingCategory.MASS_ASSIGNMENT.value

    def test_classify_finding_business_logic_bypass(self):
        category = _category_from_template("vulnerabilities/business-logic-bypass")
        assert category == FindingCategory.BUSINESS_LOGIC_BYPASS.value

    def test_infer_triage_tags_rce(self):
        tags = _infer_triage_tags(
            "vulnerabilities/rce-detect",
            FindingSeverity.CRITICAL,
            "/api/exec",
            {"info": {"tags": ["rce"]}},
        )
        assert "remote_code_execution" in tags
        assert "critical_risk" in tags

    def test_infer_triage_tags_ssrf_cloud(self):
        tags = _infer_triage_tags(
            "cloud/aws-metadata-exposure",
            FindingSeverity.CRITICAL,
            "/api/proxy",
            {"info": {"tags": ["ssrf", "cloud"]}},
        )
        assert "ssrf_cloud_metadata" in tags
        assert "critical_risk" in tags

    def test_infer_triage_tags_jwt(self):
        tags = _infer_triage_tags(
            "vulnerabilities/jwt-none-algorithm",
            FindingSeverity.HIGH,
            "/api/auth",
            {"info": {"tags": ["jwt"]}},
        )
        assert "jwt_attack" in tags

    def test_infer_triage_tags_race_condition(self):
        tags = _infer_triage_tags(
            "vulnerabilities/race-condition",
            FindingSeverity.HIGH,
            "/api/balance",
            {"info": {"tags": ["race"]}},
        )
        assert "race_condition" in tags

    def test_infer_triage_tags_mass_assignment(self):
        tags = _infer_triage_tags(
            "vulnerabilities/mass-assignment",
            FindingSeverity.CRITICAL,
            "/api/users/update",
            {"info": {"tags": ["mass-assignment"]}},
        )
        assert "mass_account_takeover" in tags

    def test_infer_triage_tags_business_logic_bypass(self):
        tags = _infer_triage_tags(
            "vulnerabilities/business-logic-bypass",
            FindingSeverity.HIGH,
            "/api/checkout",
            {"info": {"tags": ["business-logic-bypass"]}},
        )
        assert "business_logic_bypass" in tags
