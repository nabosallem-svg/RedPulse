"""Tests for Compliance Mapping, Remediation Snippets, and Integrations."""

import pytest

from app.services.compliance import map_finding_compliance, compliance_summary
from app.services.remediation_snippets import get_snippet, list_supported
from app.services.integrations import dispatch_finding_webhook


# ---- Compliance Mapping ----------------------------------------------------

def test_compliance_sqli_maps_correctly():
    mapping = map_finding_compliance({"template_id": "sqli", "severity": "HIGH"})
    assert mapping["owasp"] == "A03:2021-Injection"
    assert mapping["pci"] == "6.5.1"
    assert mapping["iso"] == "A.14.2.5"


def test_compliance_xss_maps_correctly():
    mapping = map_finding_compliance({"template_id": "xss"})
    assert mapping["owasp"] == "A03:2021-Injection"
    assert mapping["pci"] == "6.5.7"


def test_compliance_idor_maps_to_broken_access():
    mapping = map_finding_compliance({"template_id": "idor"})
    assert mapping["owasp"] == "A01:2021-Broken Access Control"
    assert mapping["pci"] == "7.2"


def test_compliance_cors_maps_correctly():
    mapping = map_finding_compliance({"template_id": "cors-misconfig"})
    assert mapping["owasp"] == "A01:2021-Broken Access Control"
    assert mapping["iso"] == "A.13.1.3"


def test_compliance_summary_counts():
    findings = [
        {"template_id": "sqli"},
        {"template_id": "xss"},
        {"template_id": "sqli"},
        {"template_id": "idor"},
    ]
    summary = compliance_summary(findings)
    assert summary["total"] == 4
    assert summary["owasp"]["A03:2021-Injection"] == 3
    assert summary["owasp"]["A01:2021-Broken Access Control"] == 1
    assert summary["pci"]["6.5.1"] == 2
    assert "summary" in summary


def test_compliance_default_for_unknown():
    mapping = map_finding_compliance({"template_id": "unknown-xyz-123"})
    assert mapping["owasp"] == "A05:2021-Security Misconfiguration"
    assert mapping["pci"] == "6.2"


# ---- Remediation Snippets --------------------------------------------------

def test_remediation_snippet_sqli_fastapi():
    snippet = get_snippet("sqli", "python-fastapi")
    assert "text(" in snippet or "SELECT" in snippet
    assert "user_input" in snippet
    assert "BAD" in snippet and "GOOD" in snippet


def test_remediation_snippet_xss_express():
    snippet = get_snippet("xss", "nodejs-express")
    assert "he.encode" in snippet or "escape" in snippet.lower()


def test_remediation_snippet_cors_php():
    snippet = get_snippet("cors", "php")
    assert "Access-Control-Allow-Origin" in snippet


def test_remediation_snippet_idor_django():
    snippet = get_snippet("idor", "python-django")
    assert "PermissionDenied" in snippet or "owner" in snippet.lower()


def test_remediation_snippet_fallback():
    # Unknown vuln should return default snippet without crashing
    snippet = get_snippet("unknown_vuln", "python-fastapi")
    assert "OWASP" in snippet or "Remediation" in snippet
    # Unknown stack should fallback to first available for vuln
    snippet2 = get_snippet("sqli", "unknown-stack-xyz")
    assert snippet2  # not empty


def test_list_supported():
    supported = list_supported()
    assert "sqli" in supported["vulns"]
    assert "python-fastapi" in supported["stacks"]


# ---- Integrations (Mock) ---------------------------------------------------

def test_integration_github_mock():
    finding = {"id": "test-finding-123", "template_id": "xss", "severity": "HIGH", "host": "example.com", "evidence": "test"}
    result = dispatch_finding_webhook(finding, "github", repo="myorg/myrepo")
    assert result["target"] == "github"
    assert "github.com" in result["issue_url"]
    assert result["mock"] is True
    assert "XSS" in result["title"] or "xss" in result["title"].lower() or "Finding" in result["title"]


def test_integration_jira_mock():
    finding = {"id": "jira-test-456", "template_id": "sqli", "severity": "CRITICAL", "host": "db.example.com"}
    result = dispatch_finding_webhook(finding, "jira", project="SEC")
    assert result["target"] == "jira"
    assert "atlassian.net" in result["ticket_url"]
    assert result["mock"] is True


def test_integration_unsupported_target_raises():
    with pytest.raises(ValueError, match="Unsupported target"):
        dispatch_finding_webhook({"id": "x"}, "unsupported")


# ---- API Endpoints ---------------------------------------------------------

def test_compliance_summary_endpoint(client):
    """GET /api/v1/projects/{project_id}/compliance-summary returns breakdown."""
    # Signup and create project
    resp = client.post("/api/v1/auth/signup", json={"email": "comp@test.com", "password": "password123"})
    assert resp.status_code == 201
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    proj_resp = client.post("/api/v1/projects/", json={"name": "Comp Proj"}, headers=headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    resp = client.get(f"/api/v1/projects/{project_id}/compliance-summary", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "data" in data
    assert "compliance" in data["data"]
    comp = data["data"]["compliance"]
    assert "owasp" in comp
    assert "pci" in comp
    assert "iso" in comp
    assert "summary" in comp
    assert data["meta"]["total_findings"] >= 0


def test_compliance_summary_tenant_isolation(client):
    """Other user's project should not be visible."""
    # User A
    resp_a = client.post("/api/v1/auth/signup", json={"email": "comp_a@test.com", "password": "password123"})
    token_a = resp_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    proj_resp = client.post("/api/v1/projects/", json={"name": "Comp A Proj"}, headers=headers_a)
    project_id = proj_resp.json()["id"]
    # User B
    resp_b = client.post("/api/v1/auth/signup", json={"email": "comp_b@test.com", "password": "password123"})
    token_b = resp_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}
    resp = client.get(f"/api/v1/projects/{project_id}/compliance-summary", headers=headers_b)
    assert resp.status_code == 404


def test_export_ticket_github_endpoint(client):
    """POST /api/v1/findings/{finding_id}/export-ticket github"""
    resp = client.post("/api/v1/auth/signup", json={"email": "export_github@test.com", "password": "password123"})
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    # Use synthetic finding_id
    finding_id = "sqli-finding-123"
    resp = client.post(f"/api/v1/findings/{finding_id}/export-ticket", json={"target": "github", "repo": "test/repo", "tech_stack": "python-fastapi"}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["target"] == "github"
    assert "github.com" in data["data"]["ticket"]["issue_url"]
    assert "remediation_snippet" in data["data"]
    assert "SELECT" in data["data"]["remediation_snippet"] or "sql" in data["data"]["remediation_snippet"].lower()


def test_export_ticket_jira_endpoint(client):
    """POST /api/v1/findings/{finding_id}/export-ticket jira"""
    resp = client.post("/api/v1/auth/signup", json={"email": "export_jira@test.com", "password": "password123"})
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    finding_id = "xss-finding-456"
    resp = client.post(f"/api/v1/findings/{finding_id}/export-ticket", json={"target": "jira", "repo": "SEC", "tech_stack": "nodejs-express"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["target"] == "jira"
    assert "atlassian.net" in resp.json()["data"]["ticket"]["ticket_url"]


def test_export_ticket_invalid_target(client):
    resp = client.post("/api/v1/auth/signup", json={"email": "export_invalid@test.com", "password": "password123"})
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post("/api/v1/findings/any-id/export-ticket", json={"target": "invalid", "repo": "test/repo"}, headers=headers)
    # Pydantic validation should reject invalid enum -> 422
    assert resp.status_code in (400, 422)


def test_reporting_engine_includes_compliance(client):
    """Reporting engine should include compliance breakdown in JSON and PDF."""
    from app.services.reporting_engine import build_report, generate_pdf_bytes, render_report_html

    findings = [
        {"host": "example.com", "severity": "HIGH", "confidence": 90, "title": "SQLi Test", "template_id": "sqli", "fingerprint": "fp1"},
        {"host": "example.com", "severity": "MEDIUM", "confidence": 70, "title": "XSS Test", "template_id": "xss", "fingerprint": "fp2"},
    ]
    report = build_report("Proj", "Eng", findings, format="html")
    assert "compliance" in report
    assert "owasp" in report["compliance"]
    assert report["compliance"]["total"] == 2
    assert "compliance" in report["executive_summary"]
    # Also check HTML and PDF contain compliance
    html = render_report_html(report)
    assert "Compliance Mapping" in html
    assert "OWASP" in html
    pdf = generate_pdf_bytes(report)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 1000
