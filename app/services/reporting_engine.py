"""RedPulse - Professional Reporting Engine.

Controlled Pentesting: transforms Findings + PoCs + CVSS into executive PDF/HTML.
Deterministic, no AI hallucination; AI layer is optional and flagged is_ai.
"""

from typing import List, Dict, Any, Optional
import datetime
import io

from app.services.cvss import calculate_cvss_v4, classify_severity, priority_from_cvss
from app.services.compliance import compliance_summary as _compliance_summary


def generate_executive_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate executive summary from findings."""
    if not findings:
        return {"total": 0, "by_severity": {}, "highest_cvss": 0.0, "summary": "No findings. Target appears secure within tested scope."}

    by_severity: Dict[str, int] = {}
    highest = 0.0
    for f in findings:
        sev = f.get("severity", "info").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        # Use existing cvss or compute
        score = f.get("cvss_score")
        if score is None:
            score, _ = calculate_cvss_v4(f.get("severity", "LOW"), f.get("confidence", 50))
        highest = max(highest, score)

    summary = f"Scanned {len(findings)} unique findings. Highest CVSS {highest} ({classify_severity(highest)}). "
    summary += ", ".join(f"{k}: {v}" for k, v in by_severity.items())
    return {"total": len(findings), "by_severity": by_severity, "highest_cvss": highest, "summary": summary}


def build_report(
    project_name: str,
    engagement_name: str,
    findings: List[Dict[str, Any]],
    format: str = "html",
    include_poc: bool = True,
    delta: Optional[Dict[str, Any]] = None,
    retest_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build professional report dict (rendered to PDF/HTML by caller).

    Args:
        project_name: Project display name
        engagement_name: Engagement display name
        findings: List of finding dicts (with optional cvss_score, poc)
        format: html or json
        include_poc: whether to include Request/Response dumps
        delta: optional delta metrics from delta_engine.calculate_delta
        retest_results: optional list of retest verification results

    Returns:
        Report dict with executive_summary, findings table, remediation
    """
    # Enrich findings with CVSS if missing
    enriched = []
    for f in findings:
        if "cvss_score" not in f:
            score, vector = calculate_cvss_v4(f.get("severity", "MEDIUM"), f.get("confidence", 70), f.get("asset_criticality", 50))
            f = {**f, "cvss_score": score, "cvss_vector": vector, "cvss_severity": classify_severity(score), "priority": priority_from_cvss(score)}
        enriched.append(f)

    # Sort by CVSS descending
    enriched.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

    executive = generate_executive_summary(enriched)
    compliance = _compliance_summary(enriched)
    # Merge compliance into executive for frontend
    executive["compliance"] = compliance

    # Build sections with retest badges
    retest_map = {r.get("finding_id") or r.get("fingerprint"): r for r in (retest_results or [])}
    sections = []
    for f in enriched:
        # Check if this finding has a retest verification
        fid = f.get("fingerprint") or f.get("id") or f.get("template_id")
        retest = retest_map.get(fid) or retest_map.get(f.get("id")) or retest_map.get(f.get("fingerprint"))
        badge = None
        if retest:
            if retest.get("new_status") == "RESOLVED" or retest.get("verified"):
                badge = {"label": "Verified Fixed", "color": "green", "verified_at": retest.get("verified_at")}
            elif retest.get("still_vulnerable"):
                badge = {"label": "Still Vulnerable", "color": "red"}
        # Also check finding's own status
        if not badge and f.get("status") == "resolved":
            badge = {"label": "Resolved", "color": "green"}
        section = {
            "title": f.get("title") or f.get("template_id") or "Untitled Finding",
            "severity": f.get("severity"),
            "cvss_score": f.get("cvss_score"),
            "cvss_vector": f.get("cvss_vector"),
            "priority": f.get("priority"),
            "host": f.get("host") or f.get("location"),
            "description": f.get("description") or f.get("evidence") or "",
            "impact": f.get("impact") or "See CVSS severity.",
            "remediation": f.get("remediation") or "Follow OWASP remediation guidance for this category.",
            "reproduction_steps": f.get("reproduction_steps") or f"1. Send request to {f.get('host')}\n2. Observe response\n3. Validate via scope_validator",
            "poc": f.get("poc") if include_poc else None,
            "fingerprint": f.get("fingerprint"),
            "retest_badge": badge,
            "verified": bool(badge and badge["color"] == "green"),
        }
        sections.append(section)

    report = {
        "title": f"RedPulse - Automated Pentest Report - {project_name} / {engagement_name}",
        "project": project_name,
        "engagement": engagement_name,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "format": format,
        "classification": "Confidential - Authorized Testing Only",
        "executive_summary": executive,
        "compliance": compliance,
        "delta": delta,
        "findings": sections,
        "retest_results": retest_results,
        "disclaimer": "Controlled Pentesting: all tests targeted via scope_validator.validate_target, no destructive exploits, passive PoC only.",
    }
    return report


# ---------------------------------------------------------------------------
# HTML / PDF Rendering
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { font-family: Helvetica, Arial, sans-serif; color: #1a1a1a; margin: 40px; line-height: 1.5; }
  .cover { text-align: center; padding: 80px 0 60px; border: 3px solid #0f2a44; margin-bottom: 40px; }
  .cover h1 { font-size: 28px; color: #0f2a44; margin: 0; }
  .cover .meta { margin-top: 18px; font-size: 13px; color: #555; }
  .classification { display: inline-block; margin-top: 14px; padding: 6px 12px; background: #b91c1c; color: white; font-size: 11px; letter-spacing: 1px; border-radius: 3px; }
  h2 { color: #0f2a44; border-bottom: 2px solid #0f2a44; padding-bottom: 6px; margin-top: 36px; }
  h3 { color: #1e3a5f; margin-top: 24px; }
  .risk-table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  .risk-table th, .risk-table td { border: 1px solid #ccc; padding: 8px 10px; text-align: left; font-size: 13px; }
  .risk-table th { background: #0f2a44; color: white; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; color:white; font-size:11px; font-weight:bold; }
  .badge-CRITICAL { background:#7f1d1d; } .badge-HIGH { background:#dc2626; } .badge-MEDIUM { background:#d97706; } .badge-LOW { background:#16a34a; } .badge-INFO { background:#6b7280; }
  .badge-green { background:#16a34a; } .badge-red { background:#dc2626; }
  .finding { border:1px solid #ddd; padding:16px; margin:16px 0; border-radius:6px; background:#fafafa; }
  .poc { background:#111827; color:#e5e7eb; padding:10px; font-family: monospace; font-size:11px; white-space: pre-wrap; word-break: break-all; border-radius:4px; max-height: 260px; overflow:auto; }
  .footer { margin-top:40px; font-size:10px; color:#888; border-top:1px solid #ddd; padding-top:10px; }
</style>
</head>
<body>
<div class="cover">
  <h1>{{ title }}</h1>
  <div class="meta">Target: {{ engagement }} &nbsp;|&nbsp; Project: {{ project }}<br>Date: {{ generated_at }}<br>Engagement: {{ engagement }}</div>
  <div class="classification">{{ classification }}</div>
</div>

<h2>Executive Summary</h2>
<p>{{ executive_summary.summary }}</p>
<table class="risk-table">
  <tr><th>Severity</th><th>Count</th></tr>
  {% for sev, cnt in executive_summary.by_severity.items() %}
  <tr><td><span class="badge badge-{{ sev }}">{{ sev }}</span></td><td>{{ cnt }}</td></tr>
  {% endfor %}
  {% if not executive_summary.by_severity %}
  <tr><td colspan="2">No findings</td></tr>
  {% endif %}
</table>
<p><strong>Total Findings:</strong> {{ executive_summary.total }} &nbsp;|&nbsp; <strong>Highest CVSS:</strong> {{ executive_summary.highest_cvss }}</p>

{% if compliance %}
<h2>Compliance Mapping</h2>
<p>{{ compliance.summary }}</p>
<table class="risk-table">
  <tr><th>Framework</th><th>Control</th><th>Count</th></tr>
  {% for k, v in compliance.owasp.items() %}<tr><td>OWASP</td><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}
  {% for k, v in compliance.pci.items() %}<tr><td>PCI-DSS v4.0</td><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}
  {% for k, v in compliance.iso.items() %}<tr><td>ISO 27001</td><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}
</table>
{% endif %}

{% if delta %}
<h2>Delta Scan Tracking</h2>
<p>{{ delta.generated_at }} â€” {{ delta.metrics.findings.new }} NEW / {{ delta.metrics.findings.resolved }} RESOLVED / {{ delta.metrics.findings.persistent }} PERSISTENT findings; {{ delta.metrics.assets.new }} NEW / {{ delta.metrics.assets.resolved }} RESOLVED assets</p>
<table class="risk-table">
  <tr><th>Type</th><th>NEW</th><th>RESOLVED</th><th>PERSISTENT</th><th>Total Current</th></tr>
  <tr><td>Findings</td><td>{{ delta.metrics.findings.new }}</td><td>{{ delta.metrics.findings.resolved }}</td><td>{{ delta.metrics.findings.persistent }}</td><td>{{ delta.metrics.findings.total_current }}</td></tr>
  <tr><td>Assets</td><td>{{ delta.metrics.assets.new }}</td><td>{{ delta.metrics.assets.resolved }}</td><td>{{ delta.metrics.assets.persistent }}</td><td>{{ delta.metrics.assets.total_current }}</td></tr>
</table>
{% if delta.delta_log %}
<p><strong>Delta Alerts:</strong></p>
<ul>
{% for alert in delta.delta_log %}
  <li style="font-size:12px">{{ alert.type }}: {{ alert.message }} ({{ alert.timestamp }})</li>
{% endfor %}
</ul>
{% endif %}
{% endif %}

<h2>Detailed Findings</h2>
{% for f in findings %}
<div class="finding">
  <h3>{{ loop.index }}. {{ f.title }} <span class="badge badge-{{ f.severity|upper }}">{{ f.severity }}</span> CVSS {{ f.cvss_score }} <span style="font-size:10px;color:#555">{{ f.cvss_vector }}</span>{% if f.retest_badge %} <span class="badge badge-{{ f.retest_badge.color }}">{{ f.retest_badge.label }}</span>{% if f.retest_badge.verified_at %} <span style="font-size:9px;color:#666">verified {{ f.retest_badge.verified_at }}</span>{% endif %}{% endif %}</h3>
  <p><strong>Host:</strong> {{ f.host }} &nbsp;|&nbsp; <strong>Priority:</strong> {{ f.priority }} &nbsp;|&nbsp; <strong>Fingerprint:</strong> {{ f.fingerprint }}</p>
  {% if f.description %}<p><strong>Description:</strong> {{ f.description }}</p>{% endif %}
  <p><strong>Impact:</strong> {{ f.impact }}</p>
  <p><strong>Remediation:</strong> {{ f.remediation }}</p>
  <p><strong>Reproduction:</strong><br><span style="font-size:12px; white-space: pre-wrap;">{{ f.reproduction_steps }}</span></p>
  {% if f.poc %}
  <p><strong>Passive PoC (Request/Response):</strong></p>
  {% if f.poc.request %}<div class="poc"><strong>Request:</strong>\n{{ f.poc.request }}</div>{% endif %}
  {% if f.poc.response %}<div class="poc" style="margin-top:6px"><strong>Response:</strong>\n{{ f.poc.response }}</div>{% endif %}
  {% if f.poc.is_passive %}<p style="font-size:10px;color:#666">* Passive PoC only - no destructive payload executed.</p>{% endif %}
  {% endif %}
</div>
{% endfor %}
{% if not findings %}<p>No findings within scope.</p>{% endif %}

<div class="footer">{{ disclaimer }}<br>Generated: {{ generated_at }} | Classification: {{ classification }}</div>
</body>
</html>
"""


def render_report_html(report: Dict[str, Any]) -> str:
    """Render report dict to HTML string via Jinja2."""
    try:
        from jinja2 import Template

        tmpl = Template(_HTML_TEMPLATE)
        return tmpl.render(**report)
    except Exception:
        # Fallback: minimal HTML without Jinja2
        html = f"<html><body><h1>{report.get('title','Report')}</h1>"
        html += f"<p>{report.get('executive_summary',{}).get('summary','')}</p>"
        for f in report.get("findings", []):
            html += f"<h3>{f.get('title')} - {f.get('severity')} CVSS {f.get('cvss_score')}</h3>"
            html += f"<p>{f.get('description','')}</p>"
        html += "</body></html>"
        return html


def generate_pdf_bytes(report: Dict[str, Any]) -> bytes:
    """Generate professional PDF bytes from report dict.

    Tries WeasyPrint first (HTML->PDF), falls back to ReportLab for production portability.
    """
    html = render_report_html(report)

    # Try WeasyPrint if available
    try:
        import importlib.util

        if importlib.util.find_spec("weasyprint") is not None:
            from weasyprint import HTML

            return HTML(string=html).write_pdf()
    except Exception:
        pass

    # Fallback: ReportLab
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
        from reportlab.lib import colors

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=14 * mm,
            bottomMargin=14 * mm,
            title=report.get("title", "Pentest Report"),
            author="RedPulse",
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=22, textColor=HexColor("#0f2a44"), alignment=TA_CENTER, spaceAfter=6)
        meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9, textColor=HexColor("#555555"), alignment=TA_CENTER)
        class_style = ParagraphStyle("Class", parent=styles["Normal"], fontSize=8, textColor=white, backColor=HexColor("#b91c1c"), alignment=TA_CENTER, borderPadding=(4, 8, 4, 8))
        h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, textColor=HexColor("#0f2a44"), spaceBefore=14, spaceAfter=6)
        h3 = ParagraphStyle("H3", parent=styles["Heading3"], fontSize=11, textColor=HexColor("#1e3a5f"), spaceBefore=8, spaceAfter=4)
        body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9, leading=13, textColor=black)
        mono = ParagraphStyle("Mono", parent=styles["Code"], fontSize=7, leading=9, textColor=HexColor("#e5e7eb"), backColor=HexColor("#111827"), borderPadding=(6, 6, 6, 6))

        story = []
        # Cover
        story.append(Spacer(1, 40))
        story.append(Paragraph(report.get("title", "Pentest Report"), title_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Target: {report.get('engagement','')}  |  Project: {report.get('project','')}<br/>Date: {report.get('generated_at','')}<br/>Engagement: {report.get('engagement','')}", meta_style))
        story.append(Spacer(1, 10))
        # Classification badge as table
        story.append(Table([[Paragraph(report.get("classification", "Confidential"), class_style)]], colWidths=[doc.width], style=TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")])))
        story.append(Spacer(1, 24))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f2a44")))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", h2))
        exec_sum = report.get("executive_summary", {})
        story.append(Paragraph(exec_sum.get("summary", ""), body))
        story.append(Spacer(1, 6))
        # Risk matrix
        by_sev = exec_sum.get("by_severity", {})
        if by_sev:
            data = [["Severity", "Count"]] + [[k, str(v)] for k, v in by_sev.items()]
            t = Table(data, colWidths=[doc.width * 0.5] * 2)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0f2a44")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, colors.HexColor("#f1f5f9")]),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
        story.append(Paragraph(f"Total Findings: {exec_sum.get('total',0)}  |  Highest CVSS: {exec_sum.get('highest_cvss',0)}", body))
        story.append(Spacer(1, 6))

        # Delta metrics (if present)
        delta = report.get("delta")
        if delta:
            story.append(Paragraph("Delta Scan Tracking", h2))
            story.append(Paragraph(f"Generated: {delta.get('generated_at','')}", ParagraphStyle("DeltaMeta", parent=body, fontSize=7, textColor=colors.grey)))
            m = delta.get("metrics", {})
            f = m.get("findings", {})
            a = m.get("assets", {})
            data = [["Type","NEW","RESOLVED","PERSISTENT","Total Current"], ["Findings", str(f.get("new",0)), str(f.get("resolved",0)), str(f.get("persistent",0)), str(f.get("total_current",0))], ["Assets", str(a.get("new",0)), str(a.get("resolved",0)), str(a.get("persistent",0)), str(a.get("total_current",0))]]
            t = Table(data, colWidths=[doc.width*0.2, doc.width*0.2, doc.width*0.2, doc.width*0.2, doc.width*0.2])
            t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),HexColor("#0f2a44")),("TEXTCOLOR",(0,0),(-1,0),white),("FONTSIZE",(0,0),(-1,-1),7),("GRID",(0,0),(-1,-1),0.5,colors.grey),("ALIGN",(0,0),(-1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
            story.append(t)
            story.append(Spacer(1,4))
            for alert in (delta.get("delta_log") or [])[:8]:
                story.append(Paragraph(f"{alert.get('type')}: {alert.get('message')} ({alert.get('timestamp')})", ParagraphStyle("DeltaAlert", parent=body, fontSize=7, textColor=HexColor("#334155"))))
            story.append(Spacer(1,6))

        # Detailed Findings
        story.append(Paragraph("Detailed Findings", h2))
        for idx, f in enumerate(report.get("findings", []), 1):
            story.append(Paragraph(f"{idx}. {f.get('title','Untitled')}  [{f.get('severity','')} ]  CVSS {f.get('cvss_score','')} <font size=7 color=#555>{f.get('cvss_vector','')}</font>", h3))
            badge = f.get("retest_badge")
            if badge:
                color_hex = "#16a34a" if badge.get("color") == "green" else "#dc2626"
                story.append(Paragraph(f"<b><font color=\"{color_hex}\">{badge.get('label','')}</font></b> {badge.get('verified_at','')}", ParagraphStyle("RetestBadge", parent=body, fontSize=8, textColor=HexColor(color_hex))))
            story.append(Paragraph(f"<b>Host:</b> {f.get('host','')} &nbsp;|&nbsp; <b>Priority:</b> {f.get('priority','')} &nbsp;|&nbsp; <b>Fingerprint:</b> {f.get('fingerprint','')}", body))
            if f.get("description"):
                story.append(Paragraph(f"<b>Description:</b> {f.get('description')}", body))
            story.append(Paragraph(f"<b>Impact:</b> {f.get('impact','')}", body))
            story.append(Paragraph(f"<b>Remediation:</b> {f.get('remediation','')}", body))
            story.append(Paragraph(f"<b>Reproduction:</b><br/><font size=8>{f.get('reproduction_steps','').replace(chr(10), '<br/>')}</font>", body))
            poc = f.get("poc")
            if poc:
                if poc.get("request"):
                    req = poc["request"][:2000].replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(f"<b>Passive PoC â€” Request:</b>", body))
                    story.append(Paragraph(req.replace("\n", "<br/>"), mono))
                if poc.get("response"):
                    resp = poc["response"][:2000].replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(f"<b>Passive PoC â€” Response:</b>", body))
                    story.append(Paragraph(resp.replace("\n", "<br/>"), mono))
                if poc.get("is_passive"):
                    story.append(Paragraph("<i>* Passive PoC only â€” no destructive payload executed.</i>", ParagraphStyle("Note", parent=body, fontSize=7, textColor=colors.grey)))
            story.append(Spacer(1, 8))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb")))
            story.append(Spacer(1, 6))

        if not report.get("findings"):
            story.append(Paragraph("No findings within scope.", body))

        # Footer disclaimer
        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1")))
        story.append(Paragraph(report.get("disclaimer","") + f"<br/>Generated: {report.get('generated_at','')} | Classification: {report.get('classification','')}", ParagraphStyle("Footer", parent=body, fontSize=7, textColor=colors.gray)))

        doc.build(story)
        return buf.getvalue()
    except Exception as e:
        # Last resort: minimal PDF header
        raise RuntimeError(f"PDF generation failed: {e}") from e
