import io
import json
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether


def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    """
    Generates a professional, genuine PDF security assessment report using ReportLab.
    Contains scan metadata, severity distribution, OWASP Top 10 coverage,
    evidence, remediation instructions, and limitations disclaimer.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    primary_color = colors.HexColor("#0f172a")  # Slate 900
    brand_color = colors.HexColor("#3b82f6")    # Blue 500
    critical_color = colors.HexColor("#ef4444")
    high_color = colors.HexColor("#f97316")
    medium_color = colors.HexColor("#f59e0b")
    low_color = colors.HexColor("#10b981")
    info_color = colors.HexColor("#64748b")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=primary_color,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    code_style = ParagraphStyle(
        "Code",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=4
    )

    story = []

    # 1. Header / Title Banner
    story.append(Paragraph("HACKFIX AI — Website Security Audit Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Non-Destructive Passive Assessment", body_style))
    story.append(Spacer(1, 12))

    # 2. Executive Scan Metadata
    summary = scan_data.get("summary", {})
    target_url = scan_data.get("target_url", "N/A")
    meta_data = [
        [Paragraph("<b>Target URL:</b>", body_style), Paragraph(target_url, body_style)],
        [Paragraph("<b>Scan Status:</b>", body_style), Paragraph(scan_data.get("status", "N/A").upper(), body_style)],
        [Paragraph("<b>Created At:</b>", body_style), Paragraph(str(scan_data.get("created_at", "N/A")), body_style)],
        [Paragraph("<b>Scan Duration:</b>", body_style), Paragraph(f"{summary.get('duration_seconds', 0)} seconds", body_style)],
        [Paragraph("<b>Pages Scanned:</b>", body_style), Paragraph(str(summary.get("pages_scanned", 1)), body_style)],
        [Paragraph("<b>Total Findings:</b>", body_style), Paragraph(str(summary.get("total_findings", 0)), body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[120, 420])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Severity Distribution Summary Table
    story.append(Paragraph("Findings Summary by Severity", h2_style))
    sev_data = [
        ["Severity", "Count", "Assessment Significance"],
        ["Critical", str(summary.get("critical_count", 0)), "Immediate compromise risk (exposed credentials or repo)"],
        ["High", str(summary.get("high_count", 0)), "Severe vulnerability (cleartext HTTP, broken CORS with credentials)"],
        ["Medium", str(summary.get("medium_count", 0)), "Security misconfiguration or absent defensive headers (CSP, HSTS)"],
        ["Low", str(summary.get("low_count", 0)), "Hardening recommendation (nosniff, referrer-policy)"],
        ["Informational", str(summary.get("info_count", 0)), "Architecture disclosure or observable catalog endpoint"],
    ]
    sev_table = Table(sev_data, colWidths=[100, 60, 380])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 14))

    # 4. OWASP Top 10:2025 Coverage Status
    story.append(Paragraph("OWASP Top 10:2025 Coverage & Assessment Scope", h2_style))
    owasp_rows = [["ID", "OWASP Category", "Status", "Findings", "Passive Assessment Scope"]]
    owasp_cov = summary.get("owasp_coverage", {})

    status_labels = {
        "findings_present": "Findings Present",
        "no_findings_detected": "No Findings Detected",
        "assessment_limited": "Assessment Limited",
        "not_assessed": "Not Assessed"
    }

    for cat_id, cat_info in owasp_cov.items():
        st = status_labels.get(cat_info.get("status"), cat_info.get("status", "N/A"))
        owasp_rows.append([
            cat_id,
            Paragraph(cat_info.get("category_name", ""), body_style),
            Paragraph(f"<b>{st}</b>", body_style),
            str(cat_info.get("finding_count", 0)),
            Paragraph(cat_info.get("limitation_note", ""), body_style)
        ])

    owasp_table = Table(owasp_rows, colWidths=[40, 150, 100, 50, 200])
    owasp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(owasp_table)
    story.append(Spacer(1, 14))

    # 5. Detailed Findings List
    findings = scan_data.get("findings", [])
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Detailed Security Findings & Evidence", title_style))
        story.append(Spacer(1, 10))

        for idx, f in enumerate(findings, 1):
            finding_items = []
            f_title = f"{idx}. [{f.get('severity', 'Low').upper()}] {f.get('title', 'Finding')}"
            finding_items.append(Paragraph(f_title, h2_style))
            
            detail_data = [
                [Paragraph("<b>OWASP Category:</b>", body_style), Paragraph(f.get("owasp_category", ""), body_style)],
                [Paragraph("<b>Affected URL:</b>", body_style), Paragraph(f.get("affected_url", ""), body_style)],
                [Paragraph("<b>Confidence / Status:</b>", body_style), Paragraph(f"{f.get('confidence', 'High')} ({f.get('evidence_status', '')})", body_style)],
                [Paragraph("<b>Verification Status:</b>", body_style), Paragraph(f.get("verification_status", "unverified"), body_style)],
                [Paragraph("<b>Description:</b>", body_style), Paragraph(f.get("description", ""), body_style)],
                [Paragraph("<b>Potential Impact:</b>", body_style), Paragraph(f.get("impact", ""), body_style)],
                [Paragraph("<b>Recommended Fix:</b>", body_style), Paragraph(f.get("recommended_fix", ""), body_style)],
            ]

            if f.get("example_after"):
                detail_data.append([
                    Paragraph("<b>Remediation Example:</b>", body_style),
                    Paragraph(f.get("example_after", "").replace("\n", "<br/>"), code_style)
                ])

            ev = f.get("evidence", {})
            if ev:
                ev_str = json.dumps(ev, indent=2)[:400]
                detail_data.append([
                    Paragraph("<b>Observed Evidence:</b>", body_style),
                    Paragraph(ev_str.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style)
                ])

            f_table = Table(detail_data, colWidths=[120, 420])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            finding_items.append(f_table)
            finding_items.append(Spacer(1, 12))
            story.append(KeepTogether(finding_items))

    # 6. Scope, Disclaimers, & Retest Information
    story.append(Spacer(1, 14))
    story.append(Paragraph("Assessment Limitations and Disclaimer", h2_style))
    disclaimer_text = (
        "This security audit was conducted by HACKFIX AI using non-destructive, passive URL inspection techniques. "
        "It evaluates observable HTTP headers, transport security, cookie configurations, and exposed resources. "
        "It does NOT perform authenticated multi-role vulnerability testing, automated exploitation, or deep source code analysis. "
        "'No findings detected' indicates that configured checks found no anomalies, but does not guarantee the target is immune to vulnerabilities. "
        "Remediation examples must be validated in staging environments prior to production rollout."
    )
    story.append(Paragraph(disclaimer_text, body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_html_report(scan_data: Dict[str, Any]) -> str:
    """Generates an HTML version of the security audit report."""
    summary = scan_data.get("summary", {})
    findings = scan_data.get("findings", [])
    target = scan_data.get("target_url", "")
    created = scan_data.get("created_at", "")

    findings_html = ""
    for f in findings:
        findings_html += f"""
        <div class="finding-card {f.get('severity', 'low').lower()}">
            <div class="finding-header">
                <span class="badge {f.get('severity', 'low').lower()}">{f.get('severity', 'Low')}</span>
                <h3>{f.get('title')}</h3>
            </div>
            <p><strong>OWASP:</strong> {f.get('owasp_category')}</p>
            <p><strong>Affected URL:</strong> <code>{f.get('affected_url')}</code></p>
            <p><strong>Description:</strong> {f.get('description')}</p>
            <p><strong>Impact:</strong> {f.get('impact')}</p>
            <p><strong>Recommended Fix:</strong> {f.get('recommended_fix')}</p>
            {f'<pre><code>{f.get("example_after")}</code></pre>' if f.get("example_after") else ''}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HACKFIX AI Security Report - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 30px; }}
        h1, h2, h3 {{ color: #38bdf8; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge.critical {{ background: #ef4444; color: white; }}
        .badge.high {{ background: #f97316; color: white; }}
        .badge.medium {{ background: #f59e0b; color: black; }}
        .badge.low {{ background: #10b981; color: white; }}
        .badge.informational {{ background: #64748b; color: white; }}
        .finding-card {{ border: 1px solid #334155; border-radius: 6px; padding: 16px; margin-bottom: 16px; background: #0f172a; }}
        pre {{ background: #020617; padding: 10px; border-radius: 4px; overflow-x: auto; color: #a5f3fc; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #334155; padding: 8px; text-align: left; }}
        th {{ background: #334155; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>HACKFIX AI Security Assessment Report</h1>
        <p>Target: <strong>{target}</strong> | Created: {created}</p>
        <h2>Findings Summary</h2>
        <table>
            <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Informational</th></tr>
            <tr>
                <td>{summary.get('critical_count', 0)}</td>
                <td>{summary.get('high_count', 0)}</td>
                <td>{summary.get('medium_count', 0)}</td>
                <td>{summary.get('low_count', 0)}</td>
                <td>{summary.get('info_count', 0)}</td>
            </tr>
        </table>
        <h2>Detailed Findings</h2>
        {findings_html if findings else '<p>No findings observed.</p>'}
    </div>
</body>
</html>
"""

