from app.services.report_service import generate_pdf_report, generate_html_report


def test_pdf_report_generation():
    mock_scan_data = {
        "id": "test-scan-uuid-12345",
        "target_url": "https://test.example.com",
        "status": "completed",
        "created_at": "2026-10-13 12:00:00 UTC",
        "summary": {
            "total_findings": 2,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 0,
            "info_count": 0,
            "pages_scanned": 3,
            "duration_seconds": 4.5,
            "owasp_coverage": {
                "A02": {
                    "category_id": "A02",
                    "category_name": "A02 Security Misconfiguration",
                    "status": "findings_present",
                    "finding_count": 1,
                    "limitation_note": "Assessed via headers"
                }
            }
        },
        "findings": [
            {
                "title": "Missing Content-Security-Policy (CSP)",
                "owasp_category": "A02:2025 Security Misconfiguration",
                "severity": "Medium",
                "confidence": "Confirmed",
                "evidence_status": "confirmed_observation",
                "description": "CSP is missing",
                "impact": "XSS risk",
                "affected_url": "https://test.example.com",
                "evidence": {"http_status": 200},
                "recommended_fix": "Add CSP header",
                "example_after": "Content-Security-Policy: default-src 'self'",
                "verification_status": "unverified"
            }
        ]
    }

    pdf_bytes = generate_pdf_report(mock_scan_data)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

    html_content = generate_html_report(mock_scan_data)
    assert "HACKFIX AI Security Assessment Report" in html_content
    assert "https://test.example.com" in html_content
    assert "Missing Content-Security-Policy" in html_content

