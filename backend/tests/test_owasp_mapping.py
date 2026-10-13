from app.scanner.engine import calculate_owasp_coverage, OWASP_2025_DEFINITIONS


def test_owasp_coverage_all_categories_present():
    coverage = calculate_owasp_coverage([])
    assert len(coverage) == 10
    assert "A01" in coverage
    assert "A02" in coverage
    assert "A10" in coverage


def test_owasp_coverage_states():
    sample_findings = [
        {
            "title": "Missing CSP",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Medium"
        },
        {
            "title": "Cleartext HTTP",
            "owasp_category": "A04:2025 Cryptographic Failures",
            "severity": "High"
        }
    ]

    coverage = calculate_owasp_coverage(sample_findings)
    # A02 and A04 should be findings_present
    assert coverage["A02"]["status"] == "findings_present"
    assert coverage["A02"]["finding_count"] == 1

    assert coverage["A04"]["status"] == "findings_present"
    assert coverage["A04"]["finding_count"] == 1

    # Non-assessed category like Injection (A05)
    assert coverage["A05"]["status"] == "not_assessed"
    assert coverage["A05"]["finding_count"] == 0

