from app.scanner.modules.zap_integrator import check_zap_availability, normalize_zap_alert


def test_zap_disabled_by_default():
    avail, msg = check_zap_availability()
    assert not avail
    assert "disabled in configuration" in msg


def test_normalize_zap_alert():
    mock_zap_alert = {
        "alert": "Cross-Domain JavaScript Source File Inclusion",
        "riskcode": "1",
        "confidence": "2",
        "cweid": "79",
        "wascid": "15",
        "url": "http://example.com/app.js",
        "description": "Script loaded from remote domain.",
        "solution": "Host scripts locally."
    }

    normalized = normalize_zap_alert(mock_zap_alert, "http://example.com")
    assert normalized["title"] == "[ZAP] Cross-Domain JavaScript Source File Inclusion"
    assert normalized["severity"] == "Low"
    assert normalized["owasp_category"] == "A05:2025 Injection"
    assert normalized["source"] == "owasp_zap"

