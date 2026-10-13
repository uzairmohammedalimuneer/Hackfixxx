import httpx
from app.scanner.modules.headers import analyze_security_headers
from app.scanner.modules.cookies import analyze_cookies
from app.scanner.modules.info_disclosure import analyze_information_disclosure


def test_missing_security_headers_detection():
    # Empty headers response
    mock_resp = httpx.Response(
        status_code=200,
        headers={"content-type": "text/html"},
        text="<html><body>Hello</body></html>"
    )

    findings = analyze_security_headers("https://example.com/", mock_resp)
    titles = [f["title"] for f in findings]

    assert "Missing Content-Security-Policy (CSP)" in titles
    assert "Missing Strict-Transport-Security (HSTS)" in titles
    assert "Missing or Ineffective X-Content-Type-Options Header" in titles
    assert "Missing Anti-Clickjacking Protections (X-Frame-Options / frame-ancestors)" in titles


def test_proper_security_headers_produce_no_findings():
    mock_resp = httpx.Response(
        status_code=200,
        headers={
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()"
        },
        text="<html><body>Secure</body></html>"
    )

    findings = analyze_security_headers("https://example.com/", mock_resp)
    assert len(findings) == 0


def test_cookie_attribute_audit():
    mock_resp = httpx.Response(
        status_code=200,
        headers={
            "set-cookie": "session_id=abcdef123456; Path=/"
        }
    )

    findings = analyze_cookies("https://example.com/", mock_resp)
    titles = [f["title"] for f in findings]

    assert "Cookie 'session_id' Missing 'Secure' Attribute" in titles
    assert "Cookie 'session_id' Missing 'HttpOnly' Attribute" in titles
    assert "Cookie 'session_id' Missing 'SameSite' Attribute" in titles


def test_secure_cookie_attributes():
    mock_resp = httpx.Response(
        status_code=200,
        headers={
            "set-cookie": "session_id=abcdef123456; Path=/; Secure; HttpOnly; SameSite=Lax"
        }
    )

    findings = analyze_cookies("https://example.com/", mock_resp)
    assert len(findings) == 0


def test_server_banner_and_stack_trace_disclosure():
    mock_resp = httpx.Response(
        status_code=500,
        headers={
            "server": "Apache/2.4.52 (Ubuntu)",
            "x-powered-by": "PHP/8.1.2"
        },
        text="<html><body>Traceback (most recent call last): File /var/www/main.py line 10</body></html>"
    )

    findings = analyze_information_disclosure("https://example.com/err", mock_resp)
    titles = [f["title"] for f in findings]

    assert any("Web Server Banner Disclosed" in t for t in titles)
    assert any("Technology Framework Disclosed" in t for t in titles)
    assert any("Application Debug Information Disclosed" in t for t in titles)

