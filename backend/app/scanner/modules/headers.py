from typing import List, Dict, Any
import httpx
from app.scanner.ssrf_validator import redact_dict


def analyze_security_headers(target_url: str, response: httpx.Response) -> List[Dict[str, Any]]:
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    status_code = response.status_code

    # 1. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append({
            "title": "Missing Content-Security-Policy (CSP)",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Medium",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                "The HTTP response does not include a Content-Security-Policy (CSP) header. "
                "CSP is a defense-in-depth standard that restricts which scripts, styles, "
                "and media can load and execute in the client's browser context."
            ),
            "impact": (
                "Without CSP, the browser will execute any injected inline scripts or load remote resources, "
                "significantly increasing exposure to Cross-Site Scripting (XSS) and data exfiltration."
            ),
            "affected_url": target_url,
            "evidence": {
                "http_status": status_code,
                "missing_header": "Content-Security-Policy",
                "observed_headers": redact_dict(dict(list(response.headers.items())[:10]))
            },
            "recommended_fix": (
                "Define a restrictive Content-Security-Policy starting with 'default-src 'self'' "
                "and explicitly allow only trusted origins for scripts, styles, and fonts."
            ),
            "example_before": "# Missing header in response\nContent-Security-Policy: (none)",
            "example_after": (
                "Content-Security-Policy: default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
                "frame-ancestors 'none'; base-uri 'self';"
            ),
            "limitations": (
                "A missing CSP does not itself create an XSS vulnerability, but removes a vital "
                "second line of browser defense should an injection flaw exist."
            ),
            "source": "native_headers",
            "references": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                "https://owasp.org/www-project-secure-headers/#content-security-policy"
            ]
        })
    else:
        # Check for weak directives
        if "'unsafe-inline'" in csp and "script-src" in csp:
            findings.append({
                "title": "Content-Security-Policy Contains 'unsafe-inline' in script-src",
                "owasp_category": "A02:2025 Security Misconfiguration",
                "severity": "Low",
                "confidence": "High",
                "evidence_status": "confirmed_observation",
                "description": (
                    "The Content-Security-Policy permits 'unsafe-inline' for scripts, "
                    "which disables browser protections against inline script execution."
                ),
                "impact": "Injected malicious script tags can execute despite CSP presence.",
                "affected_url": target_url,
                "evidence": {
                    "http_status": status_code,
                    "csp_directive": csp[:200]
                },
                "recommended_fix": "Replace 'unsafe-inline' with cryptographic nonces (nonce-...) or hashes (sha256-...).",
                "example_before": "Content-Security-Policy: script-src 'self' 'unsafe-inline';",
                "example_after": "Content-Security-Policy: script-src 'self' 'nonce-rAnd0m123';",
                "limitations": "Requires refactoring frontend templates to inject cryptographic nonces.",
                "source": "native_headers",
                "references": ["https://owasp.org/www-project-secure-headers/#content-security-policy"]
            })

    # 2. Strict-Transport-Security (HSTS)
    if target_url.lower().startswith("https://"):
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append({
                "title": "Missing Strict-Transport-Security (HSTS)",
                "owasp_category": "A04:2025 Cryptographic Failures",
                "severity": "Medium",
                "confidence": "Confirmed",
                "evidence_status": "confirmed_observation",
                "description": (
                    "The HTTPS endpoint does not include the Strict-Transport-Security (HSTS) header. "
                    "HSTS tells browsers to only interact with the website over HTTPS, protecting future "
                    "connections against protocol downgrade attacks."
                ),
                "impact": (
                    "Users visiting the site via http:// or on unencrypted public Wi-Fi may be exposed "
                    "to Man-In-The-Middle (MITM) SSL stripping attacks before any HTTPS redirect occurs."
                ),
                "affected_url": target_url,
                "evidence": {
                    "http_status": status_code,
                    "missing_header": "Strict-Transport-Security"
                },
                "recommended_fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                "example_before": "# Missing Strict-Transport-Security",
                "example_after": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "limitations": "Should only be enabled after verifying that all subdomains support HTTPS.",
                "source": "native_headers",
                "references": [
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    "https://owasp.org/www-project-secure-headers/#strict-transport-security"
                ]
            })

    # 3. X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        findings.append({
            "title": "Missing or Ineffective X-Content-Type-Options Header",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Low",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                "The X-Content-Type-Options response header is not set to 'nosniff'. "
                "This header prevents older and modern browsers from MIME-sniffing a response "
                "away from the declared content-type."
            ),
            "impact": (
                "Can enable drive-by downloads or allow uploaded non-executable files (e.g., images) "
                "to be interpreted as JavaScript or HTML by some browsers."
            ),
            "affected_url": target_url,
            "evidence": {
                "http_status": status_code,
                "observed_value": xcto or "(absent)",
                "expected": "nosniff"
            },
            "recommended_fix": "Configure web server or reverse proxy to send 'X-Content-Type-Options: nosniff'.",
            "example_before": "# Missing X-Content-Type-Options",
            "example_after": "X-Content-Type-Options: nosniff",
            "limitations": "Ensure that Content-Type headers are accurately specified on all static assets.",
            "source": "native_headers",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
        })

    # 4. X-Frame-Options or CSP frame-ancestors (Clickjacking defense)
    xfo = headers.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in csp
    if not xfo and not has_frame_ancestors:
        findings.append({
            "title": "Missing Anti-Clickjacking Protections (X-Frame-Options / frame-ancestors)",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Medium",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                "Neither X-Frame-Options nor a CSP 'frame-ancestors' directive was detected. "
                "These headers instruct the browser whether the page can be rendered inside a "
                "<frame>, <iframe>, <embed>, or <object>."
            ),
            "impact": (
                "An attacker can iframe this web page inside a malicious third-party site and overlay invisible "
                "clickable elements, tricking authenticated users into performing unintended actions (Clickjacking)."
            ),
            "affected_url": target_url,
            "evidence": {
                "http_status": status_code,
                "missing_x_frame_options": True,
                "missing_csp_frame_ancestors": True
            },
            "recommended_fix": "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
            "example_before": "# Neither header present",
            "example_after": "X-Frame-Options: SAMEORIGIN\n# Or via CSP:\nContent-Security-Policy: frame-ancestors 'self';",
            "limitations": "If legitimate embedding in trusted partner sites is required, use CSP frame-ancestors with an explicit allowlist.",
            "source": "native_headers",
            "references": ["https://owasp.org/www-community/attacks/Clickjacking"]
        })

    # 5. Referrer-Policy
    referrer_policy = headers.get("referrer-policy")
    if not referrer_policy:
        findings.append({
            "title": "Missing Referrer-Policy Header",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Low",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                "The Referrer-Policy HTTP header governs how much referrer information (URL path and query parameters) "
                "is included with requests made from this page."
            ),
            "impact": (
                "Browsers may leak sensitive URL parameters (such as tokens, search terms, or internal identifiers) "
                "to external third parties when users click external links or load external resources."
            ),
            "affected_url": target_url,
            "evidence": {
                "http_status": status_code,
                "missing_header": "Referrer-Policy"
            },
            "recommended_fix": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "example_before": "# Missing Referrer-Policy",
            "example_after": "Referrer-Policy: strict-origin-when-cross-origin",
            "limitations": "Ensure analytics tools that rely on referrer tracking are compatible with the chosen policy.",
            "source": "native_headers",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
        })

    # 6. Permissions-Policy
    permissions_policy = headers.get("permissions-policy")
    if not permissions_policy:
        findings.append({
            "title": "Missing Permissions-Policy Header",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Informational",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                "The Permissions-Policy header allows sites to restrict access to sensitive browser features "
                "such as camera, microphone, geolocation, and payment APIs for the page and embedded iframes."
            ),
            "impact": (
                "Without a Permissions-Policy, third-party scripts or embedded widgets may request or invoke "
                "browser APIs unless manually blocked by the user."
            ),
            "affected_url": target_url,
            "evidence": {
                "http_status": status_code,
                "missing_header": "Permissions-Policy"
            },
            "recommended_fix": "Define a Permissions-Policy restricting unused hardware/APIs: 'geolocation=(), microphone=(), camera=()'.",
            "example_before": "# Missing Permissions-Policy",
            "example_after": "Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()",
            "limitations": "Informational best-practice recommendation; adjust according to web app functionality.",
            "source": "native_headers",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"]
        })

    return findings

