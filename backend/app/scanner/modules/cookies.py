from typing import List, Dict, Any
import httpx
from http.cookies import SimpleCookie
from app.scanner.ssrf_validator import redact_sensitive_data


def analyze_cookies(target_url: str, response: httpx.Response) -> List[Dict[str, Any]]:
    findings = []
    
    # Extract Set-Cookie headers
    raw_cookies = response.headers.get_list("set-cookie")
    if not raw_cookies and "set-cookie" in response.headers:
        raw_cookies = [response.headers["set-cookie"]]

    if not raw_cookies:
        return findings

    for raw_cookie in raw_cookies:
        try:
            cookie = SimpleCookie()
            cookie.load(raw_cookie)
        except Exception:
            continue

        for key, morsel in cookie.items():
            cookie_name = key
            cookie_value = morsel.value
            redacted_val = redact_sensitive_data(cookie_value[:6] + "..." if len(cookie_value) > 6 else "***")
            flags = {k.lower(): v for k, v in morsel.items()}

            # 1. Missing Secure flag
            is_secure = morsel.get("secure", False)
            if not is_secure and target_url.lower().startswith("https://"):
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    "owasp_category": "A02:2025 Security Misconfiguration",
                    "severity": "Medium",
                    "confidence": "Confirmed",
                    "evidence_status": "confirmed_observation",
                    "description": (
                        f"The cookie '{cookie_name}' was set on an HTTPS connection without the 'Secure' attribute. "
                        "The Secure flag ensures that the cookie is only transmitted over encrypted (HTTPS) connections."
                    ),
                    "impact": (
                        f"If a user subsequently initiates an unencrypted HTTP request to the same domain, "
                        f"the browser will send '{cookie_name}' in cleartext, exposing it to interception."
                    ),
                    "affected_url": target_url,
                    "evidence": {
                        "cookie_name": cookie_name,
                        "cookie_value_sample": redacted_val,
                        "raw_attributes": {k: str(v) for k, v in flags.items() if v}
                    },
                    "recommended_fix": f"Add '; Secure' to the Set-Cookie header for '{cookie_name}'.",
                    "example_before": f"Set-Cookie: {cookie_name}={redacted_val}; Path=/",
                    "example_after": f"Set-Cookie: {cookie_name}={redacted_val}; Path=/; Secure; HttpOnly; SameSite=Lax",
                    "limitations": "The Secure attribute should only be omitted if the cookie is explicitly intended for plain HTTP local development.",
                    "source": "native_cookies",
                    "references": [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
                        "https://owasp.org/www-community/controls/SecureCookieAttribute"
                    ]
                })

            # 2. Missing HttpOnly attribute
            is_httponly = morsel.get("httponly", False)
            # Heuristic: session, auth, jwt, id cookies especially need HttpOnly
            is_auth_cookie = any(sub in cookie_name.lower() for sub in ["sess", "auth", "token", "jwt", "id", "login"])
            
            if not is_httponly:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    "owasp_category": "A02:2025 Security Misconfiguration",
                    "severity": "Medium" if is_auth_cookie else "Low",
                    "confidence": "Confirmed",
                    "evidence_status": "confirmed_observation",
                    "description": (
                        f"The cookie '{cookie_name}' lacks the 'HttpOnly' flag. "
                        "When HttpOnly is absent, client-side JavaScript (via `document.cookie`) can read and modify the cookie."
                    ),
                    "impact": (
                        "If an attacker discovers a Cross-Site Scripting (XSS) vulnerability, they can read this cookie "
                        "via JavaScript and exfiltrate it." + (" For authentication or session cookies, this leads to account takeover." if is_auth_cookie else "")
                    ),
                    "affected_url": target_url,
                    "evidence": {
                        "cookie_name": cookie_name,
                        "is_likely_session_or_auth": is_auth_cookie,
                        "cookie_value_sample": redacted_val
                    },
                    "recommended_fix": f"Add '; HttpOnly' to the Set-Cookie header for '{cookie_name}'.",
                    "example_before": f"Set-Cookie: {cookie_name}={redacted_val}; Path=/",
                    "example_after": f"Set-Cookie: {cookie_name}={redacted_val}; Path=/; HttpOnly; SameSite=Lax",
                    "limitations": (
                        "Some non-sensitive cookies (like frontend UI themes or analytics markers) may legitimately "
                        "need client-side script access, but session and identity tokens must always use HttpOnly."
                    ),
                    "source": "native_cookies",
                    "references": ["https://owasp.org/www-community/HttpOnly"]
                })

            # 3. SameSite attribute analysis
            samesite = morsel.get("samesite", "").lower()
            if not samesite:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    "owasp_category": "A01:2025 Broken Access Control",
                    "severity": "Low",
                    "confidence": "Confirmed",
                    "evidence_status": "confirmed_observation",
                    "description": (
                        f"The cookie '{cookie_name}' does not specify a 'SameSite' attribute. "
                        "The SameSite attribute protects against Cross-Site Request Forgery (CSRF) by regulating "
                        "when cookies are sent with cross-site requests."
                    ),
                    "impact": (
                        "Depending on browser default policies, the cookie may be sent with cross-site requests, "
                        "increasing CSRF susceptibility."
                    ),
                    "affected_url": target_url,
                    "evidence": {
                        "cookie_name": cookie_name,
                        "samesite_attribute": "(not specified)"
                    },
                    "recommended_fix": f"Set '; SameSite=Lax' (recommended default) or '; SameSite=Strict' for '{cookie_name}'.",
                    "example_before": f"Set-Cookie: {cookie_name}={redacted_val}; Path=/",
                    "example_after": f"Set-Cookie: {cookie_name}={redacted_val}; Path=/; SameSite=Lax",
                    "limitations": (
                        "Modern Chromium browsers default to SameSite=Lax after 2 minutes, but relying on browser defaults "
                        "is not consistent across all clients and Safari/Firefox."
                    ),
                    "source": "native_cookies",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]
                })
            elif samesite == "none" and not is_secure:
                findings.append({
                    "title": f"Insecure SameSite=None without Secure for '{cookie_name}'",
                    "owasp_category": "A02:2025 Security Misconfiguration",
                    "severity": "Medium",
                    "confidence": "Confirmed",
                    "evidence_status": "confirmed_observation",
                    "description": "Browsers reject cookies with SameSite=None unless the Secure flag is also set.",
                    "impact": "Modern browsers will reject this cookie, causing unexpected session or application state failures.",
                    "affected_url": target_url,
                    "evidence": {
                        "cookie_name": cookie_name,
                        "samesite": "None",
                        "secure": False
                    },
                    "recommended_fix": f"Add '; Secure' when setting SameSite=None on '{cookie_name}'.",
                    "example_before": f"Set-Cookie: {cookie_name}={redacted_val}; SameSite=None",
                    "example_after": f"Set-Cookie: {cookie_name}={redacted_val}; SameSite=None; Secure",
                    "limitations": "SameSite=None is only needed for cross-site third-party embedding.",
                    "source": "native_cookies",
                    "references": ["https://web.dev/samesite-cookies-explained/"]
                })

    return findings

