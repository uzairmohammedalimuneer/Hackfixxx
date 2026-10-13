import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
import httpx
from app.scanner.ssrf_validator import validate_url_safety


async def check_tls_and_transport(target_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)

    # 1. Plain HTTP without HTTPS warning
    if scheme == "http":
        findings.append({
            "title": "Unencrypted Transport (Cleartext HTTP)",
            "owasp_category": "A04:2025 Cryptographic Failures",
            "severity": "High",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                f"The target website was accessed over unencrypted HTTP ({target_url}). "
                "Cleartext traffic can be intercepted, read, or modified by intermediate network devices."
            ),
            "impact": (
                "Session cookies, credentials, and sensitive application data transmitted over unencrypted "
                "HTTP are vulnerable to eavesdropping and Man-In-The-Middle (MITM) tampering."
            ),
            "affected_url": target_url,
            "evidence": {
                "scheme": "http",
                "port": port,
                "url": target_url
            },
            "recommended_fix": "Enforce HTTPS across the entire application and redirect all HTTP requests to HTTPS.",
            "example_before": f"http://{hostname}:{port}/",
            "example_after": f"https://{hostname}/",
            "limitations": "Ensure valid TLS certificates are installed on web server or reverse proxy.",
            "source": "native_tls",
            "references": [
                "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                "https://letsencrypt.org/howitworks/"
            ]
        })
        return findings

    # 2. For HTTPS targets, inspect TLS certificate directly using genuine Python SSL context
    if scheme == "https" and hostname:
        ssl_context = ssl.create_default_context()
        try:
            # Connect and perform TLS handshake
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    # Check certificate expiry
                    if cert and "notAfter" in cert:
                        # Format example: 'May 10 12:00:00 2026 GMT'
                        not_after_str = cert["notAfter"]
                        try:
                            expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_remaining = (expiry_date - now).days

                            if days_remaining < 0:
                                findings.append({
                                    "title": "Expired TLS Certificate",
                                    "owasp_category": "A04:2025 Cryptographic Failures",
                                    "severity": "High",
                                    "confidence": "Confirmed",
                                    "evidence_status": "confirmed_observation",
                                    "description": f"The TLS certificate for {hostname} expired on {not_after_str} ({abs(days_remaining)} days ago).",
                                    "impact": "Browsers will show strong security warnings, blocking user access and breaking trust.",
                                    "affected_url": target_url,
                                    "evidence": {
                                        "expiry_date": not_after_str,
                                        "days_remaining": days_remaining,
                                        "tls_version": tls_version
                                    },
                                    "recommended_fix": "Renew and deploy a valid TLS certificate immediately.",
                                    "example_before": f"Expired certificate ({not_after_str})",
                                    "example_after": "Valid, auto-renewed certificate (e.g. Let's Encrypt / Certbot)",
                                    "limitations": "Automated renewal alerts should be configured on the host.",
                                    "source": "native_tls",
                                    "references": ["https://letsencrypt.org/"]
                                })
                            elif days_remaining < 15:
                                findings.append({
                                    "title": "TLS Certificate Expiring Soon",
                                    "owasp_category": "A04:2025 Cryptographic Failures",
                                    "severity": "Low",
                                    "confidence": "Confirmed",
                                    "evidence_status": "confirmed_observation",
                                    "description": f"The TLS certificate for {hostname} expires in {days_remaining} days ({not_after_str}).",
                                    "impact": "If unrenewed, the site will soon display browser warnings and become inaccessible.",
                                    "affected_url": target_url,
                                    "evidence": {
                                        "expiry_date": not_after_str,
                                        "days_remaining": days_remaining,
                                        "tls_version": tls_version
                                    },
                                    "recommended_fix": "Trigger certificate renewal before expiration.",
                                    "example_before": f"Expires in {days_remaining} days",
                                    "example_after": "Renewed certificate with >30 days validity",
                                    "limitations": "Ensure renewal automation (e.g. Certbot systemd timer) is active.",
                                    "source": "native_tls",
                                    "references": ["https://letsencrypt.org/"]
                                })
                        except Exception:
                            pass

                    # Check for outdated TLS version (TLS 1.0 or 1.1)
                    if tls_version in ("TLSv1", "TLSv1.1"):
                        findings.append({
                            "title": f"Deprecated TLS Protocol Version ({tls_version})",
                            "owasp_category": "A04:2025 Cryptographic Failures",
                            "severity": "Medium",
                            "confidence": "Confirmed",
                            "evidence_status": "confirmed_observation",
                            "description": f"The web server negotiated connection using {tls_version}. TLS 1.0 and 1.1 are deprecated.",
                            "impact": "Legacy TLS protocols have known cryptographic vulnerabilities (e.g. BEAST, POODLE) and lack modern cipher suites.",
                            "affected_url": target_url,
                            "evidence": {
                                "negotiated_version": tls_version,
                                "cipher": cipher
                            },
                            "recommended_fix": "Disable TLS 1.0 and TLS 1.1 in the web server configuration; require TLS 1.2 or TLS 1.3.",
                            "example_before": f"ssl_protocols {tls_version} TLSv1.2;",
                            "example_after": "ssl_protocols TLSv1.2 TLSv1.3;",
                            "limitations": "Check whether legacy clients require support before disabling.",
                            "source": "native_tls",
                            "references": ["https://datatracker.ietf.org/doc/html/rfc8996"]
                        })

        except ssl.SSLCertVerificationError as e:
            findings.append({
                "title": "TLS Certificate Verification Failure",
                "owasp_category": "A04:2025 Cryptographic Failures",
                "severity": "High",
                "confidence": "Confirmed",
                "evidence_status": "confirmed_observation",
                "description": f"TLS handshake failed certificate validation: {str(e)}",
                "impact": "Users will be prevented from connecting by modern web browsers unless manual security overrides are used.",
                "affected_url": target_url,
                "evidence": {
                    "error_type": "SSLCertVerificationError",
                    "details": str(e)
                },
                "recommended_fix": "Install a valid, publicly trusted certificate matching the domain name.",
                "example_before": "Self-signed or invalid hostname certificate",
                "example_after": "Trusted CA signed certificate",
                "limitations": "Internal development domains may use custom internal CAs.",
                "source": "native_tls",
                "references": ["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"]
            })
        except Exception as e:
            # In local dev test environments or connection refused on standard TLS, record note
            pass

    # 3. Check HTTP-to-HTTPS redirect behaviour
    if scheme == "https" and hostname:
        http_test_url = f"http://{hostname}/"
        is_safe, norm_http, _ = validate_url_safety(http_test_url)
        if is_safe:
            try:
                async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                    resp = await client.get(norm_http)
                    if not (resp.is_redirect and resp.headers.get("location", "").lower().startswith("https://")):
                        findings.append({
                            "title": "Missing HTTP to HTTPS Redirection",
                            "owasp_category": "A04:2025 Cryptographic Failures",
                            "severity": "Medium",
                            "confidence": "High",
                            "evidence_status": "confirmed_observation",
                            "description": (
                                f"Accessing the target via HTTP ({http_test_url}) does not automatically redirect to HTTPS. "
                                f"Observed HTTP response status: {resp.status_code}."
                            ),
                            "impact": "Users typing the domain without 'https://' may transmit requests in unencrypted cleartext.",
                            "affected_url": http_test_url,
                            "evidence": {
                                "tested_url": http_test_url,
                                "status_code": resp.status_code,
                                "redirect_location": resp.headers.get("location", "(none)")
                            },
                            "recommended_fix": "Configure HTTP (port 80) to return a 301 Permanent Redirect to HTTPS.",
                            "example_before": "HTTP 200 OK (Served over plain HTTP)",
                            "example_after": f"HTTP 301 Moved Permanently\nLocation: https://{hostname}/",
                            "limitations": "Ensure no automated API consumers break when encountering 301 redirects.",
                            "source": "native_tls",
                            "references": ["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"]
                        })
            except Exception:
                # Port 80 might not be open or firewalled, which is safe
                pass

    return findings

