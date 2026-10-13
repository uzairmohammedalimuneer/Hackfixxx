import re
from typing import List, Dict, Any
import httpx
from app.scanner.ssrf_validator import redact_sensitive_data


STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python Stack Trace"),
    (re.compile(r"at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_]+\.java:\d+\)", re.IGNORECASE), "Java Stack Trace"),
    (re.compile(r"Fatal error:.*in .*\.php on line \d+", re.IGNORECASE), "PHP Fatal Error"),
    (re.compile(r"Microsoft OLE DB Provider for (SQL Server|ODBC)", re.IGNORECASE), "Database Error Disclosure"),
    (re.compile(r"(pg_query\(\)|PostgreSQL.*ERROR:|syntax error at or near)", re.IGNORECASE), "PostgreSQL Error Disclosure"),
    (re.compile(r"(SQLSTATE\[\w+\]|ORA-\d{5}|mysql_fetch_array)", re.IGNORECASE), "SQL Error Information"),
    (re.compile(r"Django Version:.*Exception Value:", re.IGNORECASE), "Django Debug Page"),
    (re.compile(r"Werkzeug Debugger.*WSGI", re.IGNORECASE), "Werkzeug Interactive Debugger"),
]

INTERNAL_PATH_PATTERNS = [
    re.compile(r"(/var/www/[a-zA-Z0-9_\-\./]+)", re.IGNORECASE),
    re.compile(r"([A-Za-z]:\\[Users|inetpub|xampp|Apache][a-zA-Z0-9_\\\-\.]+)", re.IGNORECASE),
    re.compile(r"(/home/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\./]+)", re.IGNORECASE),
]


def analyze_information_disclosure(target_url: str, response: httpx.Response) -> List[Dict[str, Any]]:
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    body_text = response.text[:65536]  # Bound inspection window to first 64KB

    # 1. Server Banner Disclosure
    server_banner = headers.get("server")
    if server_banner:
        # Check if version numbers or detailed components are exposed (e.g. Apache/2.4.52 or nginx/1.18.0)
        has_version = bool(re.search(r"\d+\.\d+", server_banner))
        findings.append({
            "title": f"Web Server Banner Disclosed ({server_banner[:40]})",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Low" if has_version else "Informational",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                f"The web server advertises its software identity in the 'Server' header: '{server_banner}'. "
                + ("Detailed version numbers were detected, which facilitates targeted vulnerability mapping." if has_version else "")
            ),
            "impact": (
                "Attackers use advertised server technologies and version numbers to look up known CVEs "
                "and tailor exploits specifically for that server version."
            ),
            "affected_url": target_url,
            "evidence": {
                "header_name": "Server",
                "observed_value": server_banner,
                "has_version_number": has_version
            },
            "recommended_fix": (
                "Configure your web server (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx) "
                "or reverse proxy to strip or generalize the Server header."
            ),
            "example_before": f"Server: {server_banner}",
            "example_after": "Server: (generic or removed)",
            "limitations": "Removing the server banner slows reconnaissance slightly, but does not fix underlying vulnerabilities.",
            "source": "native_info_disclosure",
            "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/"]
        })

    # 2. X-Powered-By / Framework Disclosure
    powered_by = headers.get("x-powered-by") or headers.get("x-aspnet-version") or headers.get("x-runtime")
    if powered_by:
        findings.append({
            "title": f"Technology Framework Disclosed via Header ({powered_by[:40]})",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "severity": "Low",
            "confidence": "Confirmed",
            "evidence_status": "confirmed_observation",
            "description": (
                f"The application leaks underlying runtime or framework identity via headers: '{powered_by}'. "
                "Default framework signatures expose technology stack details."
            ),
            "impact": "Simplifies attacker profiling of application architecture and unpatched framework dependencies.",
            "affected_url": target_url,
            "evidence": {
                "observed_header": "X-Powered-By",
                "value": powered_by
            },
            "recommended_fix": "Disable 'X-Powered-By' in your framework settings (e.g. `app.disable('x-powered-by')` in Express).",
            "example_before": f"X-Powered-By: {powered_by}",
            "example_after": "# Header removed completely",
            "limitations": "Passive reconnaissance reduction only.",
            "source": "native_info_disclosure",
            "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/"]
        })

    # 3. Stack Trace or Debugger Page Detection
    for pattern, label in STACK_TRACE_PATTERNS:
        match = pattern.search(body_text)
        if match:
            # Extract surrounding context (safely bounded)
            start_pos = max(0, match.start() - 30)
            end_pos = min(len(body_text), match.end() + 150)
            snippet = redact_sensitive_data(body_text[start_pos:end_pos])

            findings.append({
                "title": f"Application Debug Information Disclosed ({label})",
                "owasp_category": "A10:2025 Mishandling of Exceptional Conditions",
                "severity": "High",
                "confidence": "High",
                "evidence_status": "confirmed_observation",
                "description": (
                    f"The server returned an unhandled exception or debug trace: {label}. "
                    "Production applications should display friendly generic error pages rather than technical exception details."
                ),
                "impact": (
                    "Stack traces disclose internal file paths, code snippets, database schema details, "
                    "framework versions, and third-party library versions to any visitor."
                ),
                "affected_url": target_url,
                "evidence": {
                    "matched_pattern": label,
                    "snippet": snippet.strip(),
                    "http_status": response.status_code
                },
                "recommended_fix": (
                    "Disable debug mode in production environment settings and configure global exception "
                    "handlers to return safe, standardized error responses."
                ),
                "example_before": "DEBUG = True (Exposes full traceback in browser)",
                "example_after": "DEBUG = False (Displays customized 500 error page, logs trace server-side)",
                "limitations": "Ensure developers have access to centralized server-side logging for troubleshooting.",
                "source": "native_info_disclosure",
                "references": ["https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures/"]
            })
            break  # One high-severity stack trace finding is sufficient

    # 4. Internal Path Disclosure in Response Body
    for path_pat in INTERNAL_PATH_PATTERNS:
        path_match = path_pat.search(body_text)
        if path_match:
            discovered_path = redact_sensitive_data(path_match.group(0))
            findings.append({
                "title": "Internal Filesystem Path Disclosed",
                "owasp_category": "A02:2025 Security Misconfiguration",
                "severity": "Low",
                "confidence": "Medium",
                "evidence_status": "confirmed_observation",
                "description": f"The response body contains an internal server filesystem path: '{discovered_path}'.",
                "impact": "Assists attackers in constructing path traversal payloads or locating server configuration files.",
                "affected_url": target_url,
                "evidence": {
                    "internal_path_sample": discovered_path
                },
                "recommended_fix": "Sanitize server responses and catch exceptions before internal absolute paths are returned to clients.",
                "example_before": f"Error in {discovered_path}",
                "example_after": "An unexpected error occurred. Request ID: req_98172",
                "limitations": "Ensure path is truly server-side and not an intended public URL path.",
                "source": "native_info_disclosure",
                "references": ["https://cwe.mitre.org/data/definitions/200.html"]
            })
            break

    return findings

