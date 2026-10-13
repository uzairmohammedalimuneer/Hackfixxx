import re
from typing import List, Dict, Any
from urllib.parse import urljoin
from app.scanner.ssrf_validator import SafeAsyncHttpClient, redact_sensitive_data


SAFE_RESOURCE_PROBES = [
    {
        "path": "/robots.txt",
        "description": "Inspect robots.txt for exposed admin or sensitive directories",
        "expected_type": "text/plain",
        "check_type": "robots"
    },
    {
        "path": "/.env",
        "description": "Check for exposed environment files containing secrets",
        "expected_type": "text",
        "check_type": "env"
    },
    {
        "path": "/.git/HEAD",
        "description": "Check for exposed git repository metadata",
        "expected_type": "text/plain",
        "check_type": "git"
    },
    {
        "path": "/.well-known/security.txt",
        "description": "Verify presence of RFC 9116 security contact information",
        "expected_type": "text/plain",
        "check_type": "security_txt"
    },
    {
        "path": "/openapi.json",
        "description": "Check for publicly exposed OpenAPI API documentation schema",
        "expected_type": "application/json",
        "check_type": "api_schema"
    }
]


async def probe_exposed_resources(target_url: str, http_client: SafeAsyncHttpClient) -> List[Dict[str, Any]]:
    findings = []
    
    for probe in SAFE_RESOURCE_PROBES:
        probe_url = urljoin(target_url, probe["path"])
        try:
            resp = await http_client.get(probe_url)
            
            # 1. robots.txt analysis
            if probe["check_type"] == "robots" and resp.status_code == 200:
                body = resp.text[:4096]
                # Check if robots.txt disallows sensitive admin paths (e.g. /admin, /secret, /backup, /internal)
                sensitive_disallows = re.findall(r"Disallow:\s*(/.*(?:admin|secret|backup|internal|private|staging|db|dump).*)", body, re.IGNORECASE)
                if sensitive_disallows:
                    sample = [d.strip() for d in sensitive_disallows[:5]]
                    findings.append({
                        "title": "Robots.txt Discloses Sensitive Application Paths",
                        "owasp_category": "A02:2025 Security Misconfiguration",
                        "severity": "Informational",
                        "confidence": "Confirmed",
                        "evidence_status": "confirmed_observation",
                        "description": (
                            f"The robots.txt file at {probe_url} includes disallow entries for sensitive or administrative paths. "
                            "While robots.txt requests polite web crawlers not to index these URLs, it is publicly readable."
                        ),
                        "impact": (
                            "Attackers regularly inspect robots.txt to discover unlinked administrative interfaces, "
                            "staging portals, or internal documentation paths."
                        ),
                        "affected_url": probe_url,
                        "evidence": {
                            "status_code": 200,
                            "disallowed_sensitive_paths": sample
                        },
                        "recommended_fix": (
                            "Do not rely on robots.txt for access control. Enforce strict authentication and authorization "
                            "on all sensitive routes rather than merely disallowing crawler indexing."
                        ),
                        "example_before": "Disallow: /admin-portal/\nDisallow: /internal-db/",
                        "example_after": "# Protect routes with authentication tokens/sessions on the server",
                        "limitations": "Informational observation; the discovered paths may already be properly authenticated.",
                        "source": "native_exposed_resources",
                        "references": ["https://owasp.org/www-community/attacks/Robots.txt_Information_Disclosure"]
                    })

            # 2. .env file exposure check
            elif probe["check_type"] == "env" and resp.status_code == 200:
                body = resp.text[:2048]
                # Verify that it is actually a .env file and not a custom 200 error page or HTML template
                if re.search(r"^[A-Z0-9_]{3,}\s*=\s*.+$", body, re.MULTILINE) and "<html" not in body.lower():
                    # Extract only variable keys, NEVER store or display secret values
                    env_keys = re.findall(r"^([A-Z0-9_]{3,})\s*=", body, re.MULTILINE)[:8]
                    findings.append({
                        "title": "Publicly Accessible Environment File (.env)",
                        "owasp_category": "A02:2025 Security Misconfiguration",
                        "severity": "Critical",
                        "confidence": "Confirmed",
                        "evidence_status": "confirmed_observation",
                        "description": (
                            f"An environment configuration file (.env) is directly accessible over HTTP at {probe_url}. "
                            "Environment files frequently store database credentials, API secret keys, and JWT secrets."
                        ),
                        "impact": (
                            "Direct exposure of secrets allows complete compromise of databases, external cloud APIs, "
                            "and application authentication tokens."
                        ),
                        "affected_url": probe_url,
                        "evidence": {
                            "status_code": 200,
                            "exposed_keys": [f"{k}=***REDACTED***" for k in env_keys]
                        },
                        "recommended_fix": (
                            "Block public web server access to all dotfiles (.*), and remove .env files from the web document root."
                        ),
                        "example_before": "location ~ /.env { (serves file) }",
                        "example_after": "location ~ /\\.(?!well-known) { deny all; return 404; }",
                        "limitations": "Verify that all exposed credentials in the file are immediately revoked and rotated.",
                        "source": "native_exposed_resources",
                        "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/"]
                    })

            # 3. .git repository exposure check
            elif probe["check_type"] == "git" and resp.status_code == 200:
                body = resp.text[:512]
                # A genuine git HEAD file starts with "ref: refs/" or is a 40-char SHA
                if body.startswith("ref: refs/") or (len(body.strip()) == 40 and re.match(r"^[0-9a-f]{40}$", body.strip())):
                    findings.append({
                        "title": "Exposed Git Repository Metadata (.git/HEAD)",
                        "owasp_category": "A02:2025 Security Misconfiguration",
                        "severity": "High",
                        "confidence": "Confirmed",
                        "evidence_status": "confirmed_observation",
                        "description": (
                            f"Git repository metadata (.git/HEAD) was discovered at {probe_url}. "
                            "This indicates that the version control repository is within the public webroot."
                        ),
                        "impact": (
                            "Attackers can download the entire source code repository, commit history, branch contents, "
                            "and past credentials using automated tools like git-dumper."
                        ),
                        "affected_url": probe_url,
                        "evidence": {
                            "status_code": 200,
                            "git_head_signature": redact_sensitive_data(body[:60].strip())
                        },
                        "recommended_fix": "Configure web server rules to deny access to the .git directory and all subfiles.",
                        "example_before": "# Public access to .git allowed",
                        "example_after": "location ~ /\\.git { deny all; return 404; }",
                        "limitations": "Immediate remediation required; assume past git history may have been scraped.",
                        "source": "native_exposed_resources",
                        "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/"]
                    })

            # 4. OpenAPI / Swagger documentation schema check
            elif probe["check_type"] == "api_schema" and resp.status_code == 200:
                body = resp.text[:2048]
                if '"openapi"' in body or '"swagger"' in body:
                    findings.append({
                        "title": "Publicly Observable OpenAPI / Swagger Schema",
                        "owasp_category": "A01:2025 Broken Access Control",
                        "severity": "Informational",
                        "confidence": "Confirmed",
                        "evidence_status": "confirmed_observation",
                        "description": (
                            f"The OpenAPI schema document was found publicly accessible at {probe_url}. "
                            "This exposes an exact catalog of API routes, expected parameters, and models."
                        ),
                        "impact": (
                            "While public APIs often intend to publish schemas, internal or private API endpoints "
                            "should not be disclosed to unauthenticated visitors."
                        ),
                        "affected_url": probe_url,
                        "evidence": {
                            "status_code": 200,
                            "url": probe_url,
                            "format": "JSON Schema"
                        },
                        "recommended_fix": "If this API is private or internal, restrict schema access to authenticated administrators.",
                        "example_before": "# Schema accessible without authentication",
                        "example_after": "# Require session authentication or API key for /openapi.json",
                        "limitations": "Completely benign if the API is a deliberate public service.",
                        "source": "native_exposed_resources",
                        "references": ["https://owasp.org/www-project-api-security/"]
                    })

        except Exception:
            # Resource not found or timeout, proceed to next probe
            pass

    return findings

