from typing import List, Dict, Any
from app.scanner.ssrf_validator import SafeAsyncHttpClient


async def analyze_cors(target_url: str, http_client: SafeAsyncHttpClient) -> List[Dict[str, Any]]:
    findings = []
    test_origin = "https://untrusted-third-party.example"

    try:
        # Issue request with simulated untrusted Origin
        resp = await http_client.get(
            target_url,
            headers={"Origin": test_origin}
        )

        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        # 1. Arbitrary origin reflection with credentials allowed (Severe flaw)
        if acao == test_origin and acac:
            findings.append({
                "title": "Insecure CORS: Arbitrary Origin Reflection with Credentials",
                "owasp_category": "A01:2025 Broken Access Control",
                "severity": "High",
                "confidence": "Confirmed",
                "evidence_status": "confirmed_observation",
                "description": (
                    f"The server reflected an untrusted Origin header ('{test_origin}') into "
                    f"Access-Control-Allow-Origin while also setting Access-Control-Allow-Credentials: true."
                ),
                "impact": (
                    "Malicious websites can issue cross-origin requests on behalf of logged-in victims and "
                    "read authenticated response data (including private user profile details and tokens)."
                ),
                "affected_url": target_url,
                "evidence": {
                    "sent_origin": test_origin,
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": True
                },
                "recommended_fix": (
                    "Do not dynamically reflect arbitrary Origin headers when credentials are supported. "
                    "Validate the Origin against a strict server-side allowlist of trusted domains."
                ),
                "example_before": "res.header('Access-Control-Allow-Origin', req.headers.origin);\nres.header('Access-Control-Allow-Credentials', 'true');",
                "example_after": (
                    "const ALLOWED = ['https://trusted-app.com'];\n"
                    "if (ALLOWED.includes(req.headers.origin)) {\n"
                    "  res.header('Access-Control-Allow-Origin', req.headers.origin);\n"
                    "  res.header('Access-Control-Allow-Credentials', 'true');\n"
                    "}"
                ),
                "limitations": "Verify whether endpoints on this URL handle authenticated user sessions.",
                "source": "native_cors",
                "references": [
                    "https://portswigger.net/web-security/cors",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ]
            })

        # 2. Wildcard Access-Control-Allow-Origin (Contextual assessment)
        elif acao == "*":
            findings.append({
                "title": "Permissive CORS Policy (Wildcard Access-Control-Allow-Origin: *)",
                "owasp_category": "A01:2025 Broken Access Control",
                "severity": "Informational",
                "confidence": "Confirmed",
                "evidence_status": "confirmed_observation",
                "description": (
                    "The endpoint sets 'Access-Control-Allow-Origin: *'. "
                    "This grants any website permission to read responses via client-side JavaScript."
                ),
                "impact": (
                    "If the resource is intended for public consumption (e.g., public weather API or font asset), "
                    "wildcard is standard and harmless. However, if any sensitive or proprietary data is returned, "
                    "it is readable by third-party scripts."
                ),
                "affected_url": target_url,
                "evidence": {
                    "access_control_allow_origin": "*",
                    "access_control_allow_credentials": acac
                },
                "recommended_fix": "If this endpoint serves private user data, restrict Access-Control-Allow-Origin to specific trusted origins.",
                "example_before": "Access-Control-Allow-Origin: *",
                "example_after": "Access-Control-Allow-Origin: https://app.example.com",
                "limitations": (
                    "A wildcard origin alone is NOT an exploitable vulnerability for public content. "
                    "Browsers disallow cookie transmission when the wildcard is used."
                ),
                "source": "native_cors",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"]
            })

    except Exception:
        pass

    return findings

