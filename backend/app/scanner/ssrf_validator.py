import socket
import ipaddress
import re
from urllib.parse import urlparse, urljoin
from typing import Tuple, List, Optional, Set
import httpx
from app.core.config import settings


# Cloud metadata and forbidden hostnames
METADATA_HOSTS: Set[str] = {
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
    "metadata.azure.com",
    "100.100.100.200"
}

# Regex patterns for redacting sensitive secrets
SENSITIVE_PATTERNS = [
    (re.compile(r"(api[_-]?key|secret|token|password|auth|jwt|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?", re.IGNORECASE), r"\1=***REDACTED***"),
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), r"\1***REDACTED***"),
    (re.compile(r"(ghp_[a-zA-Z0-9]{30,}|gho_[a-zA-Z0-9]{30,})"), r"***REDACTED_GITHUB_TOKEN***"),
    (re.compile(r"(AIza[0-9A-Za-z\-_]{35})"), r"***REDACTED_GOOGLE_KEY***"),
]


def redact_sensitive_data(text: str) -> str:
    """Safely redact credentials, API keys, and sensitive tokens from logs and evidence."""
    if not isinstance(text, str):
        return text
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_dict(data: dict) -> dict:
    """Recursively redacts dictionary values."""
    cleaned = {}
    for k, v in data.items():
        lower_k = str(k).lower()
        if any(secret in lower_k for secret in ["secret", "token", "password", "key", "authorization"]):
            cleaned[k] = "***REDACTED***"
        elif isinstance(v, str):
            cleaned[k] = redact_sensitive_data(v)
        elif isinstance(v, dict):
            cleaned[k] = redact_dict(v)
        elif isinstance(v, list):
            cleaned[k] = [redact_sensitive_data(item) if isinstance(item, str) else item for item in v]
        else:
            cleaned[k] = v
    return cleaned


class SSRFValidationError(Exception):
    """Raised when target URL violates SSRF safety constraints."""
    pass


def validate_url_safety(url_str: str) -> Tuple[bool, str, str]:
    """
    Validates that a URL is syntactically sound and safe from SSRF.
    Returns: (is_safe: bool, normalized_url: str, error_message: str)
    """
    if not url_str or not isinstance(url_str, str):
        return False, "", "URL cannot be empty."

    url_str = url_str.strip()
    
    try:
        parsed = urlparse(url_str)
    except Exception as e:
        return False, "", f"Malformed URL: {str(e)}"

    # 1. Scheme check: HTTP and HTTPS only
    if parsed.scheme.lower() not in ("http", "https"):
        return False, "", f"Invalid scheme '{parsed.scheme}'. Only http:// and https:// are supported."

    # 2. Host check
    hostname = parsed.hostname
    if not hostname:
        return False, "", "URL missing valid hostname or domain."

    hostname_lower = hostname.lower()

    # 3. Disallow user info (credentials embedded in URL)
    if parsed.username or parsed.password:
        return False, "", "Embedded credentials (user:password@) in URLs are strictly prohibited."

    # 4. Check against known cloud metadata services
    if hostname_lower in METADATA_HOSTS:
        return False, "", "Access to cloud metadata endpoints is prohibited."

    # 5. Check if host is on explicit developer allowlist (for local authorized testing)
    is_explicitly_allowed_dev_host = (
        hostname_lower in [h.lower() for h in settings.SCAN_ALLOWED_HOSTS]
    )

    # 6. Resolve DNS and inspect all resolved IP addresses
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, "", f"Could not resolve hostname '{hostname}': {str(e)}"
    except Exception as e:
        return False, "", f"DNS resolution failed for '{hostname}': {str(e)}"

    if not addr_info:
        return False, "", f"No IP addresses resolved for hostname '{hostname}'."

    resolved_ips = set()
    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        resolved_ips.add(ip_str)

    # Validate each resolved IP address
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "", f"Resolved to invalid IP address: {ip_str}"

        # If it's an explicitly allowed host for local testing, permit loopback or private
        if is_explicitly_allowed_dev_host:
            # Still strictly block cloud metadata even on allowed hostnames
            if str(ip_obj) == "169.254.169.254":
                return False, "", "Access to link-local cloud metadata is blocked."
            continue

        # Link-local (169.254.0.0/16, fe80::/10) - always blocked
        if ip_obj.is_link_local:
            return False, "", f"Target resolves to link-local IP address ({ip_str}), which is blocked for security."

        # Loopback (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            return False, "", (
                f"Target resolves to loopback IP address ({ip_str}). "
                "Local targets are disabled by default. Add hostname to SCAN_ALLOWED_HOSTS to test local services."
            )

        # Private IP space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if ip_obj.is_private and not settings.ALLOW_PRIVATE_IPS_IN_DEV:
            return False, "", (
                f"Target resolves to private network address ({ip_str}). "
                "Private network scanning is blocked by default to prevent SSRF."
            )

        # Multicast, reserved, unspecified
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, "", f"Target resolves to reserved or multicast IP address ({ip_str}), which is blocked."

    # Return normalized URL
    normalized_path = parsed.path if parsed.path else "/"
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc}{normalized_path}"
    if parsed.query:
        normalized += f"?{parsed.query}"

    return True, normalized, ""


class SafeAsyncHttpClient:
    """
    An async HTTP client wrapper enforcing:
    - SSRF pre-check on every request
    - Re-validation of every redirect target
    - Strict timeout
    - Max response size capping
    - No credential leakage
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_size: int = 2 * 1024 * 1024,
        verify_ssl: bool = True
    ):
        self.timeout = timeout
        self.max_size = max_size
        self.verify_ssl = verify_ssl

    async def get(
        self,
        url: str,
        headers: Optional[dict] = None,
        max_redirects: int = 5
    ) -> httpx.Response:
        current_url = url
        redirect_count = 0
        req_headers = {
            "User-Agent": "HACKFIX-AI-Security-Auditor/1.0 (+https://hackfix.local/scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }
        if headers:
            req_headers.update(headers)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=False
        ) as client:
            while True:
                # 1. SSRF validation on current URL
                is_safe, norm_url, err = validate_url_safety(current_url)
                if not is_safe:
                    raise SSRFValidationError(f"Request blocked by SSRF protection for {current_url}: {err}")

                # 2. Issue request
                response = await client.get(norm_url, headers=req_headers)

                # 3. Handle redirect manually with SSRF validation
                if response.is_redirect and "location" in response.headers:
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise httpx.TooManyRedirects(f"Exceeded max redirects ({max_redirects})")

                    raw_location = response.headers["location"]
                    next_url = urljoin(current_url, raw_location)
                    current_url = next_url
                    continue

                # 4. Enforce max response size limit
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self.max_size:
                    raise ValueError(f"Response size {content_length} bytes exceeds maximum limit ({self.max_size} bytes)")

                return response

