from datetime import datetime
from typing import Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import httpx

from app.models.scan import Scan, Finding, RetestHistory
from app.scanner.ssrf_validator import SafeAsyncHttpClient, validate_url_safety, redact_dict
from app.scanner.modules.headers import analyze_security_headers
from app.scanner.modules.tls_check import check_tls_and_transport
from app.scanner.modules.cookies import analyze_cookies
from app.scanner.modules.info_disclosure import analyze_information_disclosure
from app.scanner.modules.exposed_resources import probe_exposed_resources
from app.scanner.modules.cors_check import analyze_cors


async def execute_retest(finding_id: str, session: AsyncSession) -> Dict[str, Any]:
    """
    Reruns the specific security check for an individual finding against the authorized target.
    Compares previous evidence to new evidence and records the genuine verification status.
    """
    res = await session.execute(select(Finding).where(Finding.id == finding_id))
    finding = res.scalar_one_or_none()
    if not finding:
        raise ValueError(f"Finding with ID '{finding_id}' not found.")

    scan_res = await session.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise ValueError("Associated scan record not found.")

    target_url = finding.affected_url or scan.target_url
    previous_ev = finding.evidence or {}
    source = finding.source or "native"
    title = finding.title

    # Validate target safety before outbound retest
    is_safe, norm_url, ssrf_err = validate_url_safety(target_url)
    if not is_safe:
        status = "inconclusive"
        new_ev = {"error": f"Retest blocked by URL safety check: {ssrf_err}"}
        details = "Could not verify because target URL failed security validation."
        return await _record_retest(session, scan.id, finding, previous_ev, new_ev, status, details)

    http_client = SafeAsyncHttpClient(timeout=8.0)

    try:
        # Determine check to execute based on source and title
        if source == "native_tls" or "TLS" in title or "HTTPS" in title:
            # Rerun TLS transport check
            tls_results = await check_tls_and_transport(norm_url)
            still_found = any(f["title"] == title for f in tls_results)
            new_ev = {"observed_issues": [f["title"] for f in tls_results], "target": norm_url}
            status = "still_present" if still_found else "verified_fixed"
            details = "Repeated TLS and transport security evaluation."

        elif source == "native_cors" or "CORS" in title:
            cors_results = await analyze_cors(norm_url, http_client)
            still_found = any(f["title"] == title for f in cors_results)
            new_ev = {"observed_issues": [f["title"] for f in cors_results]}
            status = "still_present" if still_found else "verified_fixed"
            details = "Repeated CORS preflight and origin reflection audit."

        elif source == "native_exposed_resources" or any(p in title for p in [".env", "Git", "Robots", "OpenAPI"]):
            exp_results = await probe_exposed_resources(norm_url, http_client)
            still_found = any(f["title"] == title for f in exp_results)
            new_ev = {"observed_issues": [f["title"] for f in exp_results]}
            status = "still_present" if still_found else "verified_fixed"
            details = "Repeated safe probe against specific exposed resource path."

        elif source in ("native_headers", "native_cookies", "native_info_disclosure"):
            # Fetch fresh HTTP response from affected URL
            resp = await http_client.get(norm_url)
            new_headers = redact_dict(dict(list(resp.headers.items())[:15]))
            new_ev = {
                "http_status": resp.status_code,
                "headers": new_headers
            }

            if source == "native_headers":
                header_results = analyze_security_headers(norm_url, resp)
                still_found = any(f["title"] == title for f in header_results)
                status = "still_present" if still_found else "verified_fixed"
                details = f"Re-inspected HTTP headers; status code {resp.status_code}."

            elif source == "native_cookies":
                cookie_results = analyze_cookies(norm_url, resp)
                still_found = any(f["title"] == title for f in cookie_results)
                status = "still_present" if still_found else "verified_fixed"
                details = "Re-inspected Set-Cookie flags."

            elif source == "native_info_disclosure":
                info_results = analyze_information_disclosure(norm_url, resp)
                still_found = any(f["title"] == title for f in info_results)
                status = "still_present" if still_found else "verified_fixed"
                details = "Re-inspected response banners and error disclosure."

        else:
            status = "not_supported"
            new_ev = {"message": f"Automated single-point retesting not supported for source '{source}'."}
            details = "This check requires manual verification or full crawl re-run."

    except Exception as e:
        status = "inconclusive"
        new_ev = {"error": str(e)}
        details = f"Retest encountered an error when communicating with target: {str(e)[:100]}"

    return await _record_retest(session, scan.id, finding, previous_ev, new_ev, status, details)


async def _record_retest(
    session: AsyncSession,
    scan_id: str,
    finding: Finding,
    previous_ev: dict,
    new_ev: dict,
    status: str,
    details: str
) -> Dict[str, Any]:
    # Update finding verification status
    finding.verification_status = status
    finding.last_seen = datetime.utcnow()

    retest_obj = RetestHistory(
        scan_id=scan_id,
        finding_id=finding.id,
        previous_evidence=previous_ev,
        new_evidence=new_ev,
        status=status,
        timestamp=datetime.utcnow(),
        details=details
    )
    session.add(retest_obj)
    await session.commit()

    return {
        "id": retest_obj.id,
        "scan_id": scan_id,
        "finding_id": finding.id,
        "status": status,
        "timestamp": retest_obj.timestamp,
        "previous_evidence": previous_ev,
        "new_evidence": new_ev,
        "details": details
    }

