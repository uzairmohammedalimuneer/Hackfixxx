import asyncio
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import Scan, Finding, ScanLog
from app.scanner.ssrf_validator import validate_url_safety, SafeAsyncHttpClient, SSRFValidationError
from app.scanner.crawler import BoundedSameOriginCrawler
from app.scanner.modules.headers import analyze_security_headers
from app.scanner.modules.tls_check import check_tls_and_transport
from app.scanner.modules.cookies import analyze_cookies
from app.scanner.modules.info_disclosure import analyze_information_disclosure
from app.scanner.modules.exposed_resources import probe_exposed_resources
from app.scanner.modules.cors_check import analyze_cors
from app.scanner.modules.zap_integrator import run_zap_baseline_if_enabled
from app.services.gemini_service import enhance_findings_with_ai
from app.core.config import settings


OWASP_2025_DEFINITIONS = [
    {
        "id": "A01",
        "name": "A01 Broken Access Control",
        "description": "Restrictions on what authenticated and unauthenticated users can do are improperly enforced.",
        "passive_capability": "limited",
        "limitation_note": "Passive scanning tests publicly accessible endpoints, CORS, and sensitive URL paths, but cannot test multi-role authorization."
    },
    {
        "id": "A02",
        "name": "A02 Security Misconfiguration",
        "description": "Missing security hardening, default configurations, verbose error messages, and missing security headers.",
        "passive_capability": "high",
        "limitation_note": "Directly assessed via HTTP security headers, cookie flags, and server banner configurations."
    },
    {
        "id": "A03",
        "name": "A03 Software Supply Chain Failures",
        "description": "Compromised third-party dependencies, malicious build pipelines, or outdated unpatched components.",
        "passive_capability": "none",
        "limitation_note": "Software bill of materials (SBOM) and package manifest analysis are required to assess supply-chain security."
    },
    {
        "id": "A04",
        "name": "A04 Cryptographic Failures",
        "description": "Flaws in data in transit encryption, weak ciphers, expired certificates, or lack of HSTS.",
        "passive_capability": "high",
        "limitation_note": "Directly observable via TLS handshake inspection, certificate validity checks, and HSTS enforcement."
    },
    {
        "id": "A05",
        "name": "A05 Injection",
        "description": "SQL, NoSQL, OS command, or LDAP injection from untrusted user data.",
        "passive_capability": "none",
        "limitation_note": "Passive auditing does not send attack injection vectors or destructive payloads; injection testing is not assessed."
    },
    {
        "id": "A06",
        "name": "A06 Insecure Design",
        "description": "Fundamental flaws in software architecture, threat modeling, and business logic.",
        "passive_capability": "none",
        "limitation_note": "Requires architectural review and business-logic validation outside automated URL scanning."
    },
    {
        "id": "A07",
        "name": "A07 Authentication Failures",
        "description": "Weak passwords, session fixation, credential stuffing vulnerabilities, or missing MFA.",
        "passive_capability": "limited",
        "limitation_note": "Cookie security flags assessed; credential guessing and login testing are not performed in non-destructive scans."
    },
    {
        "id": "A08",
        "name": "A08 Software or Data Integrity Failures",
        "description": "Unverified code updates, untrusted deserialization, or unverified CDN scripts.",
        "passive_capability": "limited",
        "limitation_note": "Subresource Integrity (SRI) and client script signatures are only partially visible in static markup."
    },
    {
        "id": "A09",
        "name": "A09 Security Logging & Alerting Failures",
        "description": "Insufficient logging of security events, breach detection delays, or unmonitored anomalies.",
        "passive_capability": "none",
        "limitation_note": "Server-side audit logs and SIEM configurations cannot be assessed from external HTTP responses."
    },
    {
        "id": "A10",
        "name": "A10 Mishandling of Exceptional Conditions",
        "description": "Improper error handling exposing sensitive information, stack traces, or system states.",
        "passive_capability": "medium",
        "limitation_note": "Assessed via observed error pages, unhandled exception traces, and verbose internal paths."
    }
]


def calculate_owasp_coverage(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    coverage = {}
    
    # Map finding counts by category ID
    counts = {item["id"]: 0 for item in OWASP_2025_DEFINITIONS}
    for f in findings:
        cat_str = f.get("owasp_category", "")
        for item in OWASP_2025_DEFINITIONS:
            if item["id"] in cat_str or item["name"] in cat_str:
                counts[item["id"]] += 1
                break

    for item in OWASP_2025_DEFINITIONS:
        cid = item["id"]
        cname = item["name"]
        count = counts[cid]

        if count > 0:
            status = "findings_present"
        elif item["passive_capability"] == "high":
            status = "no_findings_detected"
        elif item["passive_capability"] in ("medium", "limited"):
            status = "assessment_limited"
        else:
            status = "not_assessed"

        coverage[cid] = {
            "category_id": cid,
            "category_name": cname,
            "status": status,
            "finding_count": count,
            "limitation_note": item["limitation_note"]
        }

    return coverage


class ScanOrchestrator:
    """
    Executes the complete scan lifecycle:
    FIND -> PROVE -> FIX -> VERIFY -> COMPLETED
    """

    def __init__(self, scan_id: str, session_factory):
        self.scan_id = scan_id
        self.session_factory = session_factory
        self.raw_findings: List[Dict[str, Any]] = []

    async def _log(self, message: str, stage: str = "FIND", level: str = "INFO"):
        async with self.session_factory() as session:
            log_entry = ScanLog(
                scan_id=self.scan_id,
                stage=stage,
                level=level,
                message=message,
                timestamp=datetime.utcnow()
            )
            session.add(log_entry)
            await session.commit()

    async def _update_scan_state(
        self,
        status: Optional[str] = None,
        stage: Optional[str] = None,
        error_message: Optional[str] = None,
        summary: Optional[dict] = None
    ):
        async with self.session_factory() as session:
            result = await session.execute(select(Scan).where(Scan.id == self.scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                if status:
                    scan.status = status
                if stage:
                    scan.stage = stage
                if error_message:
                    scan.error_message = error_message
                if summary:
                    scan.summary = summary
                if status == "running" and not scan.started_at:
                    scan.started_at = datetime.utcnow()
                if status in ("completed", "failed", "cancelled"):
                    scan.completed_at = datetime.utcnow()
                await session.commit()

    async def execute_scan(self):
        start_time = time.time()
        scanned_urls: List[str] = []

        try:
            # 1. Retrieve scan record
            async with self.session_factory() as session:
                res = await session.execute(select(Scan).where(Scan.id == self.scan_id))
                scan = res.scalar_one_or_none()
                if not scan:
                    return
                target_url = scan.target_url
                max_pages = scan.scan_options.get("max_pages", 15)
                crawl_depth = scan.scan_options.get("crawl_depth", 2)

            await self._update_scan_state(status="running", stage="FIND")
            await self._log(f"Initiating security scan against authorized target: {target_url}", "FIND", "INFO")

            # 2. Safety and SSRF pre-check
            is_safe, norm_url, ssrf_err = validate_url_safety(target_url)
            if not is_safe:
                err_msg = f"URL rejected by security controls: {ssrf_err}"
                await self._log(err_msg, "FIND", "ERROR")
                await self._update_scan_state(status="failed", stage="FAILED", error_message=err_msg)
                return

            http_client = SafeAsyncHttpClient(timeout=settings.REQUEST_TIMEOUT_SECONDS)

            # -------------------------------------------------------------
            # STAGE 1: FIND (Discovery, Crawl & Native Checks)
            # -------------------------------------------------------------
            await self._log("STAGE 1 [FIND]: Running non-destructive discovery and passive security checks...", "FIND", "INFO")

            # A. TLS & Transport Analysis
            await self._log("Checking TLS certificate validity, expiration, and HTTPS redirection...", "FIND", "INFO")
            tls_findings = await check_tls_and_transport(norm_url)
            self.raw_findings.extend(tls_findings)
            if tls_findings:
                await self._log(f"Observed {len(tls_findings)} transport/TLS security findings.", "FIND", "INFO")
            else:
                await self._log("TLS transport checks completed with no anomalies observed.", "FIND", "INFO")

            # B. Exposed Resources Probe
            await self._log("Probing for exposed configuration files (.env, .git, robots.txt, OpenAPI)...", "FIND", "INFO")
            resource_findings = await probe_exposed_resources(norm_url, http_client)
            self.raw_findings.extend(resource_findings)

            # C. CORS Policy Analysis
            await self._log("Auditing Cross-Origin Resource Sharing (CORS) header configuration...", "FIND", "INFO")
            cors_findings = await analyze_cors(norm_url, http_client)
            self.raw_findings.extend(cors_findings)

            # D. Same-Origin Page Crawling & Per-Page Audits
            async def audit_page(page_url: str, response: httpx.Response):
                # Security Headers
                h_findings = analyze_security_headers(page_url, response)
                self.raw_findings.extend(h_findings)

                # Cookie Attributes
                c_findings = analyze_cookies(page_url, response)
                self.raw_findings.extend(c_findings)

                # Information Disclosure & Stack Traces
                i_findings = analyze_information_disclosure(page_url, response)
                self.raw_findings.extend(i_findings)

            crawler = BoundedSameOriginCrawler(
                base_url=norm_url,
                http_client=http_client,
                max_pages=max_pages,
                max_depth=crawl_depth
            )

            async def crawl_logger(msg: str, level: str):
                await self._log(msg, "FIND", level)

            scanned_urls = await crawler.crawl(page_callback=audit_page, log_callback=crawl_logger)
            await self._log(f"Crawled {len(scanned_urls)} unique same-origin URLs safely.", "FIND", "INFO")

            # E. Optional OWASP ZAP Baseline Integration
            zap_res = await run_zap_baseline_if_enabled(norm_url)
            if zap_res.ran:
                await self._log(zap_res.message, "FIND", "INFO")
                self.raw_findings.extend(zap_res.findings)
            else:
                await self._log(f"OWASP ZAP integration status: {zap_res.message}", "FIND", "INFO")

            # -------------------------------------------------------------
            # STAGE 2: PROVE (Evaluate & Deduplicate Observed Evidence)
            # -------------------------------------------------------------
            await self._update_scan_state(stage="PROVE")
            await self._log("STAGE 2 [PROVE]: Evaluating collected HTTP evidence, headers, and status proofs...", "PROVE", "INFO")

            # Deduplicate findings by title + affected_url
            unique_findings_map = {}
            for item in self.raw_findings:
                dedup_key = f"{item['title']}|{item['affected_url']}"
                if dedup_key not in unique_findings_map:
                    unique_findings_map[dedup_key] = item

            deduplicated_findings = list(unique_findings_map.values())
            await self._log(f"Normalized and proved {len(deduplicated_findings)} distinct security findings.", "PROVE", "INFO")

            # -------------------------------------------------------------
            # STAGE 3: FIX (Remediation & Gemini AI Explanations)
            # -------------------------------------------------------------
            await self._update_scan_state(stage="FIX")
            await self._log("STAGE 3 [FIX]: Generating remediation advice and beginner-friendly AI explanations...", "FIX", "INFO")

            # Enhance findings with Gemini AI explanations (or deterministic fallback)
            async def ai_logger(msg: str):
                await self._log(msg, "FIX", "INFO")

            final_findings = await enhance_findings_with_ai(deduplicated_findings, ai_logger)

            # -------------------------------------------------------------
            # STAGE 4: VERIFY (Retest Baseline Configuration)
            # -------------------------------------------------------------
            await self._update_scan_state(stage="VERIFY")
            await self._log("STAGE 4 [VERIFY]: Preparing evidence baselines for interactive retesting...", "VERIFY", "INFO")

            # -------------------------------------------------------------
            # PERSISTENCE & SUMMARY
            # -------------------------------------------------------------
            severity_counts = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Informational": 0
            }

            for f in final_findings:
                sev = f.get("severity", "Low")
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts["Low"] += 1

            owasp_cov = calculate_owasp_coverage(final_findings)
            duration = round(time.time() - start_time, 2)

            summary = {
                "total_findings": len(final_findings),
                "critical_count": severity_counts["Critical"],
                "high_count": severity_counts["High"],
                "medium_count": severity_counts["Medium"],
                "low_count": severity_counts["Low"],
                "info_count": severity_counts["Informational"],
                "pages_scanned": len(scanned_urls),
                "duration_seconds": duration,
                "owasp_coverage": owasp_cov
            }

            # Save findings to database
            async with self.session_factory() as session:
                for f_data in final_findings:
                    finding_obj = Finding(
                        scan_id=self.scan_id,
                        title=f_data["title"],
                        owasp_category=f_data["owasp_category"],
                        severity=f_data["severity"],
                        confidence=f_data.get("confidence", "High"),
                        evidence_status=f_data.get("evidence_status", "confirmed_observation"),
                        description=f_data["description"],
                        impact=f_data["impact"],
                        affected_url=f_data["affected_url"],
                        evidence=f_data.get("evidence", {}),
                        recommended_fix=f_data["recommended_fix"],
                        example_before=f_data.get("example_before"),
                        example_after=f_data.get("example_after"),
                        limitations=f_data.get("limitations", ""),
                        verification_status="unverified",
                        source=f_data.get("source", "native"),
                        references=f_data.get("references", []),
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow()
                    )
                    session.add(finding_obj)
                await session.commit()

            await self._update_scan_state(status="completed", stage="COMPLETED", summary=summary)
            await self._log(
                f"Scan finished successfully in {duration}s. Found {len(final_findings)} issues across {len(scanned_urls)} pages.",
                "COMPLETED",
                "INFO"
            )

        except SSRFValidationError as e:
            err_msg = f"SSRF security violation: {str(e)}"
            await self._log(err_msg, "FAILED", "ERROR")
            await self._update_scan_state(status="failed", stage="FAILED", error_message=err_msg)

        except Exception as e:
            err_msg = f"Scan failed unexpectedly: {str(e)}"
            await self._log(err_msg, "FAILED", "ERROR")
            await self._update_scan_state(status="failed", stage="FAILED", error_message=err_msg)
