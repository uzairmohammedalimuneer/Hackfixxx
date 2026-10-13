import shutil
import asyncio
import json
import os
import tempfile
from typing import List, Dict, Any, Tuple
from app.core.config import settings


class ZapIntegrationResult:
    def __init__(
        self,
        ran: bool,
        findings: List[Dict[str, Any]],
        message: str
    ):
        self.ran = ran
        self.findings = findings
        self.message = message


def check_zap_availability() -> Tuple[bool, str]:
    """Inspect if ZAP baseline script or Docker is installed on the host."""
    if not settings.ZAP_ENABLED:
        return False, "OWASP ZAP integration is disabled in configuration (ZAP_ENABLED=false)."

    if settings.ZAP_USE_DOCKER:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False, "Docker executable not found on PATH for ZAP container execution."
        return True, "Docker available for ZAP Baseline container."
    else:
        zap_bin = shutil.which(settings.ZAP_PATH)
        if not zap_bin:
            return False, f"ZAP script '{settings.ZAP_PATH}' not found on PATH."
        return True, f"ZAP script found at {zap_bin}."


def normalize_zap_alert(alert: dict, target_url: str) -> Dict[str, Any]:
    """Map a genuine ZAP JSON alert into HACKFIX AI finding schema."""
    risk = alert.get("riskcode", "1")
    confidence_code = alert.get("confidence", "2")

    # Map risk codes (0: Informational, 1: Low, 2: Medium, 3: High)
    severity_map = {
        "3": "High",
        "2": "Medium",
        "1": "Low",
        "0": "Informational"
    }
    confidence_map = {
        "3": "High",
        "2": "Medium",
        "1": "Low",
        "0": "Low"
    }

    severity = severity_map.get(str(risk), "Low")
    confidence = confidence_map.get(str(confidence_code), "Medium")

    # OWASP mapping from CWE/WASC or name
    cwe_id = alert.get("cweid", "")
    owasp_cat = "A02:2025 Security Misconfiguration"
    if cwe_id in ("89", "79", "77"):
        owasp_cat = "A05:2025 Injection"
    elif cwe_id in ("319", "311", "327"):
        owasp_cat = "A04:2025 Cryptographic Failures"
    elif cwe_id in ("200", "209"):
        owasp_cat = "A10:2025 Mishandling of Exceptional Conditions"

    return {
        "title": f"[ZAP] {alert.get('alert', 'Passive Alert')}",
        "owasp_category": owasp_cat,
        "severity": severity,
        "confidence": confidence,
        "evidence_status": "confirmed_observation",
        "description": alert.get("description", "Detected by OWASP ZAP passive baseline scanner."),
        "impact": "Potential security impact identified through passive HTTP inspection.",
        "affected_url": alert.get("url", target_url),
        "evidence": {
            "zap_plugin_id": alert.get("pluginid"),
            "cwe_id": cwe_id,
            "wasc_id": alert.get("wascid"),
            "param": alert.get("param", ""),
            "evidence_snippet": alert.get("evidence", "")[:200]
        },
        "recommended_fix": alert.get("solution", "Review the finding details and apply recommended remediation."),
        "example_before": None,
        "example_after": None,
        "limitations": "Passive analysis alert; verification should be conducted in accordance with application logic.",
        "source": "owasp_zap",
        "references": alert.get("reference", "").split("\n") if alert.get("reference") else []
    }


async def run_zap_baseline_if_enabled(target_url: str) -> ZapIntegrationResult:
    """
    Executes OWASP ZAP Baseline in passive mode if enabled and installed.
    Never fabricates alerts.
    """
    is_available, status_msg = check_zap_availability()
    if not is_available:
        return ZapIntegrationResult(ran=False, findings=[], message=status_msg)

    # If available, execute with bounded timeout
    with tempfile.TemporaryDirectory() as tmpdir:
        report_json_path = os.path.join(tmpdir, "zap_report.json")
        try:
            if settings.ZAP_USE_DOCKER:
                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{tmpdir}:/zap/wrk:rw",
                    "-t", settings.ZAP_DOCKER_IMAGE,
                    "zap-baseline.py",
                    "-t", target_url,
                    "-J", "zap_report.json",
                    "-m", "2"  # 2 minute timeout
                ]
            else:
                cmd = [
                    settings.ZAP_PATH,
                    "-t", target_url,
                    "-J", report_json_path,
                    "-m", "2"
                ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120.0)
            except asyncio.TimeoutError:
                process.kill()
                return ZapIntegrationResult(
                    ran=False,
                    findings=[],
                    message="OWASP ZAP baseline scan exceeded 120s timeout."
                )

            # Check if structured report was generated
            if os.path.exists(report_json_path):
                with open(report_json_path, "r", encoding="utf-8") as f:
                    zap_data = json.load(f)

                site_alerts = zap_data.get("site", [])
                raw_alerts = []
                for site in site_alerts:
                    raw_alerts.extend(site.get("alerts", []))

                normalized = [normalize_zap_alert(a, target_url) for a in raw_alerts]
                return ZapIntegrationResult(
                    ran=True,
                    findings=normalized,
                    message=f"OWASP ZAP completed successfully ({len(normalized)} alerts detected)."
                )

            return ZapIntegrationResult(
                ran=False,
                findings=[],
                message="OWASP ZAP process completed but did not produce a JSON report."
            )

        except Exception as e:
            return ZapIntegrationResult(
                ran=False,
                findings=[],
                message=f"OWASP ZAP execution encountered an error: {str(e)}"
            )

