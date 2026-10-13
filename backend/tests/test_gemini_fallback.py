import pytest
from app.services.gemini_service import get_fallback_explanation, answer_security_question


def test_deterministic_fallback_explanation():
    res = get_fallback_explanation(
        title="Missing Content-Security-Policy (CSP)",
        description="CSP header is missing.",
        impact="XSS exposure"
    )
    assert "Content-Security-Policy" in res["explanation"]
    assert "XSS" in res["why_it_matters"]
    assert "default-src" in res["fix_advice"]


@pytest.mark.asyncio
async def test_chat_without_gemini_api_key():
    # Without an API key, chat returns robust deterministic fallback
    ans = await answer_security_question(
        question="How do I fix this CSP issue?",
        scan_target="http://example.com",
        stored_findings=[],
        focused_finding={
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "Medium",
            "owasp_category": "A02:2025 Security Misconfiguration",
            "description": "CSP is missing",
            "impact": "XSS vulnerability risk",
            "affected_url": "http://example.com",
            "evidence": {},
            "recommended_fix": "Add Content-Security-Policy header",
            "example_before": "None",
            "example_after": "Content-Security-Policy: default-src 'self'"
        }
    )

    assert ans["source"] == "deterministic_fallback"
    assert "Missing Content-Security-Policy" in ans["answer"]
    assert len(ans["suggested_questions"]) > 0

