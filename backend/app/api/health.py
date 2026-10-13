from fastapi import APIRouter
from app.core.config import settings
from app.scanner.modules.zap_integrator import check_zap_availability

router = APIRouter()


@router.get("/health")
async def health_check():
    zap_avail, zap_msg = check_zap_availability()
    gemini_ready = bool(settings.GEMINI_ENABLED and settings.GEMINI_API_KEY)

    return {
        "status": "ok",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "capabilities": {
            "scanner_engine": "native_python",
            "gemini_ai": {
                "enabled": settings.GEMINI_ENABLED,
                "configured": gemini_ready,
                "model": settings.GEMINI_MODEL,
                "fallback_available": True
            },
            "owasp_zap": {
                "enabled": settings.ZAP_ENABLED,
                "available": zap_avail,
                "message": zap_msg
            },
            "retesting": "supported",
            "pdf_reports": "supported",
            "ssrf_protection": "active"
        }
    }

