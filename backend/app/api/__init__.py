from app.api.health import router as health_router
from app.api.scan import router as scan_router
from app.api.history import router as history_router
from app.api.chat import router as chat_router
from app.api.retest import router as retest_router
from app.api.report import router as report_router

__all__ = [
    "health_router",
    "scan_router",
    "history_router",
    "chat_router",
    "retest_router",
    "report_router",
]

