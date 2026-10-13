from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.api import (
    health_router,
    scan_router,
    history_router,
    chat_router,
    retest_router,
    report_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    await init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="HACKFIX AI — Real Non-Destructive Website Security Scanner Engine",
    lifespan=lifespan
)

# Configure CORS for frontend origin
allowed_origins = [settings.FRONTEND_ORIGIN] + settings.ADDITIONAL_ALLOWED_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(scan_router, prefix="/api", tags=["Scans"])
app.include_router(history_router, prefix="/api", tags=["History"])
app.include_router(chat_router, prefix="/api", tags=["AI Chat"])
app.include_router(retest_router, prefix="/api", tags=["Retest"])
app.include_router(report_router, prefix="/api", tags=["Reports"])


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs_url": "/docs",
        "api_health": "/api/health"
    }

