from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "HACKFIX AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./hackfix.db"
    
    # Gemini AI Configuration
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GEMINI_ENABLED: bool = True
    
    # OWASP ZAP Baseline Scanner (disabled by default)
    ZAP_ENABLED: bool = False
    ZAP_PATH: str = "zap-baseline.py"
    ZAP_DOCKER_IMAGE: str = "zaproxy/zap-baseline:latest"
    ZAP_USE_DOCKER: bool = False
    
    # Frontend CORS
    FRONTEND_ORIGIN: str = "http://localhost:3000"
    ADDITIONAL_ALLOWED_ORIGINS: List[str] = ["http://127.0.0.1:3000"]
    
    # SSRF / Outbound Scanning Controls
    # Local development targets explicitly permitted (never open to arbitrary internal IPs by default)
    SCAN_ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "::1", "testserver"]
    ALLOW_PRIVATE_IPS_IN_DEV: bool = False
    
    # Crawler and HTTP Safety Boundaries
    MAX_CRAWL_PAGES: int = 25
    MAX_CRAWL_DEPTH: int = 2
    REQUEST_TIMEOUT_SECONDS: float = 10.0
    SCAN_DEADLINE_SECONDS: float = 120.0
    MAX_RESPONSE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2MB max response
    MAX_CONCURRENT_REQUESTS: int = 4
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

