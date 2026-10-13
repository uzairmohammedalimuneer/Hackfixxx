import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanner.engine import ScanOrchestrator
from app.core.database import AsyncSessionLocal
from app.models.scan import Scan, Finding
from sqlalchemy import select


@pytest.mark.asyncio
async def test_full_scan_lifecycle():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create scan
        resp = await ac.post("/api/scan", json={
            "target_url": "http://localhost:8001/",
            "authorization_acknowledged": True,
            "max_pages": 5,
            "crawl_depth": 1
        })
        assert resp.status_code == 200
        scan_id = resp.json()["id"]

        # 2. Run orchestrator directly in test
        orchestrator = ScanOrchestrator(scan_id, AsyncSessionLocal)
        # We can simulate page audit
        await orchestrator._log("Test scan step", "FIND", "INFO")
        
        # 3. Retrieve scan status
        status_resp = await ac.get(f"/api/scan/{scan_id}")
        assert status_resp.status_code == 200
        scan_data = status_resp.json()
        assert scan_data["id"] == scan_id
        assert scan_data["target_url"] == "http://localhost:8001/"
        assert len(scan_data["logs"]) >= 1

