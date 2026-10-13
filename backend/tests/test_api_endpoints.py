import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "HACKFIX AI"
    assert "capabilities" in data
    assert data["capabilities"]["scanner_engine"] == "native_python"


@pytest.mark.asyncio
async def test_scan_unauthorized_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/scan", json={
            "target_url": "http://localhost:8001/",
            "authorization_acknowledged": False
        })
    assert response.status_code == 400
    assert "authorization" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_scan_invalid_scheme_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/scan", json={
            "target_url": "ftp://localhost:8001/file",
            "authorization_acknowledged": True
        })
    assert response.status_code == 400
    assert "validation failed" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_history_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

