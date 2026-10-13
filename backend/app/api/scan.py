from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db, AsyncSessionLocal
from app.models.scan import Scan, Finding, ScanLog
from app.schemas.scan import ScanCreateRequest, ScanDetailResponse
from app.scanner.ssrf_validator import validate_url_safety
from app.scanner.engine import ScanOrchestrator

router = APIRouter()


async def run_scan_orchestrator_task(scan_id: str):
    orchestrator = ScanOrchestrator(scan_id, AsyncSessionLocal)
    await orchestrator.execute_scan()


@router.post("/scan")
async def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    if not request.authorization_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Scanning unauthorized targets is prohibited. You must explicitly acknowledge authorization."
        )

    # Validate URL safety and SSRF
    is_safe, norm_url, ssrf_err = validate_url_safety(request.target_url)
    if not is_safe:
        raise HTTPException(
            status_code=400,
            detail=f"Target URL security validation failed: {ssrf_err}"
        )

    # Create scan record in database
    new_scan = Scan(
        target_url=norm_url,
        authorization_acknowledged=True,
        status="queued",
        stage="QUEUED",
        created_at=datetime.utcnow(),
        scan_options={
            "max_pages": request.max_pages,
            "crawl_depth": request.crawl_depth
        },
        summary={
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "pages_scanned": 0,
            "duration_seconds": 0.0,
            "owasp_coverage": {}
        }
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # Launch background task
    background_tasks.add_task(run_scan_orchestrator_task, new_scan.id)

    return {
        "id": new_scan.id,
        "target_url": new_scan.target_url,
        "status": new_scan.status,
        "stage": new_scan.stage,
        "created_at": new_scan.created_at,
        "message": "Security scan queued and executing in background."
    }


@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    return scan

