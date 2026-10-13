from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, delete

from app.core.database import get_db
from app.models.scan import Scan
from app.schemas.scan import ScanListItemResponse

router = APIRouter()


@router.get("/history", response_model=List[ScanListItemResponse])
async def get_scan_history(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).order_by(desc(Scan.created_at)).limit(50)
    )
    scans = result.scalars().all()

    items = []
    for s in scans:
        summary = s.summary or {}
        items.append(
            ScanListItemResponse(
                id=s.id,
                target_url=s.target_url,
                status=s.status,
                stage=s.stage,
                created_at=s.created_at,
                completed_at=s.completed_at,
                total_findings=summary.get("total_findings", 0),
                critical_count=summary.get("critical_count", 0),
                high_count=summary.get("high_count", 0),
                medium_count=summary.get("medium_count", 0),
                low_count=summary.get("low_count", 0),
                info_count=summary.get("info_count", 0)
            )
        )
    return items


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    await db.delete(scan)
    await db.commit()
    return {"status": "deleted", "scan_id": scan_id}

