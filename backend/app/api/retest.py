from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.schemas.retest import RetestRequest, RetestResponse
from app.services.retest_service import execute_retest

router = APIRouter()


@router.post("/retest", response_model=RetestResponse)
async def retest_finding(
    request: RetestRequest,
    db: AsyncSession = Depends(get_db)
):
    try:
        result = await execute_retest(request.finding_id, db)
        return RetestResponse(
            id=result["id"],
            scan_id=result["scan_id"],
            finding_id=result["finding_id"],
            status=result["status"],
            timestamp=result["timestamp"],
            previous_evidence=result["previous_evidence"],
            new_evidence=result["new_evidence"],
            details=result["details"]
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retest failed: {str(e)}")

