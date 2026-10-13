from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.scan import Scan
from app.services.report_service import generate_pdf_report, generate_html_report

router = APIRouter()


async def _get_scan_data(scan_id: str, db: AsyncSession) -> dict:
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings_list = [
        {
            "id": f.id,
            "title": f.title,
            "owasp_category": f.owasp_category,
            "severity": f.severity,
            "confidence": f.confidence,
            "evidence_status": f.evidence_status,
            "description": f.description,
            "impact": f.impact,
            "affected_url": f.affected_url,
            "evidence": f.evidence,
            "recommended_fix": f.recommended_fix,
            "example_before": f.example_before,
            "example_after": f.example_after,
            "limitations": f.limitations,
            "verification_status": f.verification_status,
            "source": f.source
        }
        for f in scan.findings
    ]

    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.created_at else "",
        "summary": scan.summary or {},
        "findings": findings_list
    }


@router.get("/report/{scan_id}/pdf")
async def download_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan_data = await _get_scan_data(scan_id, db)
    try:
        pdf_bytes = generate_pdf_report(scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=hackfix-report-{scan_id[:8]}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF report generation failed: {str(e)}")


@router.get("/report/{scan_id}/html", response_class=HTMLResponse)
async def preview_html_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan_data = await _get_scan_data(scan_id, db)
    html_content = generate_html_report(scan_data)
    return HTMLResponse(content=html_content)


@router.get("/report/{scan_id}/json")
async def export_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    return await _get_scan_data(scan_id, db)

