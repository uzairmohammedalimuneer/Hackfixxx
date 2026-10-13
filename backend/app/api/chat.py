from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.scan import Scan, Finding
from app.schemas.chat import ChatMessageRequest, ChatMessageResponse
from app.services.gemini_service import answer_security_question

router = APIRouter()


@router.post("/chat", response_model=ChatMessageResponse)
async def chat_with_security_assistant(
    request: ChatMessageRequest,
    db: AsyncSession = Depends(get_db)
):
    # Retrieve trusted scan record
    scan_res = await db.execute(select(Scan).where(Scan.id == request.scan_id))
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{request.scan_id}' not found.")

    # Retrieve all findings for this scan
    findings_res = await db.execute(select(Finding).where(Finding.scan_id == request.scan_id))
    findings = findings_res.scalars().all()
    findings_dicts = [
        {
            "id": f.id,
            "title": f.title,
            "owasp_category": f.owasp_category,
            "severity": f.severity,
            "description": f.description,
            "impact": f.impact,
            "affected_url": f.affected_url,
            "evidence": f.evidence,
            "recommended_fix": f.recommended_fix,
            "example_before": f.example_before,
            "example_after": f.example_after
        }
        for f in findings
    ]

    focused_dict = None
    if request.finding_id:
        match = next((f for f in findings_dicts if f["id"] == request.finding_id), None)
        if match:
            focused_dict = match

    result = await answer_security_question(
        question=request.question,
        scan_target=scan.target_url,
        stored_findings=findings_dicts,
        focused_finding=focused_dict
    )

    return ChatMessageResponse(
        answer=result["answer"],
        source=result["source"],
        model_used=result.get("model_used"),
        suggested_questions=result.get("suggested_questions", []),
        finding_id=request.finding_id
    )

