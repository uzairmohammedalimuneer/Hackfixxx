from typing import Optional, List
from pydantic import BaseModel, Field


class ChatMessageRequest(BaseModel):
    scan_id: str = Field(..., description="Scan ID for server-side trusted context retrieval")
    finding_id: Optional[str] = Field(None, description="Optional finding ID to focus on")
    question: str = Field(..., min_length=2, max_length=2000, description="User's security or remediation question")


class ChatMessageResponse(BaseModel):
    answer: str
    source: str = Field(..., description="'gemini' or 'deterministic_fallback'")
    model_used: Optional[str] = None
    suggested_questions: List[str] = []
    finding_id: Optional[str] = None

