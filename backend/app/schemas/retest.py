from datetime import datetime
from typing import Dict, Any, Literal
from pydantic import BaseModel, Field


VerificationStatus = Literal["unverified", "verified_fixed", "still_present", "inconclusive", "not_supported"]


class RetestRequest(BaseModel):
    finding_id: str = Field(..., description="ID of the finding to retest")


class RetestResponse(BaseModel):
    id: str
    scan_id: str
    finding_id: str
    status: VerificationStatus
    timestamp: datetime
    previous_evidence: Dict[str, Any]
    new_evidence: Dict[str, Any]
    details: str

