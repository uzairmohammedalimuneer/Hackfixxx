from datetime import datetime
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, HttpUrl


SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]
ConfidenceLevel = Literal["Confirmed", "High", "Medium", "Low"]
EvidenceStatus = Literal["confirmed_observation", "suspected_vulnerability", "manual_review_required"]
VerificationStatus = Literal["unverified", "verified_fixed", "still_present", "inconclusive", "not_supported"]
ScanStage = Literal["QUEUED", "FIND", "PROVE", "FIX", "VERIFY", "COMPLETED", "FAILED"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
CoverageStatus = Literal["findings_present", "no_findings_detected", "assessment_limited", "not_assessed"]


class OwaspCategoryCoverage(BaseModel):
    category_id: str
    category_name: str
    status: CoverageStatus
    finding_count: int = 0
    limitation_note: str


class ScanCreateRequest(BaseModel):
    target_url: str = Field(..., description="Target website URL starting with http:// or https://")
    authorization_acknowledged: bool = Field(
        ...,
        description="Explicit user acknowledgement of authorization to scan the target website"
    )
    crawl_depth: Optional[int] = Field(default=2, ge=1, le=3)
    max_pages: Optional[int] = Field(default=15, ge=1, le=25)


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    owasp_category: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    evidence_status: EvidenceStatus
    description: str
    impact: str
    affected_url: str
    evidence: Dict[str, Any]
    recommended_fix: str
    example_before: Optional[str] = None
    example_after: Optional[str] = None
    limitations: str
    verification_status: VerificationStatus
    source: str
    references: List[str] = []
    first_seen: datetime
    last_seen: datetime


class ScanLogResponse(BaseModel):
    id: int
    timestamp: datetime
    stage: str
    level: str
    message: str


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    pages_scanned: int = 0
    duration_seconds: float = 0.0
    owasp_coverage: Dict[str, OwaspCategoryCoverage] = {}


class ScanDetailResponse(BaseModel):
    id: str
    target_url: str
    authorization_acknowledged: bool
    status: ScanStatus
    stage: ScanStage
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    summary: ScanSummary
    findings: List[FindingResponse] = []
    logs: List[ScanLogResponse] = []


class ScanListItemResponse(BaseModel):
    id: str
    target_url: str
    status: ScanStatus
    stage: ScanStage
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

