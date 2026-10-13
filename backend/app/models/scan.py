import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import String, Boolean, DateTime, Text, JSON, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    authorization_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="queued")  # queued, running, completed, failed, cancelled
    stage: Mapped[str] = mapped_column(String(32), default="QUEUED")  # QUEUED, FIND, PROVE, FIX, VERIFY, COMPLETED
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    scan_options: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    logs: Mapped[List["ScanLog"]] = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan", lazy="selectin", order_by="ScanLog.id")
    retests: Mapped[List["RetestHistory"]] = relationship("RetestHistory", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    owasp_category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)  # Critical, High, Medium, Low, Informational
    confidence: Mapped[str] = mapped_column(String(32), default="High")  # Confirmed, High, Medium, Low
    evidence_status: Mapped[str] = mapped_column(String(32), default="confirmed_observation")  # confirmed_observation, suspected_vulnerability, manual_review_required
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    affected_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    recommended_fix: Mapped[str] = mapped_column(Text, nullable=False)
    example_before: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    example_after: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    limitations: Mapped[str] = mapped_column(Text, default="")
    verification_status: Mapped[str] = mapped_column(String(32), default="unverified")  # unverified, verified_fixed, still_present, inconclusive, not_supported
    source: Mapped[str] = mapped_column(String(64), default="native")
    references: Mapped[List[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    retests: Mapped[List["RetestHistory"]] = relationship("RetestHistory", back_populates="finding", cascade="all, delete-orphan")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    stage: Mapped[str] = mapped_column(String(32), default="FIND")
    level: Mapped[str] = mapped_column(String(16), default="INFO")  # INFO, WARNING, ERROR
    message: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="logs")


class RetestHistory(Base):
    __tablename__ = "retest_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    previous_evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    new_evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # verified_fixed, still_present, inconclusive, not_supported
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    details: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="retests")
    finding: Mapped["Finding"] = relationship("Finding", back_populates="retests")

