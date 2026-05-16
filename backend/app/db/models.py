from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class CaseRecord(Base):
    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_status_updated_at", "status", "updated_at"),
        Index("ix_cases_severity_updated_at", "severity", "updated_at"),
    )

    case_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    category: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    priority: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    raw_alert: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    case_file: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseCheckpointRecord(Base):
    __tablename__ = "case_checkpoints"
    __table_args__ = (
        Index("ix_case_checkpoints_case_id_id", "case_id", "id"),
        Index("ix_case_checkpoints_case_id_node_name", "case_id", "node_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(
        String(80),
        ForeignKey("cases.case_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_name: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    case_file: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
