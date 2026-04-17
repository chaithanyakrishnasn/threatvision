"""
AuditLog — immutable hash-chained audit record.

Every actor action (agent decision, human ticket update, system classification,
API call) is written here. Each row links to its predecessor via SHA-256 hash
chain, making the log tamper-evident.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Text, Float, Integer, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin


class AuditLog(UUIDMixin, Base):
    __tablename__ = "audit_logs"

    # ── When ─────────────────────────────────────────────────────────────────
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Who ──────────────────────────────────────────────────────────────────
    # actor_type: "agent" | "human" | "system"
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)

    # ── What ─────────────────────────────────────────────────────────────────
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(300), nullable=True, index=True)

    # ── Outcome ───────────────────────────────────────────────────────────────
    # result: "success" | "failed" | "escalated"
    result: Mapped[str] = mapped_column(String(20), nullable=False, default="success", index=True)

    # ── Context ───────────────────────────────────────────────────────────────
    # Full agent reasoning — no truncation
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # JSONB blob: bytes_sent, IPs, rule matches, threat type, etc.
    log_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSONB, nullable=True
    )

    # ── Hash chain (tamper-evident) ───────────────────────────────────────────
    # First entry uses "GENESIS" as previous_hash
    previous_hash: Mapped[str] = mapped_column(Text, nullable=False)
    current_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Compound indexes for efficient API filtering ──────────────────────────
    __table_args__ = (
        Index("ix_audit_logs_actor_type_action", "actor_type", "action"),
        Index("ix_audit_logs_timestamp_result", "timestamp", "result"),
    )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "result": self.result,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "duration_ms": self.duration_ms,
            "metadata": self.log_metadata,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
