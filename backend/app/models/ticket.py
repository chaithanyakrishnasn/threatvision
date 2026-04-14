from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import String, Text, Float, Integer, Boolean, DateTime, JSON, ForeignKey, Sequence as SASequence
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, UUIDMixin, TimestampMixin

if TYPE_CHECKING:
    from .analyst import Analyst
    from .ticket_activity import TicketActivity

# PostgreSQL sequence for human-readable ticket number (TICK-0001)
_ticket_num_seq = SASequence("ticket_number_seq", start=1)


class Ticket(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "tickets"

    ticket_number: Mapped[int] = mapped_column(
        Integer,
        _ticket_num_seq,
        server_default=_ticket_num_seq.next_value(),
        unique=True,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)   # CRITICAL|HIGH|MEDIUM|LOW
    status: Mapped[str] = mapped_column(String(30), default="open")
    # open|acknowledged|in_progress|patch_attempted|resolved|verified|closed|escalated
    ticket_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # web|network|llm|cloud|api|malware|other

    # ── Assignment ────────────────────────────────────────────────────────────
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    assigned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    escalated_from: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysts.id", ondelete="SET NULL"),
        nullable=True,
    )
    escalation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    escalation_count: Mapped[int] = mapped_column(Integer, default=0)

    # ── SLA ───────────────────────────────────────────────────────────────────
    sla_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Source ────────────────────────────────────────────────────────────────
    source_type: Mapped[str] = mapped_column(String(30), default="manual")
    # agent_detected|manual|simulation
    source_event_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # ── Agent context ─────────────────────────────────────────────────────────
    agent_attempts: Mapped[int] = mapped_column(Integer, default=0)
    agent_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    agent_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string

    # ── Resolution ────────────────────────────────────────────────────────────
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    # agent_patched|analyst_fixed|false_positive|accepted_risk|wont_fix

    # ── Relationships ─────────────────────────────────────────────────────────
    assigned_analyst: Mapped[Optional["Analyst"]] = relationship(
        "Analyst",
        foreign_keys=[assigned_to],
        lazy="selectin",
    )
    activities: Mapped[list["TicketActivity"]] = relationship(
        "TicketActivity",
        back_populates="ticket",
        lazy="noload",
        order_by="TicketActivity.created_at",
    )

    @property
    def assigned_analyst_name(self) -> Optional[str]:
        return self.assigned_analyst.name if self.assigned_analyst else None

    @property
    def ticket_display_id(self) -> str:
        return f"TICK-{self.ticket_number:04d}"
