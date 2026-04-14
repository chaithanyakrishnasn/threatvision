from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, computed_field


class TicketActivityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ticket_id: str
    actor_type: str
    actor_id: str
    actor_name: str
    action: str
    old_value: Optional[str]
    new_value: Optional[str]
    comment: Optional[str]
    created_at: datetime

    @classmethod
    def from_orm_model(cls, obj) -> "TicketActivityRead":
        return cls.model_validate({
            "id": str(obj.id),
            "ticket_id": str(obj.ticket_id),
            "actor_type": obj.actor_type,
            "actor_id": str(obj.actor_id),
            "actor_name": obj.actor_name,
            "action": obj.action,
            "old_value": obj.old_value,
            "new_value": obj.new_value,
            "comment": obj.comment,
            "created_at": obj.created_at,
        })


class TicketCreate(BaseModel):
    title: str
    description: str = ""
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW
    ticket_type: str  # web|network|llm|cloud|api|malware|other
    source_type: str = "manual"
    source_event_id: Optional[str] = None
    incident_id: Optional[str] = None
    agent_confidence: Optional[float] = None
    agent_notes: Optional[str] = None


class TicketUpdate(BaseModel):
    status: Optional[str] = None
    resolution_notes: Optional[str] = None
    resolution_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


class TicketAssign(BaseModel):
    analyst_id: str


class TicketAcknowledge(BaseModel):
    analyst_id: str


class TicketResolve(BaseModel):
    analyst_id: str
    resolution_notes: str
    resolution_type: str  # agent_patched|analyst_fixed|false_positive|accepted_risk|wont_fix


class TicketEscalate(BaseModel):
    reason: str


class TicketComment(BaseModel):
    comment: str
    actor_name: str = "Analyst"
    actor_type: str = "analyst"
    actor_id: str = "system"


class TicketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ticket_number: int
    ticket_display_id: str  # TICK-0001 format
    title: str
    description: Optional[str]
    severity: str
    status: str
    ticket_type: str
    assigned_to: Optional[str]
    assigned_analyst_name: Optional[str] = None
    sla_deadline: datetime
    sla_breached: bool
    sla_hours_remaining: float
    escalation_count: int
    agent_attempts: int
    agent_confidence: Optional[float]
    agent_notes: Optional[str]
    source_type: str
    incident_id: Optional[str]
    resolution_notes: Optional[str]
    resolution_type: Optional[str]
    created_at: datetime
    updated_at: datetime
    activities: list[TicketActivityRead] = []

    @classmethod
    def from_orm_model(
        cls,
        obj,
        activities: Optional[list] = None,
    ) -> "TicketRead":
        now = datetime.now(timezone.utc)
        deadline = obj.sla_deadline
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        hours_remaining = (deadline - now).total_seconds() / 3600

        acts = []
        if activities is not None:
            acts = [TicketActivityRead.from_orm_model(a) for a in activities]

        return cls.model_validate({
            "id": str(obj.id),
            "ticket_number": obj.ticket_number,
            "ticket_display_id": f"TICK-{obj.ticket_number:04d}",
            "title": obj.title,
            "description": obj.description,
            "severity": obj.severity,
            "status": obj.status,
            "ticket_type": obj.ticket_type,
            "assigned_to": str(obj.assigned_to) if obj.assigned_to else None,
            "assigned_analyst_name": obj.assigned_analyst_name,
            "sla_deadline": obj.sla_deadline,
            "sla_breached": obj.sla_breached,
            "sla_hours_remaining": round(hours_remaining, 2),
            "escalation_count": obj.escalation_count,
            "agent_attempts": obj.agent_attempts,
            "agent_confidence": obj.agent_confidence,
            "agent_notes": obj.agent_notes,
            "source_type": obj.source_type,
            "incident_id": obj.incident_id,
            "resolution_notes": obj.resolution_notes,
            "resolution_type": obj.resolution_type,
            "created_at": obj.created_at,
            "updated_at": obj.updated_at,
            "activities": acts,
        })


class TicketStats(BaseModel):
    total: int
    open: int
    acknowledged: int
    in_progress: int
    resolved: int
    closed: int
    sla_breached: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
