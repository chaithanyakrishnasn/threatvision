from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ProjectCreate(BaseModel):
    name: str
    description: str = ""
    target_url: Optional[str] = None
    target_ip: Optional[str] = None
    tech_stack: list[str] = []
    risk_tier: str = "medium"
    owner_name: str
    assigned_analysts: list[str] = []


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_url: Optional[str] = None
    target_ip: Optional[str] = None
    tech_stack: Optional[list[str]] = None
    risk_tier: Optional[str] = None
    status: Optional[str] = None
    owner_name: Optional[str] = None
    assigned_analysts: Optional[list[str]] = None


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    target_url: Optional[str]
    target_ip: Optional[str]
    tech_stack: list[str]
    risk_tier: str
    status: str
    owner_name: str
    assigned_analysts: list[str]
    open_tickets: int
    critical_tickets: int
    resolved_tickets: int
    security_score: int
    created_at: datetime
    updated_at: datetime
    last_scan_at: Optional[datetime]

    @classmethod
    def from_orm_model(cls, obj) -> "ProjectRead":
        return cls.model_validate({
            "id": str(obj.id),
            "name": obj.name,
            "description": obj.description,
            "target_url": obj.target_url,
            "target_ip": obj.target_ip,
            "tech_stack": obj.tech_stack or [],
            "risk_tier": obj.risk_tier,
            "status": obj.status,
            "owner_name": obj.owner_name,
            "assigned_analysts": obj.assigned_analysts or [],
            "open_tickets": obj.open_tickets,
            "critical_tickets": obj.critical_tickets,
            "resolved_tickets": obj.resolved_tickets,
            "security_score": obj.security_score,
            "created_at": obj.created_at,
            "updated_at": obj.updated_at,
            "last_scan_at": obj.last_scan_at,
        })


class SecurityScoreBreakdown(BaseModel):
    overall_score: int
    open_critical: int
    open_high: int
    sla_breaches: int
    resolved_this_week: int
    breakdown: dict[str, int]
