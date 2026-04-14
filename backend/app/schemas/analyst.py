from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field


class AnalystCreate(BaseModel):
    name: str
    email: str
    tier: int = Field(ge=1, le=3)
    skills: list[str]
    availability: str = "online"
    max_tickets: Optional[int] = None  # auto-set from tier if omitted


class AnalystUpdate(BaseModel):
    name: Optional[str] = None
    availability: Optional[str] = None
    skills: Optional[list[str]] = None
    is_active: Optional[bool] = None
    max_tickets: Optional[int] = None


class AnalystAvailabilityUpdate(BaseModel):
    availability: str = Field(pattern="^(online|busy|offline)$")


class AnalystRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    email: str
    tier: int
    skills: list[str]
    availability: str
    max_tickets: int
    current_ticket_count: int
    avg_resolution_hours: float
    total_resolved: int
    success_rate: float
    is_active: bool
    created_at: datetime

    @computed_field  # type: ignore[misc]
    @property
    def workload_percentage(self) -> float:
        if self.max_tickets == 0:
            return 0.0
        return round((self.current_ticket_count / self.max_tickets) * 100, 1)

    # Allow id to come in as uuid.UUID and be returned as str
    @classmethod
    def from_orm_model(cls, obj) -> "AnalystRead":
        data = {
            "id": str(obj.id),
            "name": obj.name,
            "email": obj.email,
            "tier": obj.tier,
            "skills": obj.skills or [],
            "availability": obj.availability,
            "max_tickets": obj.max_tickets,
            "current_ticket_count": obj.current_ticket_count,
            "avg_resolution_hours": obj.avg_resolution_hours,
            "total_resolved": obj.total_resolved,
            "success_rate": obj.success_rate,
            "is_active": obj.is_active,
            "created_at": obj.created_at,
        }
        return cls.model_validate(data)


class AnalystLeaderboard(BaseModel):
    analyst: AnalystRead
    rank: int
    tickets_this_week: int
    avg_resolution_hours_this_week: float
    sla_compliance_rate: float
