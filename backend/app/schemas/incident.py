import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from .alert import AlertRead


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    status: str = "open"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    confidence: float = 0.0
    tags: list[str] = []


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    ai_analysis: Optional[str] = None
    confidence: Optional[float] = None
    tags: Optional[list[str]] = None


class IncidentRead(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ai_analysis: Optional[str] = None
    playbook_id: Optional[str] = None
    raw_events: list = []
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertRead] = []
    # Classification output fields
    threat_type: Optional[str] = None
    is_false_positive: bool = False
    explanation: Optional[str] = None
    recommended_action: Optional[str] = None
    rule_matches: list = []
    cross_layer_correlated: bool = False
    anomaly_score: float = 0.0

    @property
    def timestamp(self) -> datetime:
        return self.created_at
