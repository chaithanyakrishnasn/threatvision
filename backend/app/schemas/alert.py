import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AlertBase(BaseModel):
    rule_name: str
    description: Optional[str] = None
    severity: str = "medium"
    source: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    confidence: float = 0.0
    raw_data: dict = {}
    mitre_technique: Optional[str] = None


class AlertCreate(AlertBase):
    incident_id: Optional[uuid.UUID] = None


class AlertUpdate(BaseModel):
    severity: Optional[str] = None
    false_positive: Optional[bool] = None
    incident_id: Optional[uuid.UUID] = None


class AlertRead(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: Optional[uuid.UUID] = None
    false_positive: bool = False
    created_at: datetime
    updated_at: datetime
