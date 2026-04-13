import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class ThreatEventCreate(BaseModel):
    event_type: str
    source: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    severity: str = "low"
    category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    raw_log: dict = {}


class ThreatEventRead(ThreatEventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    enriched: bool = False
    created_at: datetime
    updated_at: datetime
