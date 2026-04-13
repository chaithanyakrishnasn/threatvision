import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class SimulationRunCreate(BaseModel):
    name: str
    scenario: str = "apt"  # apt/ransomware/insider/ddos
    red_agent_config: dict = {}
    blue_agent_config: dict = {}


class SimulationRunUpdate(BaseModel):
    status: Optional[str] = None
    events_generated: Optional[int] = None
    alerts_triggered: Optional[int] = None
    detection_rate: Optional[float] = None
    mean_time_to_detect: Optional[float] = None
    findings: Optional[str] = None
    recommendations: Optional[list] = None
    duration_seconds: Optional[float] = None


class SimulationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    scenario: str
    status: str
    red_agent_config: dict
    blue_agent_config: dict
    events_generated: int
    alerts_triggered: int
    detection_rate: float
    mean_time_to_detect: float
    red_agent_log: list
    blue_agent_log: list
    findings: Optional[str] = None
    recommendations: list
    duration_seconds: float
    created_at: datetime
    updated_at: datetime
