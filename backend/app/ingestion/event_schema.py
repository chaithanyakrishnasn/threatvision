"""
Unified event schema shared by the generator, normalizer, and pipeline.
Every event in ThreatVision — whether synthetic or ingested — must conform to this model.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class NormalizedEvent(BaseModel):
    """Canonical event representation used throughout the ingestion pipeline."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    layer: str = "network"          # "network" | "endpoint" | "application"

    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    source_port: int = 0
    dest_port: int = 0
    protocol: str = "UNKNOWN"
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration_ms: int = 0

    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    user: Optional[str] = None

    http_method: Optional[str] = None
    http_endpoint: Optional[str] = None
    http_status: Optional[int] = None
    user_agent: Optional[str] = None

    geo_country: Optional[str] = None

    flags: list[str] = Field(default_factory=list)
    scenario: Optional[str] = None  # "brute_force"|"c2_beacon"|"false_positive"|"lateral_movement"|"benign"

    severity: str = "LOW"           # "LOW"|"MEDIUM"|"HIGH"|"CRITICAL"
    confidence: float = 0.0

    raw_payload: dict = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def _upper_severity(cls, v: str) -> str:
        return v.upper()

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))
