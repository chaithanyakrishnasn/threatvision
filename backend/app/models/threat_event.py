from sqlalchemy import String, Text, Float, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, UUIDMixin, TimestampMixin


class ThreatEvent(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "threat_events"

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)  # network/endpoint/app/auth
    source: Mapped[str] = mapped_column(String(100), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    username: Mapped[str] = mapped_column(String(100), nullable=True)
    process_name: Mapped[str] = mapped_column(String(255), nullable=True)
    command_line: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="low")
    category: Mapped[str] = mapped_column(String(100), nullable=True)
    mitre_tactic: Mapped[str] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[str] = mapped_column(String(50), nullable=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(default=False)
    raw_log: Mapped[dict] = mapped_column(JSON, default=dict)
    enriched: Mapped[bool] = mapped_column(default=False)
    # Classification output fields
    threat_type: Mapped[str] = mapped_column(String(50), nullable=True)          # brute_force | c2_beacon | lateral_movement | data_exfiltration | benign | false_positive
    confidence: Mapped[float] = mapped_column(Float, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=True)
    cross_layer_correlated: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_matches: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)            # full technique list from classifier
