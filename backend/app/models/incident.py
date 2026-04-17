from sqlalchemy import String, Text, Float, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, UUIDMixin, TimestampMixin


class Incident(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # critical/high/medium/low
    status: Mapped[str] = mapped_column(String(30), default="open")  # open/investigating/contained/resolved
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    ai_analysis: Mapped[str] = mapped_column(Text, nullable=True)
    playbook_id: Mapped[str] = mapped_column(String(100), nullable=True)
    raw_events: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    # Classification output fields
    threat_type: Mapped[str] = mapped_column(String(50), nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=True)
    rule_matches: Mapped[list] = mapped_column(JSON, default=list)
    cross_layer_correlated: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    bytes_sent: Mapped[int] = mapped_column(default=0)

    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="incident", lazy="selectin")  # type: ignore
