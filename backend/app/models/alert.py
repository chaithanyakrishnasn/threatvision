import uuid
from sqlalchemy import String, Text, Float, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from .base import Base, UUIDMixin, TimestampMixin


class Alert(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True
    )
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(100), nullable=True)  # ids/firewall/edr/siem
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=True)
    port: Mapped[int] = mapped_column(nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive: Mapped[bool] = mapped_column(default=False)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre_technique: Mapped[str] = mapped_column(String(50), nullable=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="alerts")  # type: ignore
