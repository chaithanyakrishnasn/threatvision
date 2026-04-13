from sqlalchemy import String, Text, Float, JSON, Integer
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, UUIDMixin, TimestampMixin


class SimulationRun(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "simulation_runs"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scenario: Mapped[str] = mapped_column(String(100), nullable=False)  # apt/ransomware/insider/ddos
    status: Mapped[str] = mapped_column(String(30), default="pending")  # pending/running/completed/failed
    red_agent_config: Mapped[dict] = mapped_column(JSON, default=dict)
    blue_agent_config: Mapped[dict] = mapped_column(JSON, default=dict)
    events_generated: Mapped[int] = mapped_column(Integer, default=0)
    alerts_triggered: Mapped[int] = mapped_column(Integer, default=0)
    detection_rate: Mapped[float] = mapped_column(Float, default=0.0)
    mean_time_to_detect: Mapped[float] = mapped_column(Float, default=0.0)  # seconds
    red_agent_log: Mapped[list] = mapped_column(JSON, default=list)
    blue_agent_log: Mapped[list] = mapped_column(JSON, default=list)
    findings: Mapped[str] = mapped_column(Text, nullable=True)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
