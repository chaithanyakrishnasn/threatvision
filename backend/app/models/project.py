from datetime import datetime
from sqlalchemy import String, Text, Integer, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, UUIDMixin, TimestampMixin


class Project(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    target_url: Mapped[str] = mapped_column(String(500), nullable=True)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    tech_stack: Mapped[list] = mapped_column(JSON, default=list)       # ["Python", "Django", ...]
    risk_tier: Mapped[str] = mapped_column(String(20), default="medium")  # critical|high|medium|low
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|scanning|paused|archived
    owner_name: Mapped[str] = mapped_column(String(255), nullable=False)
    assigned_analysts: Mapped[list] = mapped_column(JSON, default=list)  # list of analyst UUIDs (str)

    # Cached stats — updated on ticket changes
    open_tickets: Mapped[int] = mapped_column(Integer, default=0)
    critical_tickets: Mapped[int] = mapped_column(Integer, default=0)
    resolved_tickets: Mapped[int] = mapped_column(Integer, default=0)
    security_score: Mapped[int] = mapped_column(Integer, default=100)  # 0-100

    last_scan_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
