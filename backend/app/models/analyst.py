import uuid
from sqlalchemy import String, Float, Integer, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, UUIDMixin, TimestampMixin


class Analyst(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "analysts"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    tier: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1=junior, 2=mid, 3=senior
    skills: Mapped[list] = mapped_column(JSON, default=list)  # ["web", "network", "cloud", ...]
    availability: Mapped[str] = mapped_column(String(20), default="online")  # online|busy|offline
    max_tickets: Mapped[int] = mapped_column(Integer, default=5)
    current_ticket_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_resolution_hours: Mapped[float] = mapped_column(Float, default=0.0)
    total_resolved: Mapped[int] = mapped_column(Integer, default=0)
    success_rate: Mapped[float] = mapped_column(Float, default=1.0)  # 0.0–1.0
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
