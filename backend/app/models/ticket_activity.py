import uuid
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, UUIDMixin, TimestampMixin


class TicketActivity(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ticket_activities"

    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tickets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)   # agent|analyst|system
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)    # analyst UUID or agent name
    actor_name: Mapped[str] = mapped_column(String(255), nullable=False)  # display name
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    # created|assigned|acknowledged|comment_added|status_changed|escalated|resolved|verified
    old_value: Mapped[str] = mapped_column(String(100), nullable=True)
    new_value: Mapped[str] = mapped_column(String(100), nullable=True)
    comment: Mapped[str] = mapped_column(Text, nullable=True)

    ticket: Mapped["Ticket"] = relationship("Ticket", back_populates="activities")  # type: ignore
