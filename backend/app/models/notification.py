"""In-app notifications (new critical incident, AI investigation completed,
etc.) — feeds the frontend notification bell and, later, could fan out to
email/Slack via a worker job. Kept simple deliberately; this is not the
project's focus area.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class Notification(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # "critical_incident", "investigation_complete", ...
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    related_object_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    related_object_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
