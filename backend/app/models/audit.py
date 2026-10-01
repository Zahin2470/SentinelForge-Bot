"""Application-wide audit log (docs/architecture — §30). Append-only,
never updated or deleted by application code. Covers both human actions
(rule edits, incident status changes, analyst notes) and high-value AI
actions (every tool call the agent makes — see app/models/agent.py for the
more detailed agent-specific tables this summarizes into a single
searchable trail).
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class AuditLog(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "user" | "agent" | "system"
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False)  # denormalized display name
    session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    action: Mapped[str] = mapped_column(String(100), nullable=False)  # "updated_detection_rule", "resolved_incident", ...
    object_type: Mapped[str] = mapped_column(String(100), nullable=False)  # "detection_rule", "incident", ...
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # Never contains secrets — enforced by convention in app/services/audit.py,
    # which is the only code allowed to write to this table.
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
