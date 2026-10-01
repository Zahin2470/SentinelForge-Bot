"""DetectionRule here is a **queryable index** of the YAML rules that live
in /detection-rules — the YAML files remain the source of truth for
detection logic (see docs/detection-engine.md), but the DB row is what lets
the API/dashboard list, enable/disable, and show hit-counts without parsing
YAML on every request. A sync script keeps the two in step
(scripts/sync_detection_rules.py, Phase 3).

Alert is what the detection engine and ML pipeline actually produce per
match — always linked back to the specific security_events that triggered
it, never a bare severity label with no evidence.
"""

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Boolean, DateTime, Float, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "detection_rules"

    rule_key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)  # e.g. AUTH-BRUTEFORCE-001
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    attack_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    source_path: Mapped[str] = mapped_column(String(500), nullable=False)  # path under detection-rules/
    definition: Mapped[dict] = mapped_column(JSONB, nullable=False)  # full parsed rule, for the executor


class Alert(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "alerts"

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    source: Mapped[str] = mapped_column(String(20), nullable=False)  # "rule" | "ml"
    detection_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Which security_events triggered this alert — always populated, an
    # alert with no evidence event IDs is a bug, not a valid state.
    matched_event_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False
    )

    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    entity_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entity_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Set once correlation groups this alert into an incident.
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True
    )
