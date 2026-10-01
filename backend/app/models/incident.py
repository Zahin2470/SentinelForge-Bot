"""Incident is the unit a human analyst actually works: a correlated group
of alerts/events with a lifecycle, a transparent risk-score breakdown, and
(once the AI agent runs) an evidence-grounded ai_summary. See
docs/architecture/architecture.md §7 for the risk-score component contract
this model stores verbatim (never just the final number).
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import ARRAY, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    display_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # "INC-0012"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(default=IncidentStatus.OPEN, nullable=False)

    # Transparent risk-score breakdown — every component stored, never just
    # the final number (docs/architecture/architecture.md §7).
    rule_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    correlation_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_intelligence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    asset_criticality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    identity_context_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    final_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    primary_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    primary_user: Mapped[str | None] = mapped_column(String(255), nullable=True)

    attack_techniques: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)

    # Structured AI investigation output validated against the schema in
    # docs/ai/ai-agent.md §8 before being written here.
    ai_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentEvent(UUIDPrimaryKeyMixin, Base):
    """Join table linking an incident to the security_events that make up
    its timeline — kept as its own table (rather than an array column) so
    the timeline can carry per-link metadata (e.g. which rule/alert pulled
    this event in) and can be indexed/queried efficiently."""

    __tablename__ = "incident_events"

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    security_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_events.id"), nullable=False
    )
    linked_via_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True
    )


class IncidentIOC(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "incident_iocs"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id"), nullable=False
    )
