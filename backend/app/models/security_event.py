"""The normalized security event — the common schema every ingested log
source (auth, endpoint, network, web/application, cloud audit) is converted
into. See docs/architecture/architecture.md §2 for the field list this
mirrors, and app/ingest/ for the source-specific normalizers that populate
it.

Append-only by design (no SoftDeleteMixin, no updates after creation): a
security event is a historical fact. Corrections/annotations belong on the
Alert or Incident that references it, not on the raw event.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class SecurityEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_timestamp", "timestamp"),
        Index("ix_security_events_username", "username"),
        Index("ix_security_events_hostname", "hostname"),
        Index("ix_security_events_source_ip", "source_ip"),
        Index("ix_security_events_destination_ip", "destination_ip"),
        Index("ix_security_events_event_type", "event_type"),
        Index("ix_security_events_severity", "severity"),
    )

    # Source-reported time (may differ from ingestion time under clock skew
    # or batch replay — both are kept, see ingested_at below).
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    source: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "okta", "crowdstrike", "aws_cloudtrail"
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # authentication|endpoint|network|application|cloud

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv4/IPv6
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(nullable=True)
    destination_port: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)

    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_id: Mapped[int | None] = mapped_column(nullable=True)
    command_line: Mapped[str | None] = mapped_column(String, nullable=True)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)

    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)

    # Flexible bucket for source-specific fields that don't fit the
    # standard schema. Never used as a substitute for promoting a
    # frequently-queried field to a real column.
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)

    # The original, untouched event as received — never discarded, so any
    # normalization bug is always recoverable/auditable.
    raw_event: Mapped[dict] = mapped_column(JSONB, nullable=False)

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True
    )
