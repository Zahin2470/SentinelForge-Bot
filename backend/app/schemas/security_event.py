"""API request/response schemas for security events. Kept separate from the
ORM model (app/models/security_event.py) on purpose — the wire format and
the storage format are allowed to diverge (e.g. IngestEventRequest is much
looser than the normalized model, since it's raw incoming data)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IngestEventRequest(BaseModel):
    """What callers POST to /api/v1/events/ingest. `source_format` selects
    which normalizer in app/ingest/normalizer.py handles `raw`."""

    source_format: str = Field(..., examples=["generic_auth", "generic_endpoint"])
    raw: dict[str, Any]


class IngestBatchRequest(BaseModel):
    events: list[IngestEventRequest] = Field(..., min_length=1, max_length=1000)


class IngestResult(BaseModel):
    accepted: int
    rejected: int
    rejected_reasons: list[str] = Field(default_factory=list)
    created_event_ids: list[uuid.UUID] = Field(default_factory=list)


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    ingested_at: datetime
    source: str
    source_type: str
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    process_name: str | None = None
    command_line: str | None = None
    event_type: str
    action: str | None = None
    status: str | None = None
    severity: str


class SecurityEventSearchParams(BaseModel):
    username: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    event_type: str | None = None
    severity: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
