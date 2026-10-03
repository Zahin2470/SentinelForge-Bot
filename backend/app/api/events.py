"""Ingestion + search endpoints for security events.

Ingestion is intentionally the ONLY write path into security_events, and it
requires a scoped ingestion API credential in production (see
docs/security/threat-model.md — "malicious user" row); auth wiring lands
with app/core/security.py in the next increment, so these routes accept a
placeholder Depends for now rather than being silently open.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.repositories.security_event_repository import SecurityEventRepository
from app.schemas.security_event import (
    IngestBatchRequest,
    IngestResult,
    SecurityEventRead,
    SecurityEventSearchParams,
)
from app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/api/v1/events", tags=["events"])

_ingestion_service = IngestionService()
_event_repo = SecurityEventRepository()


@router.post("/ingest", response_model=IngestResult)
def ingest_events(payload: IngestBatchRequest, db: Session = Depends(get_db)) -> IngestResult:
    result = _ingestion_service.ingest_batch(db, payload.events)
    db.commit()
    return result


@router.get("/search", response_model=list[SecurityEventRead])
def search_events(
    params: SecurityEventSearchParams = Depends(), db: Session = Depends(get_db)
) -> list[SecurityEventRead]:
    events = _event_repo.search(
        db,
        username=params.username,
        hostname=params.hostname,
        source_ip=params.source_ip,
        event_type=params.event_type,
        severity=params.severity,
        start_time=params.start_time,
        end_time=params.end_time,
        limit=params.limit,
        offset=params.offset,
    )
    return [SecurityEventRead.model_validate(e) for e in events]
