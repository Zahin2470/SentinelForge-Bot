"""Ingestion orchestration: normalize raw events, persist them, and
(optionally) trigger detection. Bad events in a batch are quarantined
(logged, counted, excluded) rather than failing the whole batch — one
malformed event from a flaky source should never block the other 999.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.ingest.normalizer import NormalizationError, normalize
from app.repositories.security_event_repository import SecurityEventRepository
from app.schemas.security_event import IngestEventRequest, IngestResult

logger = get_logger(__name__)


class IngestionService:
    def __init__(self, event_repo: SecurityEventRepository | None = None) -> None:
        self.event_repo = event_repo or SecurityEventRepository()

    def ingest_batch(self, db: Session, requests: list[IngestEventRequest]) -> IngestResult:
        normalized_events: list[dict] = []
        rejected_reasons: list[str] = []

        for req in requests:
            try:
                normalized_events.append(normalize(req.source_format, req.raw))
            except NormalizationError as exc:
                logger.warning("event_normalization_failed", source_format=req.source_format, error=str(exc))
                rejected_reasons.append(str(exc))

        created = self.event_repo.create_many(db, normalized_events) if normalized_events else []

        return IngestResult(
            accepted=len(created),
            rejected=len(rejected_reasons),
            rejected_reasons=rejected_reasons,
            created_event_ids=[e.id for e in created],
        )
