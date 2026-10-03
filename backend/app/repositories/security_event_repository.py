"""Data access for SecurityEvent. Repositories contain query logic only —
no business rules (no "should this trigger an alert" here); that belongs in
app/services/. Every method takes the Session it should use rather than
holding one, so a single repository instance is safe to reuse across
requests (it holds no per-request state).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent


class SecurityEventRepository:
    def create(self, db: Session, event_data: dict) -> SecurityEvent:
        event = SecurityEvent(**event_data)
        db.add(event)
        db.flush()  # populate event.id without committing — caller controls the transaction boundary
        return event

    def create_many(self, db: Session, events_data: list[dict]) -> list[SecurityEvent]:
        events = [SecurityEvent(**data) for data in events_data]
        db.add_all(events)
        db.flush()
        return events

    def get_by_id(self, db: Session, event_id: uuid.UUID) -> SecurityEvent | None:
        return db.get(SecurityEvent, event_id)

    def get_many_by_ids(self, db: Session, event_ids: list[uuid.UUID]) -> list[SecurityEvent]:
        if not event_ids:
            return []
        stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
        return list(db.execute(stmt).scalars().all())

    def search(
        self,
        db: Session,
        *,
        username: str | None = None,
        hostname: str | None = None,
        source_ip: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SecurityEvent]:
        stmt = select(SecurityEvent)
        if username:
            stmt = stmt.where(SecurityEvent.username == username)
        if hostname:
            stmt = stmt.where(SecurityEvent.hostname == hostname)
        if source_ip:
            stmt = stmt.where(SecurityEvent.source_ip == source_ip)
        if event_type:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
        if severity:
            stmt = stmt.where(SecurityEvent.severity == severity)
        if start_time:
            stmt = stmt.where(SecurityEvent.timestamp >= start_time)
        if end_time:
            stmt = stmt.where(SecurityEvent.timestamp <= end_time)

        stmt = stmt.order_by(SecurityEvent.timestamp.desc()).limit(limit).offset(offset)
        return list(db.execute(stmt).scalars().all())

    def get_window(
        self, db: Session, *, start_time: datetime, end_time: datetime, source_type: str | None = None
    ) -> list[SecurityEvent]:
        """Used by the detection service to pull the event window a rule
        should be evaluated against (docs/detection-engine.md §6)."""
        stmt = select(SecurityEvent).where(
            SecurityEvent.timestamp >= start_time, SecurityEvent.timestamp <= end_time
        )
        if source_type:
            stmt = stmt.where(SecurityEvent.source_type == source_type)
        stmt = stmt.order_by(SecurityEvent.timestamp.asc())
        return list(db.execute(stmt).scalars().all())
