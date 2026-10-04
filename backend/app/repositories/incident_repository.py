from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.incident import Incident, IncidentEvent


class IncidentRepository:
    def next_display_id(self, db: Session) -> str:
        """Generates the next INC-NNNN display ID. Uses a count-based
        approach guarded by the caller's transaction; fine at demo/portfolio
        volume — a real deployment would use a DB sequence to avoid a race
        between concurrent incident creations."""
        count = db.execute(select(func.count()).select_from(Incident)).scalar_one()
        return f"INC-{count + 1:04d}"

    def create(self, db: Session, incident_data: dict) -> Incident:
        incident = Incident(**incident_data)
        db.add(incident)
        db.flush()
        return incident

    def get_by_id(self, db: Session, incident_id: uuid.UUID) -> Incident | None:
        return db.get(Incident, incident_id)

    def list_all(self, db: Session, *, status: str | None = None, limit: int = 50, offset: int = 0) -> list[Incident]:
        stmt = select(Incident)
        if status:
            stmt = stmt.where(Incident.status == status)
        stmt = stmt.order_by(Incident.created_at.desc()).limit(limit).offset(offset)
        return list(db.execute(stmt).scalars().all())

    def link_events(self, db: Session, incident_id: uuid.UUID, event_ids: list[uuid.UUID], alert_id: uuid.UUID | None = None) -> None:
        for event_id in event_ids:
            db.add(IncidentEvent(incident_id=incident_id, security_event_id=event_id, linked_via_alert_id=alert_id))
        db.flush()
