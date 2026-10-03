from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_rule import Alert


class AlertRepository:
    def create(self, db: Session, alert_data: dict) -> Alert:
        alert = Alert(**alert_data)
        db.add(alert)
        db.flush()
        return alert

    def get_by_id(self, db: Session, alert_id: uuid.UUID) -> Alert | None:
        return db.get(Alert, alert_id)

    def list_unassigned_to_incident(self, db: Session, *, since: datetime | None = None) -> list[Alert]:
        """Alerts not yet grouped into an incident — what the correlation
        engine (Phase 4) will consume."""
        stmt = select(Alert).where(Alert.incident_id.is_(None))
        if since:
            stmt = stmt.where(Alert.created_at >= since)
        stmt = stmt.order_by(Alert.created_at.asc())
        return list(db.execute(stmt).scalars().all())

    def list_for_incident(self, db: Session, incident_id: uuid.UUID) -> list[Alert]:
        stmt = select(Alert).where(Alert.incident_id == incident_id)
        return list(db.execute(stmt).scalars().all())

    def assign_to_incident(self, db: Session, alert_ids: list[uuid.UUID], incident_id: uuid.UUID) -> int:
        if not alert_ids:
            return 0
        stmt = select(Alert).where(Alert.id.in_(alert_ids))
        alerts = db.execute(stmt).scalars().all()
        for alert in alerts:
            alert.incident_id = incident_id
        db.flush()
        return len(alerts)
