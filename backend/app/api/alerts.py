from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.repositories.alert_repository import AlertRepository
from app.schemas.alert import AlertRead

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

_alert_repo = AlertRepository()


@router.get("/unassigned", response_model=list[AlertRead])
def list_unassigned_alerts(db: Session = Depends(get_db)) -> list[AlertRead]:
    """Alerts not yet grouped into an incident — awaiting the correlation
    engine (Phase 4, not yet implemented)."""
    alerts = _alert_repo.list_unassigned_to_incident(db)
    return [AlertRead.model_validate(a) for a in alerts]
