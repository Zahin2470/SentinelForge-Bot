"""Incident listing + a manual "run correlation now" endpoint, mirroring
the detection-rules router's /run endpoint for the same reason: in a real
deployment correlation runs off a worker job, but for demos/tests/
`make simulate`, triggering it synchronously and seeing the created
incidents immediately is more useful than waiting on a poll interval.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.repositories.incident_repository import IncidentRepository
from app.services.correlation_service import CorrelationService

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_incident_repo = IncidentRepository()
_correlation_service = CorrelationService(incident_repo=_incident_repo)


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    display_id: str
    title: str
    severity: str
    status: str
    rule_score: float | None = None
    anomaly_score: float | None = None
    correlation_score: float | None = None
    threat_intelligence_score: float | None = None
    asset_criticality_score: float | None = None
    identity_context_score: float | None = None
    final_risk_score: float | None = None
    primary_host: str | None = None
    primary_user: str | None = None


class CorrelationRunSummary(BaseModel):
    incidents_created: int
    incident_display_ids: list[str]


@router.get("", response_model=list[IncidentRead])
def list_incidents(
    status_filter: str | None = None, db: Session = Depends(get_db)
) -> list[IncidentRead]:
    incidents = _incident_repo.list_all(db, status=status_filter)
    return [IncidentRead.model_validate(i) for i in incidents]


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: uuid.UUID, db: Session = Depends(get_db)) -> IncidentRead:
    incident = _incident_repo.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return IncidentRead.model_validate(incident)


@router.post("/correlate", response_model=CorrelationRunSummary)
def run_correlation(db: Session = Depends(get_db)) -> CorrelationRunSummary:
    incidents = _correlation_service.run_correlation(db)
    db.commit()
    return CorrelationRunSummary(
        incidents_created=len(incidents),
        incident_display_ids=[i.display_id for i in incidents],
    )
