from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.repositories.ioc_repository import IOCRepository
from app.services.threat_intel_service import ThreatIntelService

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intel"])

_ioc_repo = IOCRepository()
_threat_intel_service = ThreatIntelService(ioc_repo=_ioc_repo)


class IOCRead(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    source: str
    confidence: float
    threat_level: str


class ImportFeedRequest(BaseModel):
    feed_path: str = "threat-intel/sample_feed.json"


class ImportFeedResult(BaseModel):
    imported: int
    skipped: int
    skip_reasons: list[str]


class MatchRunSummary(BaseModel):
    alerts_created: int
    matches: list[dict]


@router.get("/iocs", response_model=list[IOCRead])
def list_iocs(db: Session = Depends(get_db)) -> list[IOCRead]:
    iocs = _ioc_repo.list_all(db)
    return [IOCRead.model_validate(_ioc_repo.to_dict(i) | {"source": i.source}) for i in iocs]


@router.post("/import", response_model=ImportFeedResult)
def import_feed(payload: ImportFeedRequest, db: Session = Depends(get_db)) -> ImportFeedResult:
    result = _threat_intel_service.import_feed(db, payload.feed_path)
    db.commit()
    return ImportFeedResult(**result)


@router.post("/match", response_model=MatchRunSummary)
def run_matching(db: Session = Depends(get_db)) -> MatchRunSummary:
    summaries = _threat_intel_service.run_matching(db)
    db.commit()
    return MatchRunSummary(alerts_created=len(summaries), matches=summaries)
