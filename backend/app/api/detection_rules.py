"""Detection rule listing + a manual "run detection now" endpoint.

In a real deployment, detection runs automatically off the ingestion queue
(a worker job, app/workers/) rather than being triggered by an API call —
this manual endpoint exists for demos, tests, and `make simulate`, where
running it synchronously and seeing the result immediately is more useful
than waiting on a background worker's polling interval.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.repositories.detection_rule_repository import DetectionRuleRepository
from app.schemas.detection_rule import DetectionRuleRead
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/api/v1/detection-rules", tags=["detection"])

_rule_repo = DetectionRuleRepository()
_detection_service = DetectionService(rule_repo=_rule_repo)


class DetectionRunSummary(BaseModel):
    rules_evaluated: int
    matches: int
    unsupported: int


@router.get("", response_model=list[DetectionRuleRead])
def list_detection_rules(db: Session = Depends(get_db)) -> list[DetectionRuleRead]:
    rules = _rule_repo.list_all(db)
    return [DetectionRuleRead.model_validate(r) for r in rules]


@router.post("/run", response_model=DetectionRunSummary)
def run_detection(db: Session = Depends(get_db)) -> DetectionRunSummary:
    results = _detection_service.run_enabled_rules(db)
    db.commit()
    return DetectionRunSummary(
        rules_evaluated=len({r.rule_id for r in results}),
        matches=sum(1 for r in results if r.matched),
        unsupported=sum(1 for r in results if r.status == "unsupported"),
    )
