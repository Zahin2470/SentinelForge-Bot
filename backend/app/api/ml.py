"""Manual ML anomaly-scoring trigger, mirroring the /detection-rules/run
and /incidents/correlate endpoints — in a real deployment this runs off a
worker job, but for demos/tests, triggering it synchronously is more
useful than waiting on a poll interval.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.services.ml_scoring_service import MLScoringService

router = APIRouter(prefix="/api/v1/ml", tags=["ml"])

_ml_scoring_service = MLScoringService()


class MLScoringSummary(BaseModel):
    entities_scored: int
    alerts_created: int
    scores: list[dict]


@router.post("/score", response_model=MLScoringSummary)
def run_ml_scoring(db: Session = Depends(get_db)) -> MLScoringSummary:
    results = _ml_scoring_service.run_scoring(db)
    db.commit()
    return MLScoringSummary(
        entities_scored=len(results),
        alerts_created=sum(1 for r in results if r["alerted"]),
        scores=[{"entity": r["entity"], "score": round(r["score"], 4)} for r in results],
    )
