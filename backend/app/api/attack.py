"""ATT&CK technique lookup and coverage visualization data (docs — §12:
"Detected Techniques / Covered Techniques / Uncovered Techniques /
Detection Coverage"). The frontend's coverage view (not yet built) would
consume /coverage directly.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.attack.coverage import compute_coverage
from app.attack.reference_data import map_technique
from app.core.db import get_db
from app.repositories.detection_rule_repository import DetectionRuleRepository

router = APIRouter(prefix="/api/v1/attack", tags=["attack"])

_rule_repo = DetectionRuleRepository()


class TechniqueMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str | None
    is_subtechnique: bool
    parent_technique_id: str | None


class CoverageResponse(BaseModel):
    total_techniques: int
    covered_technique_ids: list[str]
    uncovered_technique_ids: list[str]
    detected_technique_ids: list[str]
    coverage_percent: float


@router.get("/techniques/{technique_id}", response_model=TechniqueMapping)
def get_technique_mapping(technique_id: str) -> TechniqueMapping:
    mapping = map_technique(technique_id)
    if mapping is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id!r} not in the curated reference set "
            "(see app/attack/reference_data.py's module docstring).",
        )
    return TechniqueMapping(**mapping)


@router.get("/coverage", response_model=CoverageResponse)
def get_coverage(db: Session = Depends(get_db)) -> CoverageResponse:
    rules = _rule_repo.list_enabled(db)
    rule_technique_ids = [r.attack_technique_id for r in rules if r.attack_technique_id]
    # detected_technique_ids (techniques with an actual alert/incident so
    # far) needs Alert->DetectionRule->technique_id join history; left as
    # empty for now — a real implementation joins alerts to detection_rules
    # and maps attack_technique_id, which is straightforward but needs a
    # dedicated repository method not yet written (tracked as a TODO here
    # rather than faked with a guess).
    report = compute_coverage(rule_technique_ids)
    return CoverageResponse(**report.to_dict())
