"""Wires app.ml.model.AnomalyModel to persistence: pulls the recent event
window, extracts per-entity features (app.ml.features), scores each entity,
and creates an Alert (source="ml") for anything over the threshold — same
"always attach evidence" contract as app/services/detection_service.py:
matched_event_ids is always populated with the entity's events from the
window, never a bare score with no evidence trail.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.ml.features import build_feature_table
from app.ml.model import AnomalyModel
from app.models.security_event import SecurityEvent
from app.repositories.alert_repository import AlertRepository
from app.repositories.security_event_repository import SecurityEventRepository
from app.services.risk_scoring import score_to_severity

logger = get_logger(__name__)

DEFAULT_LOOKBACK = timedelta(hours=1)  # matches app.ml.synthetic.CANONICAL_WINDOW_MINUTES
DEFAULT_THRESHOLD = 0.75


def _event_to_ml_dict(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "timestamp": event.timestamp,
        "hostname": event.hostname,
        "username": event.username,
        "source_ip": event.source_ip,
        "country": event.country,
        "event_type": event.event_type,
        "status": event.status,
    }


class ModelNotAvailable(RuntimeError):
    """Raised when no trained model artifact can be found. Callers should
    treat this the same way the AI agent's degraded mode is documented:
    surface a clear 'ML scoring unavailable' message rather than crash the
    whole detection pipeline — rules/correlation don't depend on ML."""


def _find_latest_model_path(models_dir: str | Path) -> Path:
    models_dir = Path(models_dir)
    candidates = sorted(models_dir.glob("anomaly_*.joblib"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise ModelNotAvailable(
            f"No trained model artifact found under {models_dir}. Run `make train-ml` first."
        )
    return candidates[0]


class MLScoringService:
    def __init__(
        self,
        event_repo: SecurityEventRepository | None = None,
        alert_repo: AlertRepository | None = None,
        model_path: str | Path | None = None,
    ) -> None:
        self.event_repo = event_repo or SecurityEventRepository()
        self.alert_repo = alert_repo or AlertRepository()
        self._model_path = model_path
        self._model: AnomalyModel | None = None

    def _get_model(self) -> AnomalyModel:
        if self._model is not None:
            return self._model
        path = self._model_path or _find_latest_model_path(get_settings().ml_models_path)
        self._model = AnomalyModel.load(path)
        logger.info("ml_model_loaded", model_version=self._model.metadata.model_version, path=str(path))
        return self._model

    def run_scoring(
        self,
        db: Session,
        *,
        as_of: datetime | None = None,
        lookback: timedelta = DEFAULT_LOOKBACK,
        threshold: float = DEFAULT_THRESHOLD,
        entity_field: str = "username",
    ) -> list[dict]:
        """Scores every entity active in the recent window. Returns a list
        of {entity, score, alerted} dicts for every entity considered (not
        just the ones that alerted) so a caller can report what was scored,
        mirroring DetectionService.run_enabled_rules returning every
        DetectionResult including non-matches.
        """
        try:
            model = self._get_model()
        except ModelNotAvailable as exc:
            logger.warning("ml_scoring_skipped", reason=str(exc))
            return []

        as_of = as_of or datetime.now(tz=timezone.utc)
        window_start = as_of - lookback

        events = self.event_repo.get_window(db, start_time=window_start, end_time=as_of)
        event_dicts = [_event_to_ml_dict(e) for e in events]
        events_by_entity_id: dict = {}
        for e, ed in zip(events, event_dicts, strict=True):
            entity_value = ed.get(entity_field)
            if entity_value is None:
                continue
            events_by_entity_id.setdefault(entity_value, []).append(e)

        feature_table = build_feature_table(event_dicts, entity_field=entity_field, window=lookback)

        results: list[dict] = []
        for entity, features in feature_table.items():
            score = model.score_one(features)
            alerted = score >= threshold
            results.append({"entity": entity, "score": score, "alerted": alerted})

            if not alerted:
                continue

            entity_events = events_by_entity_id[entity]
            severity = score_to_severity(score)

            alert_fields = {
                "source": "ml",
                "detection_rule_id": None,
                "title": f"Anomalous behavior detected for {entity_field} '{entity}'",
                "severity": severity,
                "matched_event_ids": [e.id for e in entity_events],
                "anomaly_score": score,
                "model_version": model.metadata.model_version,
            }
            if entity_field == "username":
                alert_fields["entity_username"] = entity
                alert_fields["entity_hostname"] = next((e.hostname for e in entity_events if e.hostname), None)
            else:
                alert_fields["entity_hostname"] = entity
                alert_fields["entity_username"] = next((e.username for e in entity_events if e.username), None)

            self.alert_repo.create(db, alert_fields)
            logger.info(
                "ml_alert_created",
                entity=entity,
                entity_field=entity_field,
                score=round(score, 3),
                severity=severity,
                model_version=model.metadata.model_version,
            )

        return results
