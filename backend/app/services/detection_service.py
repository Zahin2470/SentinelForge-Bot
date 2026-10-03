"""Wires the pure detection executor (app/detection/executor.py) to
persisted data: pulls a window of SecurityEvent rows, converts them to the
plain dicts the executor expects, runs every enabled rule, and writes an
Alert row for each match — always with matched_event_ids populated, never
a bare severity label (docs/detection-engine.md §3).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.detection.executor import DetectionResult, evaluate_rule
from app.models.security_event import SecurityEvent
from app.repositories.alert_repository import AlertRepository
from app.repositories.detection_rule_repository import DetectionRuleRepository
from app.repositories.security_event_repository import SecurityEventRepository

logger = get_logger(__name__)

# How far back to look when evaluating rules against newly ingested events.
# Generous relative to the longest rule timeframe in the current library
# (10m) so a rule's window is never truncated; revisit once rules with
# longer timeframes ship.
DEFAULT_LOOKBACK = timedelta(hours=1)


def _event_to_dict(event: SecurityEvent) -> dict:
    """Converts an ORM row to the plain dict shape app.detection.executor
    expects. Deliberately explicit (not a generic __dict__ dump) so the
    executor's contract doesn't silently change if a column is renamed."""
    return {
        "id": event.id,
        "timestamp": event.timestamp,
        "hostname": event.hostname,
        "username": event.username,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "source_port": event.source_port,
        "protocol": event.protocol,
        "process_name": event.process_name,
        "command_line": event.command_line,
        "event_type": event.event_type,
        "action": event.action,
        "status": event.status,
        "severity": event.severity,
    }


class DetectionService:
    def __init__(
        self,
        rule_repo: DetectionRuleRepository | None = None,
        event_repo: SecurityEventRepository | None = None,
        alert_repo: AlertRepository | None = None,
    ) -> None:
        self.rule_repo = rule_repo or DetectionRuleRepository()
        self.event_repo = event_repo or SecurityEventRepository()
        self.alert_repo = alert_repo or AlertRepository()

    def run_enabled_rules(
        self, db: Session, *, as_of: datetime | None = None, lookback: timedelta = DEFAULT_LOOKBACK
    ) -> list[DetectionResult]:
        """Evaluates every enabled rule against the recent event window and
        creates an Alert for each match. Returns every DetectionResult
        (including 'unsupported' ones) so a caller (e.g. an API endpoint
        used in tests/demos) can report exactly what happened — matches are
        the subset with .matched == True.
        """
        as_of = as_of or datetime.now(tz=timezone.utc)
        window_start = as_of - lookback

        rules = self.rule_repo.list_enabled(db)
        events = self.event_repo.get_window(db, start_time=window_start, end_time=as_of)
        event_dicts = [_event_to_dict(e) for e in events]

        all_results: list[DetectionResult] = []
        for rule in rules:
            results = evaluate_rule(rule.definition, event_dicts)
            all_results.extend(results)

            for result in results:
                if not result.matched:
                    if result.status == "unsupported":
                        logger.info(
                            "detection_rule_unsupported", rule_id=result.rule_id, reason=result.reason
                        )
                    continue

                matched_events = [e for e in events if str(e.id) in result.matched_event_ids]
                entity_username = next((e.username for e in matched_events if e.username), None)
                entity_hostname = next((e.hostname for e in matched_events if e.hostname), None)

                self.alert_repo.create(
                    db,
                    {
                        "source": "rule",
                        "detection_rule_id": rule.id,
                        "title": rule.title,
                        "severity": rule.severity,
                        "matched_event_ids": [e.id for e in matched_events],
                        "entity_username": entity_username,
                        "entity_hostname": entity_hostname,
                    },
                )
                logger.info(
                    "alert_created",
                    rule_id=result.rule_id,
                    matched_event_count=len(matched_events),
                    entity_username=entity_username,
                    entity_hostname=entity_hostname,
                )

        return all_results
