"""Wires app.correlation.engine (pure grouping) and app.services.risk_scoring
(pure scoring) to persistence: pulls unassigned alerts, groups them,
creates one Incident per group, links the group's alerts and their
underlying security_events to it, and stores a full, transparent
risk-score breakdown (docs/architecture/architecture.md §7) — never just
the final number.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.correlation.engine import (
    DEFAULT_CORRELATION_WINDOW,
    correlate_alerts,
    group_primary_entity,
    group_severity,
)
from app.core.logging import get_logger
from app.models.detection_rule import Alert
from app.models.incident import Incident
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.incident_repository import IncidentRepository
from app.services.risk_scoring import (
    compute_risk_score,
    correlation_score_from_group_size,
    rule_score_from_alerts,
)

logger = get_logger(__name__)


def _alert_to_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "created_at": alert.created_at,
        "entity_username": alert.entity_username,
        "entity_hostname": alert.entity_hostname,
        "severity": alert.severity,
        "matched_event_ids": alert.matched_event_ids,
    }


class CorrelationService:
    def __init__(
        self,
        alert_repo: AlertRepository | None = None,
        incident_repo: IncidentRepository | None = None,
        asset_repo: AssetRepository | None = None,
    ) -> None:
        self.alert_repo = alert_repo or AlertRepository()
        self.incident_repo = incident_repo or IncidentRepository()
        self.asset_repo = asset_repo or AssetRepository()

    def run_correlation(
        self, db: Session, *, time_window=DEFAULT_CORRELATION_WINDOW, since: datetime | None = None
    ) -> list[Incident]:
        alerts = self.alert_repo.list_unassigned_to_incident(db, since=since)
        if not alerts:
            return []

        alerts_by_id = {a.id: a for a in alerts}
        alert_dicts = [_alert_to_dict(a) for a in alerts]

        groups = correlate_alerts(alert_dicts, time_window=time_window)

        created_incidents: list[Incident] = []
        for group in groups:
            incident = self._create_incident_for_group(db, group, alerts_by_id)
            created_incidents.append(incident)

        return created_incidents

    def _create_incident_for_group(self, db: Session, group: list[dict], alerts_by_id: dict) -> Incident:
        severity = group_severity(group)
        entity = group_primary_entity(group)

        group_alert_ids = [a["id"] for a in group]
        group_severities = [a["severity"] for a in group]

        rule_score = rule_score_from_alerts(group_severities)
        correlation_score = correlation_score_from_group_size(len(group))

        asset_criticality_score = None
        if entity["primary_host"]:
            asset = self.asset_repo.get_by_hostname(db, entity["primary_host"])
            if asset:
                asset_criticality_score = asset.criticality_score

        # anomaly_score, threat_intelligence_score, identity_context_score
        # are not yet computable — Phase 5 (ML) and Phase 6 (threat intel)
        # haven't landed. Left as None rather than faked, and
        # compute_risk_score renormalizes over what's actually available.
        components = {
            "rule_score": rule_score,
            "anomaly_score": None,
            "correlation_score": correlation_score,
            "threat_intelligence_score": None,
            "asset_criticality_score": asset_criticality_score,
            "identity_context_score": None,
        }
        final_risk_score = compute_risk_score(components)

        display_id = self.incident_repo.next_display_id(db)
        title = self._build_title(entity, severity, len(group))

        incident = self.incident_repo.create(
            db,
            {
                "display_id": display_id,
                "title": title,
                "description": "",
                "severity": severity,
                "primary_host": entity["primary_host"],
                "primary_user": entity["primary_user"],
                **components,
                "final_risk_score": final_risk_score,
            },
        )

        # Link alerts to the incident and pull each alert's evidence events
        # into the incident timeline.
        self.alert_repo.assign_to_incident(db, group_alert_ids, incident.id)

        all_event_ids: list = []
        for alert_id in group_alert_ids:
            alert = alerts_by_id[alert_id]
            all_event_ids.extend(alert.matched_event_ids)
            self.incident_repo.link_events(db, incident.id, alert.matched_event_ids, alert_id=alert_id)

        logger.info(
            "incident_created",
            display_id=display_id,
            severity=severity,
            alert_count=len(group),
            final_risk_score=final_risk_score,
            primary_user=entity["primary_user"],
            primary_host=entity["primary_host"],
        )

        return incident

    @staticmethod
    def _build_title(entity: dict, severity: str, alert_count: int) -> str:
        who = entity["primary_user"] or entity["primary_host"] or "Unknown entity"
        plural = "s" if alert_count != 1 else ""
        return f"{severity.capitalize()} severity activity — {who} ({alert_count} correlated alert{plural})"
