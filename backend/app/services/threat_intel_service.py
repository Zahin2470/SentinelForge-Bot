"""Wires app.threat_intel.stix_normalizer and app.threat_intel.matcher to
persistence: imports a STIX-like sample feed into the IOC table, and
matches recent events against known IOCs to create threat-intel-sourced
alerts — same "always attach evidence" contract as the detection and ML
scoring services.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.security_event import SecurityEvent
from app.repositories.alert_repository import AlertRepository
from app.repositories.ioc_repository import IOCRepository
from app.repositories.security_event_repository import SecurityEventRepository
from app.threat_intel.matcher import find_ioc_matches
from app.threat_intel.stix_normalizer import UnsupportedStixPattern, normalize_stix_indicator

logger = get_logger(__name__)

DEFAULT_LOOKBACK = timedelta(hours=1)


def _event_to_ti_dict(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "domain": event.domain,
        "url": event.url,
        "file_hash": event.file_hash,
    }


class ThreatIntelService:
    def __init__(
        self,
        ioc_repo: IOCRepository | None = None,
        event_repo: SecurityEventRepository | None = None,
        alert_repo: AlertRepository | None = None,
    ) -> None:
        self.ioc_repo = ioc_repo or IOCRepository()
        self.event_repo = event_repo or SecurityEventRepository()
        self.alert_repo = alert_repo or AlertRepository()

    def import_feed(self, db: Session, feed_path: str | Path) -> dict:
        """Imports a STIX-bundle-shaped JSON file. Returns
        {imported, skipped, skip_reasons} — a bad indicator in the feed is
        logged and skipped, never allowed to abort the whole import
        (same philosophy as app.services.ingestion_service's event batches).
        """
        with open(feed_path) as f:
            bundle = json.load(f)

        indicators = [o for o in bundle.get("objects", []) if o.get("type") == "indicator"]
        imported, skip_reasons = 0, []

        for indicator in indicators:
            try:
                ioc_data = normalize_stix_indicator(indicator)
            except (ValueError, UnsupportedStixPattern) as exc:
                skip_reasons.append(f"{indicator.get('id', '?')}: {exc}")
                logger.warning("threat_intel_indicator_skipped", indicator_id=indicator.get("id"), reason=str(exc))
                continue

            self.ioc_repo.upsert(db, ioc_data)
            imported += 1

        return {"imported": imported, "skipped": len(skip_reasons), "skip_reasons": skip_reasons}

    def run_matching(
        self, db: Session, *, as_of: datetime | None = None, lookback: timedelta = DEFAULT_LOOKBACK
    ) -> list[dict]:
        """Returns one summary dict per alert created:
        {alert_id, ioc_type, ioc_value, matched_event_count}."""
        as_of = as_of or datetime.now(tz=timezone.utc)
        window_start = as_of - lookback

        events = self.event_repo.get_window(db, start_time=window_start, end_time=as_of)
        iocs = self.ioc_repo.list_all(db)
        if not events or not iocs:
            return []

        events_by_id = {e.id: e for e in events}
        event_dicts = [_event_to_ti_dict(e) for e in events]
        ioc_dicts = [self.ioc_repo.to_dict(i) for i in iocs]

        matches = find_ioc_matches(event_dicts, ioc_dicts)

        # Group matches by IOC so one alert covers all events an indicator
        # hit, rather than one alert per matched event.
        matches_by_ioc: dict = {}
        for m in matches:
            matches_by_ioc.setdefault(m.ioc_id, []).append(m)

        summaries: list[dict] = []
        for ioc_id, ioc_matches in matches_by_ioc.items():
            first = ioc_matches[0]
            matched_events = [events_by_id[m.event_id] for m in ioc_matches]
            severity = (
                "critical" if first.threat_level == "high"
                else "medium" if first.threat_level == "medium"
                else "low"
            )

            alert = self.alert_repo.create(
                db,
                {
                    "source": "threat_intel",
                    "detection_rule_id": None,
                    "title": f"Known {first.ioc_type.upper()} indicator matched: {first.ioc_value}",
                    "severity": severity,
                    "matched_event_ids": [e.id for e in matched_events],
                    "entity_username": next((e.username for e in matched_events if e.username), None),
                    "entity_hostname": next((e.hostname for e in matched_events if e.hostname), None),
                },
            )
            summaries.append(
                {
                    "alert_id": alert.id,
                    "ioc_type": first.ioc_type,
                    "ioc_value": first.ioc_value,
                    "matched_event_count": len(matched_events),
                }
            )
            logger.info(
                "threat_intel_alert_created",
                ioc_type=first.ioc_type,
                ioc_value=first.ioc_value,
                matched_event_count=len(matched_events),
                confidence=first.confidence,
            )

        return summaries
