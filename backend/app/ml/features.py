"""Feature extraction (docs/ml/ml-pipeline.md §3). Pure functions over
plain event dicts (the same shape app.detection.executor consumes) — no
DB, no sklearn — so the exact same code computes features at training time
and at inference time, which is what avoids train/serve skew.

Scope note: docs/ml/ml-pipeline.md §3 lists a fuller feature set than what's
implemented below (e.g. process_frequency, destination_port_frequency,
user/host_behavior_baseline). Those depend on the behavioral-baseline
service that app/detection/executor.py also doesn't have yet (see its
module docstring) — this module implements the subset computable directly
from a window of normalized events, and is honest about the rest in
FEATURE_NAMES / the module below rather than silently omitting them.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

# The feature vector's column order — training and inference must always
# produce columns in this exact order, since IsolationForest has no concept
# of column names, only positions. app/ml/model.py stores this alongside
# the trained model and refuses to score a mismatched feature set.
FEATURE_NAMES = [
    "failed_login_count",
    "successful_login_count",
    "total_events",
    "unique_source_ips",
    "unique_countries",
    "distinct_hostnames",
    "privilege_change_count",
    "night_time_event_ratio",
    "event_rate_per_minute",
]

# Events between 22:00 and 06:00 (entity-local not modeled — UTC used
# throughout, a documented simplification) count toward
# night_time_event_ratio. Real deployments would use each user's actual
# working-hours baseline instead of a fixed band; see the "unusual_hour"
# row in docs/ml/ml-pipeline.md §3 for why this is a stand-in for that.
NIGHT_START_HOUR = 22
NIGHT_END_HOUR = 6


def _is_night(hour: int) -> bool:
    return hour >= NIGHT_START_HOUR or hour < NIGHT_END_HOUR


def extract_entity_features(events: list[dict], window: timedelta) -> dict[str, float]:
    """events: every normalized event for ONE entity within ONE window
    (already filtered by the caller — this function doesn't group or
    window, it only aggregates). Returns a dict keyed by FEATURE_NAMES."""
    if not events:
        return dict.fromkeys(FEATURE_NAMES, 0.0)

    failed_login_count = sum(1 for e in events if e.get("event_type") == "authentication" and e.get("status") == "failure")
    successful_login_count = sum(1 for e in events if e.get("event_type") == "authentication" and e.get("status") == "success")
    total_events = len(events)
    unique_source_ips = len({e["source_ip"] for e in events if e.get("source_ip")})
    unique_countries = len({e["country"] for e in events if e.get("country")})
    distinct_hostnames = len({e["hostname"] for e in events if e.get("hostname")})
    privilege_change_count = sum(1 for e in events if e.get("event_type") == "privilege_modification")
    night_events = sum(1 for e in events if _is_night(e["timestamp"].hour))
    night_time_event_ratio = night_events / total_events
    window_minutes = max(window.total_seconds() / 60.0, 1.0)
    event_rate_per_minute = total_events / window_minutes

    return {
        "failed_login_count": float(failed_login_count),
        "successful_login_count": float(successful_login_count),
        "total_events": float(total_events),
        "unique_source_ips": float(unique_source_ips),
        "unique_countries": float(unique_countries),
        "distinct_hostnames": float(distinct_hostnames),
        "privilege_change_count": float(privilege_change_count),
        "night_time_event_ratio": night_time_event_ratio,
        "event_rate_per_minute": event_rate_per_minute,
    }


def build_feature_table(
    events: list[dict], *, entity_field: str = "username", window: timedelta = timedelta(hours=1)
) -> dict[Any, dict[str, float]]:
    """Groups a batch of events by entity_field (skipping events where it's
    None) and computes one feature dict per entity. This does NOT do time
    windowing itself — the caller is expected to have already scoped
    `events` to the window it wants features computed over (mirrors how
    app.services.detection_service pulls a window before calling the
    detection executor).
    """
    grouped: dict[Any, list[dict]] = defaultdict(list)
    for e in events:
        entity_value = e.get(entity_field)
        if entity_value is None:
            continue
        grouped[entity_value].append(e)

    return {entity: extract_entity_features(entity_events, window) for entity, entity_events in grouped.items()}


def features_to_vector(features: dict[str, float]) -> list[float]:
    """Converts a feature dict to the fixed-order vector IsolationForest
    expects. Raises if a feature is missing rather than silently
    defaulting — a missing feature means extract_entity_features and this
    module's FEATURE_NAMES have drifted apart, which should fail loudly."""
    return [features[name] for name in FEATURE_NAMES]
