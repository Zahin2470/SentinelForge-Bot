"""Correlation engine (docs/architecture/architecture.md §3-5, Phase 4).

Pure grouping logic, deliberately decoupled from the database — mirrors the
split in app/detection/executor.py: a pure function that's easy to reason
about and test, wired to persistence by app/services/correlation_service.py.

Algorithm: entity + temporal correlation via union-find. Two alerts are
merged into the same group if they share an entity (same username OR same
hostname) AND fall within `time_window` of each other. Merging is
transitive — alert A and alert C can end up in the same incident even if
they're further apart than time_window, as long as a chain of intermediate
alerts (A-B, B-C, each within the window and sharing an entity) connects
them. This mirrors how a real campaign unfolds: an attacker's activity
drifts across a longer span than any single pairwise gap.

This is NOT the same thing as CORRELATION-MULTIHOST-001 (a detection-time
meta-rule over raw events) — this operates one level up, over *alerts*
already produced by rules/ML, deciding which of them belong to the same
incident.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

DEFAULT_CORRELATION_WINDOW = timedelta(minutes=30)


def _shares_entity(a: dict, b: dict) -> bool:
    if a.get("entity_username") and a.get("entity_username") == b.get("entity_username"):
        return True
    if a.get("entity_hostname") and a.get("entity_hostname") == b.get("entity_hostname"):
        return True
    return False


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[rx] = ry


def correlate_alerts(
    alerts: list[dict], time_window: timedelta = DEFAULT_CORRELATION_WINDOW
) -> list[list[dict]]:
    """Groups alerts into candidate incidents.

    Each alert dict must have at least: id, created_at (timezone-aware
    datetime), entity_username, entity_hostname, severity. Returns a list
    of groups (each a list of the original alert dicts); every input alert
    appears in exactly one output group, including singleton groups for
    alerts that don't correlate with anything else — every alert becomes
    (part of) an incident, correlation just decides how they're bundled.
    """
    if not alerts:
        return []

    sorted_alerts = sorted(alerts, key=lambda a: a["created_at"])
    n = len(sorted_alerts)
    uf = _UnionFind(n)

    for i in range(n):
        for j in range(i + 1, n):
            gap = sorted_alerts[j]["created_at"] - sorted_alerts[i]["created_at"]
            if gap > time_window:
                break  # sorted by time — no later j will be within window of i either
            if _shares_entity(sorted_alerts[i], sorted_alerts[j]):
                uf.union(i, j)

    groups: dict[int, list[dict]] = defaultdict(list)
    for i, alert in enumerate(sorted_alerts):
        groups[uf.find(i)].append(alert)

    # Stable, deterministic ordering: earliest-alert-first within each
    # group, groups ordered by their earliest alert.
    ordered_groups = sorted(groups.values(), key=lambda g: g[0]["created_at"])
    return ordered_groups


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def group_severity(group: list[dict]) -> str:
    """An incident's severity is the highest severity among its correlated
    alerts — never averaged down, since one critical alert in a bundle of
    otherwise-low-severity noise still deserves critical-level attention."""
    return max(group, key=lambda a: _SEVERITY_ORDER.get(a.get("severity", "low"), 0))["severity"]


def group_primary_entity(group: list[dict]) -> dict[str, Any]:
    """Picks the most common username/hostname across the group as the
    incident's headline entity — used for the incident title and for the
    asset-criticality risk-score lookup."""
    usernames = [a["entity_username"] for a in group if a.get("entity_username")]
    hostnames = [a["entity_hostname"] for a in group if a.get("entity_hostname")]
    primary_user = max(set(usernames), key=usernames.count) if usernames else None
    primary_host = max(set(hostnames), key=hostnames.count) if hostnames else None
    return {"primary_user": primary_user, "primary_host": primary_host}
