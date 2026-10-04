"""Tests for app.correlation.engine — pure grouping logic, no DB needed."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from app.correlation.engine import correlate_alerts, group_primary_entity, group_severity

_id_counter = itertools.count(1)


def _alert(minute: float, **fields) -> dict:
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    alert = {
        "id": f"alert-{next(_id_counter)}",
        "created_at": base + timedelta(minutes=minute),
        "entity_username": None,
        "entity_hostname": None,
        "severity": "medium",
    }
    alert.update(fields)
    return alert


def test_alerts_sharing_username_within_window_are_grouped() -> None:
    alerts = [
        _alert(0, entity_username="jdoe", severity="high"),
        _alert(5, entity_username="jdoe", severity="critical"),
    ]

    groups = correlate_alerts(alerts, time_window=timedelta(minutes=30))

    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_alerts_sharing_hostname_within_window_are_grouped() -> None:
    alerts = [
        _alert(0, entity_hostname="corp-dc-01", severity="medium"),
        _alert(10, entity_hostname="corp-dc-01", severity="high"),
    ]

    groups = correlate_alerts(alerts, time_window=timedelta(minutes=30))

    assert len(groups) == 1


def test_alerts_with_no_shared_entity_stay_separate() -> None:
    alerts = [
        _alert(0, entity_username="jdoe", severity="high"),
        _alert(5, entity_username="asmith", severity="high"),
    ]

    groups = correlate_alerts(alerts, time_window=timedelta(minutes=30))

    assert len(groups) == 2
    assert all(len(g) == 1 for g in groups)


def test_alerts_outside_time_window_stay_separate_even_with_same_entity() -> None:
    alerts = [
        _alert(0, entity_username="jdoe", severity="high"),
        _alert(120, entity_username="jdoe", severity="high"),  # 2 hours later
    ]

    groups = correlate_alerts(alerts, time_window=timedelta(minutes=30))

    assert len(groups) == 2


def test_transitive_correlation_chains_across_a_longer_span() -> None:
    """A(t=0) -jdoe- B(t=20) -jdoe- C(t=40): A-C gap is 40min (over the
    30min window) but they chain through B, so all three should group."""
    alerts = [
        _alert(0, entity_username="jdoe", severity="medium"),
        _alert(20, entity_username="jdoe", severity="high"),
        _alert(40, entity_username="jdoe", severity="critical"),
    ]

    groups = correlate_alerts(alerts, time_window=timedelta(minutes=30))

    assert len(groups) == 1
    assert len(groups[0]) == 3


def test_every_alert_appears_in_exactly_one_group_including_singletons() -> None:
    alerts = [
        _alert(0, entity_username="jdoe", severity="high"),
        _alert(5, entity_username="jdoe", severity="high"),
        _alert(200, entity_username="nobody_else_shares_this", severity="low"),
    ]

    groups = correlate_alerts(alerts, time_window=timedelta(minutes=30))
    all_ids = [a["id"] for g in groups for a in g]

    assert sorted(all_ids) == sorted(a["id"] for a in alerts)
    assert len(groups) == 2  # the jdoe pair, plus the lone singleton


def test_empty_input_returns_empty_list() -> None:
    assert correlate_alerts([]) == []


def test_group_severity_takes_the_max_not_the_average() -> None:
    group = [
        {"severity": "low"},
        {"severity": "critical"},
        {"severity": "medium"},
    ]
    assert group_severity(group) == "critical"


def test_group_primary_entity_picks_most_common() -> None:
    group = [
        {"entity_username": "jdoe", "entity_hostname": "host-a"},
        {"entity_username": "jdoe", "entity_hostname": "host-b"},
        {"entity_username": "jdoe", "entity_hostname": "host-a"},
    ]
    entity = group_primary_entity(group)
    assert entity["primary_user"] == "jdoe"
    assert entity["primary_host"] == "host-a"


if __name__ == "__main__":
    test_alerts_sharing_username_within_window_are_grouped()
    test_alerts_sharing_hostname_within_window_are_grouped()
    test_alerts_with_no_shared_entity_stay_separate()
    test_alerts_outside_time_window_stay_separate_even_with_same_entity()
    test_transitive_correlation_chains_across_a_longer_span()
    test_every_alert_appears_in_exactly_one_group_including_singletons()
    test_empty_input_returns_empty_list()
    test_group_severity_takes_the_max_not_the_average()
    test_group_primary_entity_picks_most_common()
    print("All correlation engine tests passed.")
