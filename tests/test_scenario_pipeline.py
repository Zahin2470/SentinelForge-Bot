"""End-to-end test of the parts of the pipeline that don't require a live
database: raw scenario events -> app.ingest.normalizer -> app.detection.executor.
This is the strongest test in the repo right now, because it exercises the
same code path simulator/replay.py uses against a real DB, just with the
persistence layer swapped for plain lists — so a passing run here is real
evidence the detection logic is correct end-to-end, not just unit-correct
in isolation.

Run with PYTHONPATH set to both the repo root (for `simulator`) and
backend/ (for `app`):
    PYTHONPATH=.:backend python3 tests/test_scenario_pipeline.py
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (_REPO_ROOT, _REPO_ROOT / "backend"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.correlation.engine import correlate_alerts, group_primary_entity, group_severity  # noqa: E402
from app.detection.executor import evaluate_rule  # noqa: E402
from app.detection.parser import load_rules_from_dir  # noqa: E402
from app.ingest.normalizer import normalize  # noqa: E402
from app.services.risk_scoring import (  # noqa: E402
    compute_risk_score,
    correlation_score_from_group_size,
    rule_score_from_alerts,
    threat_intelligence_score_from_alerts,
)
from app.threat_intel.matcher import find_ioc_matches  # noqa: E402
from app.threat_intel.stix_normalizer import normalize_stix_indicator, UnsupportedStixPattern  # noqa: E402
from simulator.scenarios import get_scenario  # noqa: E402

_id_counter = itertools.count(1)


def _run_scenario_in_memory(scenario_name: str) -> tuple[set[str], set[str]]:
    """Returns (matched_rule_ids, unsupported_rule_ids)."""
    scenario = get_scenario(scenario_name)

    normalized_events = []
    for source_format, raw in scenario.events:
        event = normalize(source_format, raw)
        event["id"] = f"evt-{next(_id_counter)}"
        normalized_events.append(event)

    rules = load_rules_from_dir("detection-rules", only_enabled=True)

    matched_rule_ids: set[str] = set()
    unsupported_rule_ids: set[str] = set()
    for rule in rules:
        if rule["logsource"]["category"] == "correlation":
            continue  # meta-rules are consumed by the correlation engine, not the per-rule executor
        for result in evaluate_rule(rule, normalized_events):
            if result.matched:
                matched_rule_ids.add(result.rule_id)
            elif result.status == "unsupported":
                unsupported_rule_ids.add(result.rule_id)

    return matched_rule_ids, unsupported_rule_ids


def test_brute_force_scenario_matches_ground_truth() -> None:
    scenario = get_scenario("brute_force_privilege_escalation")
    matched, _unsupported = _run_scenario_in_memory("brute_force_privilege_escalation")

    expected = set(scenario.ground_truth["expected_rule_matches"])
    expected_no_match = set(scenario.ground_truth["expected_no_match"])

    assert expected.issubset(matched), f"missing expected matches: {expected - matched}"
    assert not (matched & expected_no_match), f"unexpected matches: {matched & expected_no_match}"


def test_benign_scenario_triggers_nothing() -> None:
    scenario = get_scenario("benign_noise_only")
    matched, _unsupported = _run_scenario_in_memory("benign_noise_only")

    expected_no_match = set(scenario.ground_truth["expected_no_match"])
    assert not (matched & expected_no_match), f"benign scenario unexpectedly matched: {matched}"


def _alerts_from_detection(scenario_name: str) -> list[dict]:
    """Mirrors app.services.detection_service's ORM-to-alert conversion,
    but entirely in memory: normalize -> detect -> build alert dicts ready
    for the correlation engine. This is the same shape
    app/services/correlation_service.py builds from real Alert rows."""
    scenario = get_scenario(scenario_name)

    normalized_events = []
    for source_format, raw in scenario.events:
        event = normalize(source_format, raw)
        event["id"] = f"evt-{next(_id_counter)}"
        normalized_events.append(event)

    return _alerts_from_detection_from_events(normalized_events)


def _alerts_from_detection_from_events(normalized_events: list[dict]) -> list[dict]:
    events_by_id = {e["id"]: e for e in normalized_events}
    rules = load_rules_from_dir("detection-rules", only_enabled=True)

    alerts = []
    for rule in rules:
        if rule["logsource"]["category"] == "correlation":
            continue
        for result in evaluate_rule(rule, normalized_events):
            if not result.matched:
                continue
            matched_events = [events_by_id[eid] for eid in result.matched_event_ids]
            entity_username = next((e["username"] for e in matched_events if e.get("username")), None)
            entity_hostname = next((e["hostname"] for e in matched_events if e.get("hostname")), None)
            # Use the latest matched event's timestamp as the alert's
            # created_at, same as a real alert would be timestamped at
            # the moment the rule fired.
            created_at = max(e["timestamp"] for e in matched_events)
            alerts.append(
                {
                    "id": f"alert-{next(_id_counter)}",
                    "created_at": created_at,
                    "entity_username": entity_username,
                    "entity_hostname": entity_hostname,
                    "severity": result.severity,
                    "rule_id": result.rule_id,
                }
            )
    return alerts


def test_full_pipeline_correlates_brute_force_alerts_into_one_incident() -> None:
    """detection -> correlation -> risk scoring, all in memory, for the
    brute-force scenario: AUTH-BRUTEFORCE-001 and CLOUD-SECCONTROL-001 both
    tie back to user 'jdoe' within the correlation window, so they should
    merge into a single incident with a risk score reflecting both."""
    alerts = _alerts_from_detection("brute_force_privilege_escalation")
    rule_ids = {a["rule_id"] for a in alerts}
    assert rule_ids == {"AUTH-BRUTEFORCE-001", "CLOUD-SECCONTROL-001"}

    groups = correlate_alerts(alerts)
    assert len(groups) == 1, f"expected exactly one correlated incident, got {len(groups)}: {groups}"

    group = groups[0]
    assert len(group) == 2

    entity = group_primary_entity(group)
    assert entity["primary_user"] == "jdoe"

    severity = group_severity(group)
    assert severity == "critical"  # CLOUD-SECCONTROL-001 is critical, AUTH-BRUTEFORCE-001 is high

    rule_score = rule_score_from_alerts([a["severity"] for a in group])
    correlation_score = correlation_score_from_group_size(len(group))
    final_risk_score = compute_risk_score(
        {
            "rule_score": rule_score,
            "anomaly_score": None,
            "correlation_score": correlation_score,
            "threat_intelligence_score": None,
            "asset_criticality_score": None,
            "identity_context_score": None,
        }
    )
    # rule_score=1.0 (critical), correlation_score=0.2 (2 alerts) ->
    # renormalized over weights 0.35 and 0.15: (0.35*1.0 + 0.15*0.2) / 0.5
    assert final_risk_score is not None
    assert abs(final_risk_score - 0.76) < 1e-6


def test_full_pipeline_benign_scenario_produces_no_alerts_to_correlate() -> None:
    alerts = _alerts_from_detection("benign_noise_only")
    assert alerts == []
    assert correlate_alerts(alerts) == []


def _load_sample_iocs() -> list[dict]:
    with open("threat-intel/sample_feed.json") as f:
        bundle = json.load(f)
    iocs = []
    for obj in bundle["objects"]:
        if obj.get("type") != "indicator":
            continue
        try:
            ioc = normalize_stix_indicator(obj)
        except UnsupportedStixPattern:
            continue  # honestly skipped, same as the real import path
        ioc["id"] = obj["id"]
        iocs.append(ioc)
    return iocs


def test_threat_intel_matching_adds_a_third_alert_to_the_same_incident() -> None:
    """Full Phase 3-6 chain in memory: detect -> ML n/a here (needs a
    trained model file) -> threat-intel IOC match -> correlate. The sample
    feed's known-malicious IP indicator (198.51.100.23) is exactly the
    brute-force scenario's attacker IP, so it should produce a third alert
    that correlates into the SAME incident as the rule-sourced alerts
    (same entity: hostname corp-vpn-gw / username jdoe), and
    threat_intelligence_score should be populated as a result."""
    scenario = get_scenario("brute_force_privilege_escalation")

    normalized_events = []
    for source_format, raw in scenario.events:
        event = normalize(source_format, raw)
        event["id"] = f"evt-{next(_id_counter)}"
        normalized_events.append(event)
    events_by_id = {e["id"]: e for e in normalized_events}

    rule_alerts = _alerts_from_detection_from_events(normalized_events)

    iocs = _load_sample_iocs()
    assert len(iocs) == 3  # 3 of 4 sample indicators parse; the 4th is an intentionally unsupported OR pattern

    ioc_matches = find_ioc_matches(normalized_events, iocs)
    assert len(ioc_matches) >= 1, "expected the sample feed's known attacker IP to match the scenario"

    ti_alert_events = [events_by_id[m.event_id] for m in ioc_matches]
    ti_alert = {
        "id": "alert-threat-intel-1",
        "created_at": max(e["timestamp"] for e in ti_alert_events),
        "entity_username": next((e["username"] for e in ti_alert_events if e.get("username")), None),
        "entity_hostname": next((e["hostname"] for e in ti_alert_events if e.get("hostname")), None),
        "severity": "critical",  # the matched indicator's threat_level is "high" -> critical severity
        "source": "threat_intel",
    }

    all_alerts = [{**a, "source": "rule"} for a in rule_alerts] + [ti_alert]
    groups = correlate_alerts(all_alerts)

    assert len(groups) == 1, f"expected the threat-intel alert to join the existing incident, got {len(groups)} groups"
    group = groups[0]
    assert len(group) == 3

    ti_score = threat_intelligence_score_from_alerts(group)
    assert ti_score is not None
    assert ti_score == 1.0  # severity_to_score("critical")


if __name__ == "__main__":
    test_brute_force_scenario_matches_ground_truth()
    test_benign_scenario_triggers_nothing()
    test_full_pipeline_correlates_brute_force_alerts_into_one_incident()
    test_full_pipeline_benign_scenario_produces_no_alerts_to_correlate()
    test_threat_intel_matching_adds_a_third_alert_to_the_same_incident()
    print("All end-to-end scenario pipeline tests passed.")
