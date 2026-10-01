"""Positive/negative tests for CLOUD-SECCONTROL-001 (bare `audit_event` condition)."""

from app.detection.executor import evaluate_rule
from app.detection.parser import load_rule
from tests.detection.fixtures import at, make_event

RULE_PATH = "detection-rules/cloud/cloud_disabled_security_control_001.yml"


def _rule() -> dict:
    return load_rule(RULE_PATH)


def test_disable_logging_action_triggers() -> None:
    rule = _rule()
    events = [make_event(at(0), event_type="cloud_audit", action="disable_logging")]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1


def test_remove_mfa_requirement_triggers() -> None:
    rule = _rule()
    events = [make_event(at(0), event_type="cloud_audit", action="remove_mfa_requirement")]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1


def test_unrelated_cloud_audit_action_does_not_trigger() -> None:
    rule = _rule()
    events = [make_event(at(0), event_type="cloud_audit", action="create_snapshot")]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


def test_matching_action_wrong_event_type_does_not_trigger() -> None:
    rule = _rule()
    events = [make_event(at(0), event_type="endpoint", action="disable_logging")]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


if __name__ == "__main__":
    test_disable_logging_action_triggers()
    test_remove_mfa_requirement_triggers()
    test_unrelated_cloud_audit_action_does_not_trigger()
    test_matching_action_wrong_event_type_does_not_trigger()
    print("All CLOUD-SECCONTROL-001 tests passed.")
