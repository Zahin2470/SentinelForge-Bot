"""Rules that depend on infrastructure that doesn't exist yet (the
behavioral-baseline service, rule-chaining) must come back as
status="unsupported" with a clear reason — never silently return no
matches (which would be indistinguishable from "evaluated and found
nothing") and never raise an unhandled exception."""

from app.detection.executor import evaluate_rule
from app.detection.parser import load_rule
from tests.detection.fixtures import at, make_event


def test_baseline_dependent_rule_reports_unsupported() -> None:
    rule = load_rule("detection-rules/authentication/auth_new_login_ip_002.yml")
    events = [make_event(at(0), event_type="authentication", status="success", username="alice")]

    results = evaluate_rule(rule, events)

    assert len(results) == 1
    assert results[0].status == "unsupported"
    assert not results[0].matched
    assert "baseline" in results[0].reason.lower()


def test_rule_chaining_dependent_rule_reports_unsupported() -> None:
    rule = load_rule("detection-rules/authentication/auth_privilege_change_003.yml")
    events = [make_event(at(0), event_type="privilege_modification", username="alice")]

    results = evaluate_rule(rule, events)

    assert len(results) == 1
    assert results[0].status == "unsupported"
    assert not results[0].matched
    assert "rule-chaining" in results[0].reason.lower() or "chain" in results[0].reason.lower()


def test_frequency_baseline_rule_reports_unsupported() -> None:
    rule = load_rule("detection-rules/network/network_unusual_outbound_001.yml")
    events = [make_event(at(0), event_type="network_connection", direction="outbound", destination_port=4444)]

    results = evaluate_rule(rule, events)

    assert len(results) == 1
    assert results[0].status == "unsupported"
    assert not results[0].matched


if __name__ == "__main__":
    test_baseline_dependent_rule_reports_unsupported()
    test_rule_chaining_dependent_rule_reports_unsupported()
    test_frequency_baseline_rule_reports_unsupported()
    print("All unsupported-condition tests passed.")
