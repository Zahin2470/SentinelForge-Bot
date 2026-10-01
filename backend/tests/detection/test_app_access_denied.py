"""Positive/negative tests for APP-ACCESSDENIED-001 (count(denied_response) >= 10)."""

from app.detection.executor import evaluate_rule
from app.detection.parser import load_rule
from tests.detection.fixtures import at, make_event

RULE_PATH = "detection-rules/application/application_repeated_access_denied_001.yml"


def _rule() -> dict:
    return load_rule(RULE_PATH)


def test_ten_denied_responses_triggers() -> None:
    rule = _rule()
    events = [
        make_event(at(i * 0.2), event_type="application_request", status=403, source_ip="203.0.113.5")
        for i in range(10)
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1
    assert len(matched[0].matched_event_ids) == 10


def test_nine_denied_responses_does_not_trigger() -> None:
    rule = _rule()
    events = [
        make_event(at(i * 0.2), event_type="application_request", status=403, source_ip="203.0.113.5")
        for i in range(9)
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


def test_mixed_401_and_403_both_count() -> None:
    """The rule's status filter is [401, 403] — both should count toward
    the threshold together."""
    rule = _rule()
    events = [
        make_event(
            at(i * 0.2),
            event_type="application_request",
            status=401 if i % 2 == 0 else 403,
            source_ip="198.51.100.7",
        )
        for i in range(10)
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1


def test_200_responses_are_ignored() -> None:
    rule = _rule()
    events = [
        make_event(at(i * 0.2), event_type="application_request", status=200, source_ip="203.0.113.5")
        for i in range(20)
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


if __name__ == "__main__":
    test_ten_denied_responses_triggers()
    test_nine_denied_responses_does_not_trigger()
    test_mixed_401_and_403_both_count()
    test_200_responses_are_ignored()
    print("All APP-ACCESSDENIED-001 tests passed.")
