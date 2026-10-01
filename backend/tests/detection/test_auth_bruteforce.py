"""Positive/negative tests for AUTH-BRUTEFORCE-001
(count(failed_login) >= 5 followed_by successful_login), per
docs/detection-engine.md §5 — every rule needs one case that must trigger
and one close-but-not-matching case that must not.
"""

from app.detection.executor import evaluate_rule
from app.detection.parser import load_rule
from tests.detection.fixtures import at, make_event

RULE_PATH = "detection-rules/authentication/auth_bruteforce_001.yml"


def _rule() -> dict:
    return load_rule(RULE_PATH)


def test_five_failed_logins_then_success_triggers() -> None:
    rule = _rule()
    events = [
        make_event(at(0), event_type="authentication", status="failure", username="alice", source_ip="1.2.3.4"),
        make_event(at(1), event_type="authentication", status="failure", username="alice", source_ip="1.2.3.4"),
        make_event(at(2), event_type="authentication", status="failure", username="alice", source_ip="1.2.3.4"),
        make_event(at(3), event_type="authentication", status="failure", username="alice", source_ip="1.2.3.4"),
        make_event(at(4), event_type="authentication", status="failure", username="alice", source_ip="1.2.3.4"),
        make_event(at(5), event_type="authentication", status="success", username="alice", source_ip="1.2.3.4"),
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1
    assert matched[0].rule_id == "AUTH-BRUTEFORCE-001"
    assert len(matched[0].matched_event_ids) == 6  # 5 failures + 1 success
    assert matched[0].group_key == ("alice", "1.2.3.4")


def test_four_failed_logins_then_success_does_not_trigger() -> None:
    """One short of the threshold — must NOT trigger."""
    rule = _rule()
    events = [
        make_event(at(0), event_type="authentication", status="failure", username="bob", source_ip="5.6.7.8"),
        make_event(at(1), event_type="authentication", status="failure", username="bob", source_ip="5.6.7.8"),
        make_event(at(2), event_type="authentication", status="failure", username="bob", source_ip="5.6.7.8"),
        make_event(at(3), event_type="authentication", status="failure", username="bob", source_ip="5.6.7.8"),
        make_event(at(4), event_type="authentication", status="success", username="bob", source_ip="5.6.7.8"),
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


def test_five_failed_logins_no_success_does_not_trigger() -> None:
    """Threshold reached but no success ever follows — must NOT trigger."""
    rule = _rule()
    events = [
        make_event(at(i), event_type="authentication", status="failure", username="carol", source_ip="9.9.9.9")
        for i in range(5)
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


def test_failed_logins_from_different_users_do_not_combine() -> None:
    """group_by is [username, source_ip] — failures split across different
    users at the same IP must not be combined into one match."""
    rule = _rule()
    events = []
    for i, user in enumerate(["u1", "u2", "u3", "u4", "u5"]):
        events.append(
            make_event(
                at(i), event_type="authentication", status="failure", username=user, source_ip="10.0.0.1"
            )
        )
    events.append(
        make_event(at(6), event_type="authentication", status="success", username="u1", source_ip="10.0.0.1")
    )

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


def test_success_outside_timeframe_does_not_trigger() -> None:
    """5 failures within the window, but the success comes after the
    10-minute timeframe has elapsed — must NOT trigger."""
    rule = _rule()
    events = [
        make_event(at(0), event_type="authentication", status="failure", username="dave", source_ip="1.1.1.1"),
        make_event(at(1), event_type="authentication", status="failure", username="dave", source_ip="1.1.1.1"),
        make_event(at(2), event_type="authentication", status="failure", username="dave", source_ip="1.1.1.1"),
        make_event(at(3), event_type="authentication", status="failure", username="dave", source_ip="1.1.1.1"),
        make_event(at(4), event_type="authentication", status="failure", username="dave", source_ip="1.1.1.1"),
        make_event(at(20), event_type="authentication", status="success", username="dave", source_ip="1.1.1.1"),
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


if __name__ == "__main__":
    # Allows `python3 tests/detection/test_auth_bruteforce.py` to run these
    # directly without pytest installed, for quick local sanity checks.
    test_five_failed_logins_then_success_triggers()
    test_four_failed_logins_then_success_does_not_trigger()
    test_five_failed_logins_no_success_does_not_trigger()
    test_failed_logins_from_different_users_do_not_combine()
    test_success_outside_timeframe_does_not_trigger()
    print("All AUTH-BRUTEFORCE-001 tests passed.")
