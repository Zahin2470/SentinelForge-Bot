"""Tests for app.agents.state_machine — pure, no DB/LLM needed."""

from app.agents.schemas import AgentLimits, AgentState
from app.agents.state_machine import InvalidTransition, LimitExceeded, LimitTracker, validate_transition


def test_valid_forward_transition_does_not_raise() -> None:
    validate_transition(AgentState.RECEIVED, AgentState.UNDERSTANDING)
    validate_transition(AgentState.COLLECTING_EVIDENCE, AgentState.CORRELATING)


def test_skipping_states_raises() -> None:
    try:
        validate_transition(AgentState.RECEIVED, AgentState.COMPLETED)
        raise AssertionError("expected InvalidTransition")
    except InvalidTransition:
        pass


def test_transition_to_failed_always_allowed() -> None:
    for state in AgentState:
        if state == AgentState.FAILED:
            continue
        validate_transition(state, AgentState.FAILED)  # must never raise


def test_hypothesis_validation_can_loop_back_to_generation() -> None:
    """The one intentional back-edge in the state machine — a hypothesis
    that doesn't validate should be able to trigger generating a new one,
    not force the whole investigation to fail."""
    validate_transition(AgentState.HYPOTHESIS_VALIDATION, AgentState.HYPOTHESIS_GENERATION)


def test_terminal_states_allow_no_further_transitions_except_failed_noop() -> None:
    try:
        validate_transition(AgentState.COMPLETED, AgentState.UNDERSTANDING)
        raise AssertionError("expected InvalidTransition")
    except InvalidTransition:
        pass


def test_limit_tracker_steps() -> None:
    tracker = LimitTracker(limits=AgentLimits(max_steps=3))
    tracker.record_step()
    tracker.record_step()
    tracker.record_step()
    try:
        tracker.record_step()
        raise AssertionError("expected LimitExceeded")
    except LimitExceeded:
        pass


def test_limit_tracker_tool_calls() -> None:
    tracker = LimitTracker(limits=AgentLimits(max_tool_calls=2))
    tracker.record_tool_call()
    tracker.record_tool_call()
    try:
        tracker.record_tool_call()
        raise AssertionError("expected LimitExceeded")
    except LimitExceeded:
        pass


def test_limit_tracker_retries() -> None:
    tracker = LimitTracker(limits=AgentLimits(max_retries=1))
    tracker.record_retry()
    try:
        tracker.record_retry()
        raise AssertionError("expected LimitExceeded")
    except LimitExceeded:
        pass


def test_limit_tracker_time_budget() -> None:
    import time

    tracker = LimitTracker(limits=AgentLimits(max_investigation_seconds=0))
    time.sleep(0.01)
    try:
        tracker.check_time_budget()
        raise AssertionError("expected LimitExceeded")
    except LimitExceeded:
        pass


def test_limit_tracker_counters_are_independent_per_instance() -> None:
    """A fresh LimitTracker per run — using one instance's counters must
    never leak into another run's budget."""
    t1 = LimitTracker(limits=AgentLimits(max_steps=1))
    t2 = LimitTracker(limits=AgentLimits(max_steps=5))
    t1.record_step()
    t2.record_step()
    t2.record_step()
    assert t1.steps_taken == 1
    assert t2.steps_taken == 2


if __name__ == "__main__":
    test_valid_forward_transition_does_not_raise()
    test_skipping_states_raises()
    test_transition_to_failed_always_allowed()
    test_hypothesis_validation_can_loop_back_to_generation()
    test_terminal_states_allow_no_further_transitions_except_failed_noop()
    test_limit_tracker_steps()
    test_limit_tracker_tool_calls()
    test_limit_tracker_retries()
    test_limit_tracker_time_budget()
    test_limit_tracker_counters_are_independent_per_instance()
    print("All state machine tests passed.")
