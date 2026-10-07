"""Tests for app.agents.orchestrator — the main loop, using
MockLLMProvider to script deterministic decision sequences. These exercise
the SAME orchestrator code a real provider would run through; only the
decision source is swapped.
"""

from app.agents.llm_provider import AgentDecision, MockLLMProvider, ProviderUnavailable
from app.agents.orchestrator import run_agent
from app.agents.schemas import AgentLimits, AgentState, ToolCall
from app.agents.tools import build_test_registry


def _minimal_report(**overrides) -> dict:
    base = {
        "classification": "brute_force",
        "severity": "high",
        "confidence": 0.85,
        "summary": "Repeated failed logins followed by a success.",
        "evidence": [],
        "evidence_sources": [],
    }
    base.update(overrides)
    return base


def test_full_happy_path_reaches_completed() -> None:
    registry = build_test_registry({"events": [{"id": "evt-1", "username": "jdoe"}]})

    script = [
        AgentDecision(next_state=AgentState.UNDERSTANDING),
        AgentDecision(
            next_state=AgentState.COLLECTING_EVIDENCE,
            tool_calls=[ToolCall(tool_name="search_security_events", input={"username": "jdoe"})],
        ),
        AgentDecision(next_state=AgentState.CORRELATING),
        AgentDecision(next_state=AgentState.THREAT_INTELLIGENCE_LOOKUP),
        AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),
        AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
        AgentDecision(next_state=AgentState.RISK_ASSESSMENT),
        AgentDecision(next_state=AgentState.REPORT_GENERATION),
        AgentDecision(next_state=AgentState.HUMAN_REVIEW),
        AgentDecision(next_state=AgentState.COMPLETED, final_report=_minimal_report(evidence=["evt-1"])),
    ]
    provider = MockLLMProvider(script)

    result = run_agent("inc-1", registry, provider, actor_role="SOC_ANALYST")

    assert result.succeeded
    assert result.final_state == AgentState.COMPLETED
    assert result.report.classification == "brute_force"
    assert result.total_tool_calls == 1


def test_provider_unavailable_fails_cleanly() -> None:
    """docs/ai/ai-agent.md §9 — degraded mode: a clear failure, not a crash."""

    class AlwaysUnavailable:
        model_name = "unavailable"

        def decide(self, **kwargs):
            raise ProviderUnavailable("no API key configured")

    registry = build_test_registry({})
    result = run_agent("inc-1", registry, AlwaysUnavailable(), actor_role="SOC_ANALYST")

    assert not result.succeeded
    assert result.final_state == AgentState.FAILED
    assert "AI analysis unavailable" in result.failure_reason


def test_invalid_transition_fails_the_run() -> None:
    """A provider (real or manipulated) trying to skip straight to
    COMPLETED must not be allowed to."""
    registry = build_test_registry({})
    provider = MockLLMProvider([AgentDecision(next_state=AgentState.COMPLETED, final_report=_minimal_report())])

    result = run_agent("inc-1", registry, provider, actor_role="SOC_ANALYST")

    assert result.final_state == AgentState.FAILED
    assert "Cannot transition" in result.failure_reason


def test_exceeding_max_steps_fails_the_run() -> None:
    """A script that keeps looping via the one allowed back-edge
    (HYPOTHESIS_VALIDATION <-> HYPOTHESIS_GENERATION) must still be
    stopped by the step limit, not allowed to run forever."""
    registry = build_test_registry({})

    provider = MockLLMProvider(
        [
            AgentDecision(next_state=AgentState.UNDERSTANDING),
            AgentDecision(next_state=AgentState.COLLECTING_EVIDENCE),
            AgentDecision(next_state=AgentState.CORRELATING),
            AgentDecision(next_state=AgentState.THREAT_INTELLIGENCE_LOOKUP),
            AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),
            AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
            AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),  # loop back — allowed by the state graph
            AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
            AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),  # keeps looping...
            AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
            AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),  # ...forever, script exceeds max_steps
            AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
            AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),
        ]
    )

    result = run_agent("inc-1", registry, provider, actor_role="SOC_ANALYST", limits=AgentLimits(max_steps=5))

    assert result.final_state == AgentState.FAILED
    assert "max_steps" in result.failure_reason


def test_report_missing_evidence_is_retried_then_succeeds() -> None:
    """docs/ai/ai-agent.md §8: malformed output is retried, not
    immediately failed."""
    registry = build_test_registry({"events": [{"id": "evt-1"}]})
    script = [
        AgentDecision(next_state=AgentState.UNDERSTANDING),
        AgentDecision(
            next_state=AgentState.COLLECTING_EVIDENCE,
            tool_calls=[ToolCall(tool_name="get_event_by_id", input={"event_id": "evt-1"})],
        ),
        AgentDecision(next_state=AgentState.CORRELATING),
        AgentDecision(next_state=AgentState.THREAT_INTELLIGENCE_LOOKUP),
        AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),
        AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
        AgentDecision(next_state=AgentState.RISK_ASSESSMENT),
        AgentDecision(next_state=AgentState.REPORT_GENERATION),
        AgentDecision(next_state=AgentState.HUMAN_REVIEW),
        # First attempt: empty evidence — invalid, must be retried
        AgentDecision(next_state=AgentState.COMPLETED, final_report=_minimal_report(evidence=[])),
        # Retry path re-enters REPORT_GENERATION -> HUMAN_REVIEW -> COMPLETED,
        # following the normal state graph, this time with corrected evidence
        AgentDecision(next_state=AgentState.HUMAN_REVIEW),
        AgentDecision(next_state=AgentState.COMPLETED, final_report=_minimal_report(evidence=["evt-1"])),
    ]
    provider = MockLLMProvider(script)

    result = run_agent("inc-1", registry, provider, actor_role="SOC_ANALYST", limits=AgentLimits(max_retries=2))

    assert result.succeeded
    assert result.report.evidence == ["evt-1"]


def test_report_with_fabricated_evidence_exhausts_retries_and_fails() -> None:
    registry = build_test_registry({"events": [{"id": "evt-1"}]})
    bad_report = _minimal_report(evidence=["evt-99-fabricated"])
    script = [
        AgentDecision(next_state=AgentState.UNDERSTANDING),
        AgentDecision(
            next_state=AgentState.COLLECTING_EVIDENCE,
            tool_calls=[ToolCall(tool_name="get_event_by_id", input={"event_id": "evt-1"})],
        ),
        AgentDecision(next_state=AgentState.CORRELATING),
        AgentDecision(next_state=AgentState.THREAT_INTELLIGENCE_LOOKUP),
        AgentDecision(next_state=AgentState.HYPOTHESIS_GENERATION),
        AgentDecision(next_state=AgentState.HYPOTHESIS_VALIDATION),
        AgentDecision(next_state=AgentState.RISK_ASSESSMENT),
        AgentDecision(next_state=AgentState.REPORT_GENERATION),
        AgentDecision(next_state=AgentState.HUMAN_REVIEW),
        AgentDecision(next_state=AgentState.COMPLETED, final_report=bad_report),  # attempt 1
        AgentDecision(next_state=AgentState.HUMAN_REVIEW),
        AgentDecision(next_state=AgentState.COMPLETED, final_report=bad_report),  # retry 1
        AgentDecision(next_state=AgentState.HUMAN_REVIEW),
        AgentDecision(next_state=AgentState.COMPLETED, final_report=bad_report),  # retry 2 -> exhausted
    ]
    provider = MockLLMProvider(script)

    result = run_agent(
        "inc-1", registry, provider, actor_role="SOC_ANALYST", limits=AgentLimits(max_retries=2, max_steps=20)
    )

    assert result.final_state == AgentState.FAILED
    assert "fabricated evidence" in result.failure_reason


if __name__ == "__main__":
    test_full_happy_path_reaches_completed()
    test_provider_unavailable_fails_cleanly()
    test_invalid_transition_fails_the_run()
    test_exceeding_max_steps_fails_the_run()
    test_report_missing_evidence_is_retried_then_succeeds()
    test_report_with_fabricated_evidence_exhausts_retries_and_fails()
    print("All orchestrator tests passed.")
