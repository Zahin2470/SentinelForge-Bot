"""The agent orchestration loop (docs/ai/ai-agent.md §3, §6, §8).

LLM → Agent tool (authorized, audited) → structured, evidence-grounded
output — never a bare "analyze this" prompt with no structure, never an
unbounded loop, never an unvalidated report. This module is where every
other piece in app/agents/ actually gets wired together and run.
"""

from __future__ import annotations

import uuid

from app.agents.evidence import validate_report_grounding
from app.agents.llm_provider import LLMProvider, ProviderUnavailable
from app.agents.schemas import (
    AgentLimits,
    AgentRunResult,
    AgentState,
    AgentStepRecord,
    AttackMapping,
    InvestigationReport,
    ToolResult,
)
from app.agents.state_machine import InvalidTransition, LimitExceeded, LimitTracker, validate_transition
from app.agents.tools import ToolRegistry


def _build_report(data: dict) -> InvestigationReport:
    attack_mapping = [
        AttackMapping(technique_id=m["technique_id"], technique_name=m["technique_name"])
        for m in data.get("attack_mapping", [])
    ]
    kwargs = {k: v for k, v in data.items() if k != "attack_mapping"}
    return InvestigationReport(attack_mapping=attack_mapping, **kwargs)


def run_agent(
    incident_id: str,
    tool_registry: ToolRegistry,
    llm_provider: LLMProvider,
    *,
    actor_role: str,
    limits: AgentLimits | None = None,
    incident_context: dict | None = None,
) -> AgentRunResult:
    """Runs one investigation to completion or failure. Never raises —
    every failure mode (a real LLMProvider being unavailable, a limit
    being hit, an invalid transition, a report that fails validation or
    evidence-grounding even after retries) becomes a FAILED
    AgentRunResult with a clear failure_reason, matching
    docs/ai/ai-agent.md §9's degraded-mode philosophy: fail clearly, don't
    crash the caller.
    """
    run_id = str(uuid.uuid4())
    limits = limits or AgentLimits()
    tracker = LimitTracker(limits=limits)
    state = AgentState.RECEIVED
    steps: list[AgentStepRecord] = []
    all_tool_results: list[ToolResult] = []
    incident_context = incident_context or {}

    def fail(reason: str) -> AgentRunResult:
        steps.append(AgentStepRecord(step_index=len(steps), state=AgentState.FAILED, summary=reason))
        return AgentRunResult(
            run_id=run_id,
            incident_id=incident_id,
            final_state=AgentState.FAILED,
            steps=steps,
            failure_reason=reason,
            total_tool_calls=tracker.tool_calls_made,
        )

    try:
        while True:
            tracker.record_step()
            tracker.check_time_budget()

            try:
                decision = llm_provider.decide(
                    state=state, incident_context=incident_context, tool_results_so_far=all_tool_results
                )
            except ProviderUnavailable as exc:
                return fail(f"AI analysis unavailable: {exc}")

            validate_transition(state, decision.next_state)
            state = decision.next_state

            step_tool_results: list[ToolResult] = []
            if decision.tool_calls:
                for tc in decision.tool_calls:
                    tracker.record_tool_call()
                    result = tool_registry.call(tc, actor_role=actor_role)
                    step_tool_results.append(result)
                    all_tool_results.append(result)

            steps.append(
                AgentStepRecord(
                    step_index=len(steps),
                    state=state,
                    tool_calls=step_tool_results,
                    summary=decision.reasoning_summary,
                )
            )

            if state == AgentState.FAILED:
                return fail(decision.reasoning_summary or "Model signaled failure")

            if state == AgentState.COMPLETED:
                if decision.final_report is None:
                    return fail("Reached COMPLETED with no final_report attached")

                report = _build_report(decision.final_report)
                problems = report.validate()
                grounding = validate_report_grounding(report, all_tool_results) if not problems else None

                if not problems and grounding is not None and grounding.is_fully_grounded:
                    return AgentRunResult(
                        run_id=run_id,
                        incident_id=incident_id,
                        final_state=AgentState.COMPLETED,
                        steps=steps,
                        report=report,
                        total_tool_calls=tracker.tool_calls_made,
                    )

                # Malformed or ungrounded — retry (docs/ai/ai-agent.md §8:
                # "retried up to MAX_RETRIES, then the run fails cleanly
                # rather than showing invalid or partially-fabricated
                # content"). Stay at REPORT_GENERATION and ask again.
                reason = (
                    "; ".join(problems)
                    if problems
                    else f"fabricated evidence: {grounding.fabricated_evidence + grounding.fabricated_sources}"
                )
                try:
                    tracker.record_retry()
                except LimitExceeded as exc:
                    return fail(f"Report failed validation after max retries ({reason}): {exc}")

                state = AgentState.REPORT_GENERATION
                continue

    except (LimitExceeded, InvalidTransition) as exc:
        return fail(str(exc))
