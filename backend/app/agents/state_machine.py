"""State machine transitions and resource-limit enforcement
(docs/ai/ai-agent.md §3, §6). Pure functions/small stateful tracker — no
LLM, no DB.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.agents.schemas import ALLOWED_TRANSITIONS, AgentLimits, AgentState


class InvalidTransition(ValueError):
    pass


def validate_transition(current: AgentState, next_state: AgentState) -> None:
    """Raises InvalidTransition unless next_state is FAILED (always
    allowed, from any state) or is in current's allowed-transitions set.
    This is what stops a bug (or a manipulated LLM response) from e.g.
    jumping straight from RECEIVED to COMPLETED, skipping evidence
    collection entirely."""
    if next_state == AgentState.FAILED:
        return
    allowed = ALLOWED_TRANSITIONS.get(current, set())
    if next_state not in allowed:
        raise InvalidTransition(
            f"Cannot transition from {current.value} to {next_state.value}. "
            f"Allowed: {sorted(s.value for s in allowed)}"
        )


class LimitExceeded(RuntimeError):
    """Raised when a hard limit is hit — the orchestrator catches this and
    transitions the run to FAILED with this message as the reason, rather
    than letting the loop continue (docs/ai/ai-agent.md §6: "there is no
    path to an unbounded autonomous loop")."""


@dataclass
class LimitTracker:
    """Tracks resource usage against AgentLimits for one run. A fresh
    instance per AgentRun — never shared across runs/incidents."""

    limits: AgentLimits
    _steps_taken: int = 0
    _tool_calls_made: int = 0
    _retries_used: int = 0
    _started_at: float = field(default_factory=time.time)

    def record_step(self) -> None:
        self._steps_taken += 1
        if self._steps_taken > self.limits.max_steps:
            raise LimitExceeded(f"Exceeded max_steps ({self.limits.max_steps})")

    def record_tool_call(self) -> None:
        self._tool_calls_made += 1
        if self._tool_calls_made > self.limits.max_tool_calls:
            raise LimitExceeded(f"Exceeded max_tool_calls ({self.limits.max_tool_calls})")

    def record_retry(self) -> None:
        self._retries_used += 1
        if self._retries_used > self.limits.max_retries:
            raise LimitExceeded(f"Exceeded max_retries ({self.limits.max_retries})")

    def check_time_budget(self) -> None:
        elapsed = time.time() - self._started_at
        if elapsed > self.limits.max_investigation_seconds:
            raise LimitExceeded(
                f"Exceeded max_investigation_seconds ({self.limits.max_investigation_seconds}), "
                f"elapsed={elapsed:.1f}s"
            )

    @property
    def steps_taken(self) -> int:
        return self._steps_taken

    @property
    def tool_calls_made(self) -> int:
        return self._tool_calls_made
