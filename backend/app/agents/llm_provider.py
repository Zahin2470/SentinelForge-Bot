"""LLM provider abstraction (docs/ai/ai-agent.md §2). The agent orchestrator
only ever talks to this interface, never to a specific vendor SDK
directly — this is what makes MockLLMProvider a genuine substitute for a
real model in tests, not just a stub that happens to share a name.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

from app.agents.schemas import AgentState, ToolCall, ToolResult


@dataclass
class AgentDecision:
    """What the LLM provider returns each step: either one or more tool
    calls to make, or a final answer (an investigation report as a raw
    dict, validated by the orchestrator against InvestigationReport)."""

    next_state: AgentState
    tool_calls: list[ToolCall] | None = None
    final_report: dict[str, Any] | None = None
    reasoning_summary: str = ""


class LLMProvider(ABC):
    @abstractmethod
    def decide(
        self,
        *,
        state: AgentState,
        incident_context: dict[str, Any],
        tool_results_so_far: list[ToolResult],
    ) -> AgentDecision:
        """Given the current state and everything gathered so far, decide
        the next action. Real providers construct a prompt with the
        SYSTEM/USER/DATA sections kept explicitly separate
        (docs/ai/ai-agent.md §5) and parse the model's response into an
        AgentDecision; this interface hides that entirely from the
        orchestrator."""

    @property
    @abstractmethod
    def model_name(self) -> str: ...


class ProviderUnavailable(RuntimeError):
    """Raised by a real provider when no API key is configured or the
    provider call fails — the degraded-mode signal
    (docs/ai/ai-agent.md §9: "the API returns a clear 'AI analysis
    unavailable' response rather than failing silently")."""


class AnthropicProvider(LLMProvider):
    """Structural stub: this is what a real integration looks like, not a
    placeholder that pretends to work. Requires network access and an API
    key, so it's untested in this offline dev environment by necessity —
    same honest limitation as every other network-dependent piece of this
    repo. A real implementation would construct the SYSTEM/USER/DATA
    prompt sections (docs/ai/ai-agent.md §5), call the Anthropic Messages
    API with tool-use enabled, and parse tool_use blocks into ToolCalls or
    a final text/JSON block into a report dict.
    """

    def __init__(self, model: str, api_key: str) -> None:
        if not api_key:
            raise ProviderUnavailable("ANTHROPIC_API_KEY not configured")
        self._model = model
        self._api_key = api_key

    @property
    def model_name(self) -> str:
        return self._model

    def decide(self, *, state, incident_context, tool_results_so_far) -> AgentDecision:  # noqa: ARG002
        raise ProviderUnavailable(
            "AnthropicProvider requires network access to the Anthropic API, "
            "not available in this offline dev environment."
        )


class OpenAIProvider(LLMProvider):
    """Same honest-stub status as AnthropicProvider — see its docstring."""

    def __init__(self, model: str, api_key: str) -> None:
        if not api_key:
            raise ProviderUnavailable("OPENAI_API_KEY not configured")
        self._model = model
        self._api_key = api_key

    @property
    def model_name(self) -> str:
        return self._model

    def decide(self, *, state, incident_context, tool_results_so_far) -> AgentDecision:  # noqa: ARG002
        raise ProviderUnavailable("OpenAIProvider requires network access, not available here.")


class LocalProvider(LLMProvider):
    """For a locally-hosted model (e.g. via Ollama/vLLM) — same interface,
    would call a local HTTP endpoint instead of a cloud API. Stubbed for
    the same reason: no such endpoint exists in this dev environment."""

    def __init__(self, model: str, base_url: str) -> None:
        self._model = model
        self._base_url = base_url

    @property
    def model_name(self) -> str:
        return self._model

    def decide(self, *, state, incident_context, tool_results_so_far) -> AgentDecision:  # noqa: ARG002
        raise ProviderUnavailable(f"LocalProvider requires a reachable endpoint at {self._base_url}.")


class MockLLMProvider(LLMProvider):
    """A genuinely deterministic, scriptable provider — not a random
    stand-in. Tests hand it a `script`: a list of AgentDecision-producing
    callables (or plain AgentDecision objects), one per call to decide().
    This is what makes it possible to run the FULL agent orchestration
    loop — state transitions, tool dispatch, authorization, evidence
    grounding, output validation — end-to-end in this environment without
    any network access, exercising exactly the same orchestrator code path
    a real provider would run through.
    """

    def __init__(self, script: list[AgentDecision | Callable[..., AgentDecision]], model_name: str = "mock-v1") -> None:
        self._script = list(script)
        self._call_index = 0
        self._model_name = model_name

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def calls_made(self) -> int:
        return self._call_index

    def decide(
        self, *, state: AgentState, incident_context: dict[str, Any], tool_results_so_far: list[ToolResult]
    ) -> AgentDecision:
        if self._call_index >= len(self._script):
            raise ProviderUnavailable(
                f"MockLLMProvider script exhausted after {self._call_index} calls — "
                "the orchestrator asked for more decisions than the test scripted."
            )
        entry = self._script[self._call_index]
        self._call_index += 1

        if callable(entry) and not isinstance(entry, AgentDecision):
            return entry(state=state, incident_context=incident_context, tool_results_so_far=tool_results_so_far)
        return entry
