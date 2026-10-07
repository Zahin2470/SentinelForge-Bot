"""Core agent data structures (docs/ai/ai-agent.md §3, §8).

Plain dataclasses, not Pydantic — consistent with every other pure engine
module in this repo (app.detection.executor.DetectionResult,
app.correlation.engine, app.ml.model.TrainedModelMetadata): the
orchestration logic in app/agents/ needs to be importable and testable
without pydantic/fastapi/sqlalchemy installed. The API layer
(app/api/agent.py, not yet built) would define Pydantic
request/response schemas that convert to/from these at the boundary, the
same pattern app/api/incidents.py already uses for
app.correlation.engine's output.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AgentState(str, Enum):
    RECEIVED = "RECEIVED"
    UNDERSTANDING = "UNDERSTANDING"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    CORRELATING = "CORRELATING"
    THREAT_INTELLIGENCE_LOOKUP = "THREAT_INTELLIGENCE_LOOKUP"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    HYPOTHESIS_VALIDATION = "HYPOTHESIS_VALIDATION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    REPORT_GENERATION = "REPORT_GENERATION"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# The state machine's allowed transitions (docs/ai/ai-agent.md §3). Every
# state can also transition directly to FAILED (a tool error, a validation
# failure, a limit being hit) — that's handled separately in the
# orchestrator rather than listed on every row here, since "anything can
# fail" would make this table mostly noise.
ALLOWED_TRANSITIONS: dict[AgentState, set[AgentState]] = {
    AgentState.RECEIVED: {AgentState.UNDERSTANDING},
    AgentState.UNDERSTANDING: {AgentState.COLLECTING_EVIDENCE},
    AgentState.COLLECTING_EVIDENCE: {AgentState.CORRELATING},
    AgentState.CORRELATING: {AgentState.THREAT_INTELLIGENCE_LOOKUP},
    AgentState.THREAT_INTELLIGENCE_LOOKUP: {AgentState.HYPOTHESIS_GENERATION},
    AgentState.HYPOTHESIS_GENERATION: {AgentState.HYPOTHESIS_VALIDATION},
    AgentState.HYPOTHESIS_VALIDATION: {AgentState.RISK_ASSESSMENT, AgentState.HYPOTHESIS_GENERATION},
    AgentState.RISK_ASSESSMENT: {AgentState.REPORT_GENERATION},
    AgentState.REPORT_GENERATION: {AgentState.HUMAN_REVIEW},
    AgentState.HUMAN_REVIEW: {AgentState.COMPLETED},
    AgentState.COMPLETED: set(),
    AgentState.FAILED: set(),
}


@dataclass
class AgentLimits:
    """Hard, not advisory (docs/ai/ai-agent.md §6)."""

    max_steps: int = 12
    max_tool_calls: int = 20
    max_retries: int = 2
    max_investigation_seconds: int = 120


@dataclass
class ToolCall:
    tool_name: str
    input: dict[str, Any]
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ToolResult:
    call_id: str
    tool_name: str
    authorized: bool
    success: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    # Every event/rule/chunk/IOC ID this tool result actually surfaced —
    # the evidence-grounding validator (app/agents/evidence.py) only ever
    # accepts a citation if it appears in the union of every ToolResult's
    # evidence_ids across the whole run.
    evidence_ids: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass
class AttackMapping:
    technique_id: str
    technique_name: str


@dataclass
class InvestigationReport:
    """Matches the structured output contract in docs/ai/ai-agent.md §8."""

    classification: str
    severity: str
    confidence: float
    summary: str
    evidence: list[str] = field(default_factory=list)
    detection_contributions: list[str] = field(default_factory=list)
    ml_anomaly_score: float | None = None
    attack_mapping: list[AttackMapping] = field(default_factory=list)
    alternative_explanations: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    human_approval_statement: str = (
        "No automatic containment action was executed. Human analyst "
        "approval is required for operational response."
    )

    def validate(self) -> list[str]:
        """Structural validation (docs/ai/ai-agent.md §8 — "malformed
        output is retried... then the run fails cleanly"). Returns a list
        of problems; empty means valid. Deliberately NOT raising on the
        first problem, so a caller can log/retry with the full picture of
        what's wrong rather than one field at a time."""
        problems: list[str] = []
        if self.severity not in ("low", "medium", "high", "critical"):
            problems.append(f"invalid severity: {self.severity!r}")
        if not 0.0 <= self.confidence <= 1.0:
            problems.append(f"confidence out of range [0,1]: {self.confidence!r}")
        if not self.classification.strip():
            problems.append("classification must not be empty")
        if not self.summary.strip():
            problems.append("summary must not be empty")
        if not self.evidence:
            problems.append("evidence must not be empty — a report with no cited evidence is not grounded")
        return problems


@dataclass
class AgentStepRecord:
    step_index: int
    state: AgentState
    tool_calls: list[ToolResult] = field(default_factory=list)
    summary: str = ""
    started_at: float = field(default_factory=time.time)
    latency_ms: float = 0.0


@dataclass
class AgentRunResult:
    run_id: str
    incident_id: str
    final_state: AgentState
    steps: list[AgentStepRecord] = field(default_factory=list)
    report: InvestigationReport | None = None
    failure_reason: str | None = None
    total_tool_calls: int = 0

    @property
    def succeeded(self) -> bool:
        return self.final_state == AgentState.COMPLETED and self.report is not None
