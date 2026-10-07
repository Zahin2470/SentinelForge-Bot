"""Evidence grounding (docs/ai/ai-agent.md §8: "every claim must trace
back to a real event ID, rule ID, or retrieved document ID that was
actually returned by a tool call in that run — the model cannot cite a
source it wasn't given"). This is app.rag.citation's validation pattern
generalized from RAG chunk IDs to every kind of evidence ID the agent can
cite: security events, detection rules, IOCs, and knowledge-base chunks.

Pure function over ToolResult records — no DB, no LLM.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.agents.schemas import InvestigationReport, ToolResult


@dataclass
class GroundingResult:
    grounded_evidence: list[str]
    fabricated_evidence: list[str]
    grounded_sources: list[str]
    fabricated_sources: list[str]

    @property
    def is_fully_grounded(self) -> bool:
        return not self.fabricated_evidence and not self.fabricated_sources

    @property
    def hallucination_rate(self) -> float:
        """The metric docs/evaluation.md §3 tracks for the agent as a
        whole ("fraction of cited evidence IDs that actually exist in the
        tool results returned during that run")."""
        total = len(self.grounded_evidence) + len(self.fabricated_evidence)
        return len(self.fabricated_evidence) / total if total else 0.0


def collect_evidence_ids(tool_results: list[ToolResult]) -> set[str]:
    """The full set of IDs this run is allowed to cite — the union of
    every successful tool call's evidence_ids. A failed or unauthorized
    tool call contributes nothing: if a tool call was denied, whatever the
    model might have hoped to find there was never actually shown to it."""
    ids: set[str] = set()
    for result in tool_results:
        if result.success and result.authorized:
            ids.update(result.evidence_ids)
    return ids


def validate_report_grounding(report: InvestigationReport, tool_results: list[ToolResult]) -> GroundingResult:
    """Checks both `evidence` (event/rule/IOC IDs) and `evidence_sources`
    (formatted RAG citations, e.g. "Brute Force Response Playbook
    (playbook)") against what the run's tool calls actually surfaced.
    evidence_sources are checked by substring/membership against the
    formatted source strings collected from knowledge-search tool results,
    since that field is human-readable text, not a raw ID.
    """
    available_ids = collect_evidence_ids(tool_results)
    available_sources: set[str] = set()
    for result in tool_results:
        if result.success and result.authorized:
            sources = result.output.get("evidence_sources")
            if sources:
                available_sources.update(sources)

    grounded_evidence = [e for e in report.evidence if e in available_ids]
    fabricated_evidence = [e for e in report.evidence if e not in available_ids]

    grounded_sources = [s for s in report.evidence_sources if s in available_sources]
    fabricated_sources = [s for s in report.evidence_sources if s not in available_sources]

    return GroundingResult(
        grounded_evidence=grounded_evidence,
        fabricated_evidence=fabricated_evidence,
        grounded_sources=grounded_sources,
        fabricated_sources=fabricated_sources,
    )
