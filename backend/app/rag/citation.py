"""Citation validation (docs — §11: "Do not allow the AI to fabricate
citations"). Pure function: given the chunk IDs a model actually cited and
the chunk IDs that were actually retrieved and shown to it, returns which
citations are valid and which are fabricated — a citation to a chunk_id
that was never in the retrieved context is fabricated by definition,
regardless of how plausible it sounds.

This is the same anti-hallucination pattern app/ai/agent's evidence
grounding uses for event/rule IDs (docs/ai/ai-agent.md §8) applied to RAG
sources specifically.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.rag.retrieval import RetrievedChunk


@dataclass
class CitationValidationResult:
    valid_citations: list[str]
    fabricated_citations: list[str]

    @property
    def all_valid(self) -> bool:
        return not self.fabricated_citations

    @property
    def hallucination_rate(self) -> float:
        """Fraction of cited sources that were fabricated — the metric
        docs/evaluation.md §3 tracks for the agent as a whole; this
        function is what actually computes it for the RAG-citation slice
        of that number."""
        total = len(self.valid_citations) + len(self.fabricated_citations)
        return len(self.fabricated_citations) / total if total else 0.0


def validate_citations(cited_chunk_ids: list[str], retrieved_chunks: list[RetrievedChunk]) -> CitationValidationResult:
    retrieved_ids = {c.chunk_id for c in retrieved_chunks}

    valid = [cid for cid in cited_chunk_ids if cid in retrieved_ids]
    fabricated = [cid for cid in cited_chunk_ids if cid not in retrieved_ids]

    return CitationValidationResult(valid_citations=valid, fabricated_citations=fabricated)


def format_evidence_sources(retrieved_chunks: list[RetrievedChunk]) -> list[str]:
    """Formats retrieved chunks as the "Evidence Sources" list shown to
    the analyst (docs — §11's example: "1. Internal SOC Playbook —
    Authentication Incident"). Only ever called with chunks that were
    actually retrieved — this function has no way to fabricate a source
    that wasn't passed to it, which is the point."""
    return [f"{chunk.document_title} ({chunk.source})" for chunk in retrieved_chunks]
