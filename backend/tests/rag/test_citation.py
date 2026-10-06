"""Tests for app.rag.citation — pure functions, no DB needed."""

from app.rag.citation import format_evidence_sources, validate_citations
from app.rag.retrieval import RetrievedChunk


def _chunk(chunk_id, title="Doc", source="playbook"):
    return RetrievedChunk(chunk_id=chunk_id, score=0.8, content="...", document_title=title, source=source)


def test_all_cited_chunks_actually_retrieved_are_valid() -> None:
    retrieved = [_chunk("c1"), _chunk("c2")]
    result = validate_citations(["c1", "c2"], retrieved)

    assert result.valid_citations == ["c1", "c2"]
    assert result.fabricated_citations == []
    assert result.all_valid is True
    assert result.hallucination_rate == 0.0


def test_citation_to_never_retrieved_chunk_is_fabricated() -> None:
    """The core anti-hallucination check: a model claiming a source it was
    never actually given must be caught, no matter how plausible it
    sounds."""
    retrieved = [_chunk("c1")]
    result = validate_citations(["c1", "c99-never-retrieved"], retrieved)

    assert result.valid_citations == ["c1"]
    assert result.fabricated_citations == ["c99-never-retrieved"]
    assert result.all_valid is False


def test_hallucination_rate_computed_correctly() -> None:
    retrieved = [_chunk("c1"), _chunk("c2")]
    result = validate_citations(["c1", "fake1", "fake2"], retrieved)

    assert result.hallucination_rate == 2 / 3


def test_no_citations_at_all_is_not_a_hallucination() -> None:
    result = validate_citations([], [_chunk("c1")])
    assert result.all_valid is True
    assert result.hallucination_rate == 0.0


def test_format_evidence_sources() -> None:
    retrieved = [
        _chunk("c1", title="Brute Force Response Playbook", source="playbook"),
        _chunk("c2", title="MITRE ATT&CK Reference", source="attack"),
    ]
    formatted = format_evidence_sources(retrieved)
    assert formatted == [
        "Brute Force Response Playbook (playbook)",
        "MITRE ATT&CK Reference (attack)",
    ]


def test_format_evidence_sources_never_includes_unretrieved_content() -> None:
    """Structural guarantee, not just a behavioral test: this function
    takes ONLY the retrieved chunks as input — there is no code path by
    which it could format a source that wasn't actually retrieved."""
    retrieved = [_chunk("c1", title="Only This One")]
    formatted = format_evidence_sources(retrieved)
    assert len(formatted) == 1
    assert "Only This One" in formatted[0]


if __name__ == "__main__":
    test_all_cited_chunks_actually_retrieved_are_valid()
    test_citation_to_never_retrieved_chunk_is_fabricated()
    test_hallucination_rate_computed_correctly()
    test_no_citations_at_all_is_not_a_hallucination()
    test_format_evidence_sources()
    test_format_evidence_sources_never_includes_unretrieved_content()
    print("All citation validation tests passed.")
