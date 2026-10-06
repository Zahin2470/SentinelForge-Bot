"""Tests for app.rag.chunking — pure functions, no DB needed. Also chunks
every real document in knowledge-base/ to catch quality regressions on
actual content, not just hand-built fixtures.
"""

from pathlib import Path

from app.rag.chunking import MAX_CHUNK_CHARS, MIN_CHUNK_CHARS, chunk_document


def test_short_document_becomes_one_chunk() -> None:
    text = "# Title\n\n## Section\n\nJust a short paragraph here."
    chunks = chunk_document(text)
    assert len(chunks) == 1
    assert "Just a short paragraph" in chunks[0].content


def test_splits_on_h2_headers() -> None:
    text = (
        "# Doc Title\n\n"
        "## First Section\n\n"
        "Content of the first section, long enough to matter for retrieval.\n\n"
        "## Second Section\n\n"
        "Content of the second section, also long enough to matter."
    )
    chunks = chunk_document(text)
    assert len(chunks) == 2
    assert chunks[0].section_title == "First Section"
    assert chunks[1].section_title == "Second Section"
    assert "first section" in chunks[0].content.lower()
    assert "second section" in chunks[1].content.lower()


def test_h1_title_is_not_its_own_chunk() -> None:
    text = "# Just A Title\n\n## Real Section\n\nActual content lives here, not in the title."
    chunks = chunk_document(text)
    assert len(chunks) == 1
    assert chunks[0].section_title == "Real Section"


def test_header_only_section_merges_forward_not_standalone() -> None:
    """An H2 with no body before the next header (an 'umbrella' heading
    for subsections) must not become its own near-empty chunk."""
    text = (
        "# Title\n\n"
        "## Umbrella Heading\n\n"
        "### First Subsection\n\n"
        "Real content for the first subsection, long enough to be meaningful.\n\n"
        "### Second Subsection\n\n"
        "Real content for the second subsection, long enough to be meaningful."
    )
    chunks = chunk_document(text)
    assert len(chunks) == 2
    assert "umbrella heading" in chunks[0].content.lower()  # folded into the first subsection
    assert "first subsection" in chunks[0].content.lower()


def test_no_chunk_exceeds_max_chars() -> None:
    long_paragraph = "This is a long sentence about security. " * 60  # way over MAX_CHUNK_CHARS
    text = f"# Title\n\n## Section\n\n{long_paragraph}"
    chunks = chunk_document(text)
    assert all(len(c.content) <= MAX_CHUNK_CHARS for c in chunks)
    assert len(chunks) > 1  # had to actually split


def test_empty_document_returns_no_chunks() -> None:
    assert chunk_document("") == []
    assert chunk_document("   \n\n  ") == []


def test_document_with_no_headers_still_chunks() -> None:
    text = "Just some plain text with no markdown headers at all, describing a security concept."
    chunks = chunk_document(text)
    assert len(chunks) == 1
    assert chunks[0].section_title is None


def test_chunk_indices_are_sequential() -> None:
    text = "# T\n\n## A\n\nContent A.\n\n## B\n\nContent B.\n\n## C\n\nContent C."
    chunks = chunk_document(text)
    assert [c.index for c in chunks] == list(range(len(chunks)))


def test_all_real_knowledge_base_documents_chunk_without_error() -> None:
    """Chunks every actual file in knowledge-base/ — catches quality
    regressions on real content, not just synthetic fixtures."""
    kb_dir = Path("knowledge-base")
    md_files = list(kb_dir.rglob("*.md"))
    assert len(md_files) >= 6, "expected at least the 6 knowledge-base documents written for Phase 7"

    for path in md_files:
        text = path.read_text()
        chunks = chunk_document(text)
        assert len(chunks) >= 1, f"{path} produced zero chunks"
        for c in chunks:
            assert len(c.content) <= MAX_CHUNK_CHARS, f"{path} chunk {c.index} exceeds MAX_CHUNK_CHARS"
            assert len(c.content.strip()) >= MIN_CHUNK_CHARS or len(chunks) == 1, (
                f"{path} chunk {c.index} is suspiciously short and should have been merged: {c.content!r}"
            )


if __name__ == "__main__":
    test_short_document_becomes_one_chunk()
    test_splits_on_h2_headers()
    test_h1_title_is_not_its_own_chunk()
    test_header_only_section_merges_forward_not_standalone()
    test_no_chunk_exceeds_max_chars()
    test_empty_document_returns_no_chunks()
    test_document_with_no_headers_still_chunks()
    test_chunk_indices_are_sequential()
    test_all_real_knowledge_base_documents_chunk_without_error()
    print("All chunking tests passed.")
