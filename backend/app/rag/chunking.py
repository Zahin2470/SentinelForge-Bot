"""Chunking (docs — §11 "documents → chunking → metadata extraction →
embedding generation"). Pure functions over plain text — no DB, no
embedding provider — so chunking logic is testable and reviewable in
isolation from everything downstream of it.

Chunks along markdown section boundaries (## headers) rather than a fixed
character count where possible: a knowledge-base document like
brute-force-response.md is written in clearly delineated steps, and
splitting mid-step would hand the retriever (and ultimately the LLM)
fragments that don't stand on their own. Falls back to fixed-size
splitting with overlap for any section that's still too long after
header-splitting, so no chunk exceeds MAX_CHUNK_CHARS regardless of the
source document's structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_CHUNK_CHARS = 1200
CHUNK_OVERLAP_CHARS = 150
MIN_CHUNK_CHARS = 40  # a chunk shorter than this (e.g. a stray heading with no body) is merged into its neighbor

_HEADER_RE = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)


@dataclass
class Chunk:
    index: int
    content: str
    section_title: str | None = None


def _split_by_headers(text: str) -> list[tuple[str | None, str]]:
    """Splits markdown text into (section_title, section_body) pairs at ##
    (or deeper) header boundaries. Content before the first header (if
    any) gets section_title=None. The top-level `# Title` line is kept
    with whatever section follows it, not split into its own chunk — a
    lone title line has no retrieval value by itself."""
    matches = list(_HEADER_RE.finditer(text))
    if not matches:
        return [(None, text.strip())] if text.strip() else []

    sections: list[tuple[str | None, str]] = []
    # Content before the first header line (usually just the H1 title +
    # metadata lines like "**Category:** ...") gets prepended to the first
    # real section rather than becoming its own tiny chunk.
    preamble = text[: matches[0].start()].strip()

    for i, match in enumerate(matches):
        level = len(match.group(1))
        title = match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()

        if level == 1:
            # H1 is the document title — fold BOTH its header line and its
            # body (e.g. "**Category:** ..." / "**Applies to:** ..."
            # metadata lines, which carry real retrieval-relevant content
            # like technique IDs) into preamble, rather than discarding
            # the body entirely.
            combined = f"{match.group(0)}\n\n{body}".strip() if body else match.group(0)
            preamble = f"{preamble}\n\n{combined}".strip() if preamble else combined
            continue

        if body:
            full_body = f"{preamble}\n\n{body}".strip() if preamble else body
            preamble = ""  # consumed by the first section that actually has content
        else:
            # No body of its own (e.g. an H2 umbrella heading whose only
            # content lives in H3 children below it) — leave full_body
            # empty so it falls back to the bare header line below, which
            # is what the header-only-merges-forward pass in
            # chunk_document() detects. Preamble is deliberately NOT
            # consumed here — it carries forward to whichever section
            # actually has content first.
            full_body = ""
        sections.append((title, full_body if full_body else match.group(0)))

    if not sections:  # document had only an H1, no subsections
        return [(None, text.strip())]

    return sections


def _split_long_text(text: str, max_chars: int, overlap: int) -> list[str]:
    """Fixed-size fallback splitter with overlap, breaking on paragraph
    boundaries where possible so a split doesn't land mid-sentence any
    more than necessary."""
    if len(text) <= max_chars:
        return [text]

    paragraphs = [p for p in text.split("\n\n") if p.strip()]
    pieces: list[str] = []
    current = ""

    for para in paragraphs:
        candidate = f"{current}\n\n{para}".strip() if current else para
        if len(candidate) <= max_chars:
            current = candidate
        else:
            if current:
                pieces.append(current)
            # carry a trailing overlap from the previous piece into the next
            overlap_text = current[-overlap:] if current else ""
            current = f"{overlap_text}\n\n{para}".strip() if overlap_text else para

    if current:
        pieces.append(current)

    # A single paragraph longer than max_chars on its own still needs a
    # hard split — rare for our knowledge base's prose style, but handled.
    final: list[str] = []
    for piece in pieces:
        if len(piece) <= max_chars:
            final.append(piece)
        else:
            for start in range(0, len(piece), max_chars - overlap):
                final.append(piece[start : start + max_chars])

    return final


def chunk_document(text: str, *, max_chars: int = MAX_CHUNK_CHARS, overlap: int = CHUNK_OVERLAP_CHARS) -> list[Chunk]:
    sections = _split_by_headers(text)

    raw_chunks: list[tuple[str | None, str]] = []
    for title, body in sections:
        if not body.strip():
            continue
        for piece in _split_long_text(body, max_chars, overlap):
            raw_chunks.append((title, piece))

    # Merge any chunk that's suspiciously short into a neighbor, rather
    # than storing a near-empty, low-retrieval-value fragment. A
    # header-with-no-body chunk (e.g. an H2 that's purely an umbrella for
    # H3 subsections beneath it) reads naturally as an introduction to
    # what follows, so it merges FORWARD into the next chunk; anything
    # else short merges BACKWARD into the previous one.
    is_header_only = [False] * len(raw_chunks)
    for i, (title, body) in enumerate(raw_chunks):
        if title and re.fullmatch(r"#{1,6}\s+" + re.escape(title), body.strip()):
            is_header_only[i] = True

    merged: list[tuple[str | None, str]] = []
    pending_prefix = ""
    for i, (title, body) in enumerate(raw_chunks):
        if is_header_only[i] and i + 1 < len(raw_chunks):
            pending_prefix = f"{pending_prefix}\n\n{body}".strip() if pending_prefix else body
            continue

        effective_body = f"{pending_prefix}\n\n{body}".strip() if pending_prefix else body
        pending_prefix = ""

        if merged and len(effective_body) < MIN_CHUNK_CHARS:
            prev_title, prev_body = merged[-1]
            merged[-1] = (prev_title, f"{prev_body}\n\n{effective_body}".strip())
        else:
            merged.append((title, effective_body))

    return [Chunk(index=i, content=body, section_title=title) for i, (title, body) in enumerate(merged)]
