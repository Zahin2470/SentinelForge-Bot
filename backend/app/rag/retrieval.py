"""Semantic retrieval + reranking (docs — §11 pipeline: "semantic
retrieval → reranking → LLM context"). Pure numpy over embedding arrays —
no DB — so retrieval quality is testable in isolation from pgvector.

Production note: at real scale, the nearest-neighbor search itself runs in
Postgres via pgvector's ivfflat index (see the migration in
migrations/versions/0001_initial_schema.py), not by pulling every chunk's
embedding into Python and comparing here. This module is what the
retrieval logic *means* — reviewable, testable — and doubles as the
actual implementation at the scale a demo/portfolio knowledge base
realistically has (dozens to low hundreds of chunks), where pulling
everything into memory and reranking in Python is completely reasonable
and no slower than round-tripping to the DB for pgvector's approximate
search.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class RetrievedChunk:
    chunk_id: str
    score: float
    content: str
    document_title: str
    source: str


def cosine_similarity(query_vector: np.ndarray, chunk_vectors: np.ndarray) -> np.ndarray:
    """query_vector: (dim,). chunk_vectors: (n_chunks, dim). Returns
    (n_chunks,) similarity scores in [-1, 1] (in practice [0, 1] for
    non-negative TF-IDF vectors). Chunks with an all-zero vector (would
    divide by zero) score 0 rather than raising or returning NaN."""
    query_norm = np.linalg.norm(query_vector)
    chunk_norms = np.linalg.norm(chunk_vectors, axis=1)

    dot_products = chunk_vectors @ query_vector
    denom = chunk_norms * query_norm

    with np.errstate(divide="ignore", invalid="ignore"):
        scores = np.where(denom > 0, dot_products / denom, 0.0)
    return scores


def retrieve_top_k(
    query_vector: np.ndarray,
    chunks: list[dict],
    chunk_vectors: np.ndarray,
    *,
    k: int = 5,
    min_score: float = 0.0,
) -> list[RetrievedChunk]:
    """chunks[i] must correspond to chunk_vectors[i] — same order, same
    length. Each chunk dict needs: id, content, document_title, source.
    Returns the top-k by cosine similarity, highest first, excluding
    anything below min_score (so a query with no relevant chunks in the
    corpus returns an empty list rather than k irrelevant ones)."""
    if len(chunks) == 0:
        return []
    if len(chunks) != chunk_vectors.shape[0]:
        raise ValueError(f"chunks length ({len(chunks)}) must match chunk_vectors rows ({chunk_vectors.shape[0]})")

    scores = cosine_similarity(query_vector, chunk_vectors)
    ranked_indices = np.argsort(-scores)

    results: list[RetrievedChunk] = []
    for idx in ranked_indices[:k]:
        score = float(scores[idx])
        if score < min_score:
            break  # scores are sorted descending, nothing after this clears the bar either
        chunk = chunks[idx]
        results.append(
            RetrievedChunk(
                chunk_id=chunk["id"],
                score=score,
                content=chunk["content"],
                document_title=chunk["document_title"],
                source=chunk["source"],
            )
        )
    return results


def rerank_by_recency_and_category(
    retrieved: list[RetrievedChunk],
    *,
    category_boost: dict[str, float] | None = None,
    boost_weight: float = 0.1,
) -> list[RetrievedChunk]:
    """A lightweight reranking step (docs — §11 "reranking"): nudges the
    pure-similarity ranking by a small, explicit category preference —
    e.g. boosting 'playbook' chunks slightly above 'terminology' chunks
    for an investigation query, since a playbook is directly actionable
    and a glossary entry is background. This does NOT reorder based on
    anything the retrieval call doesn't already expose (no hidden
    signals) — category_boost is passed in by the caller, not inferred.
    """
    if not category_boost:
        return retrieved

    def reranked_score(chunk: RetrievedChunk) -> float:
        boost = category_boost.get(chunk.source, 0.0)
        return chunk.score + boost_weight * boost

    return sorted(retrieved, key=reranked_score, reverse=True)
