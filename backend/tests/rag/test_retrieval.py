"""Tests for app.rag.retrieval — pure numpy, no DB needed."""

import numpy as np

from app.rag.retrieval import RetrievedChunk, cosine_similarity, rerank_by_recency_and_category, retrieve_top_k


def test_cosine_similarity_identical_vectors_score_one() -> None:
    v = np.array([1.0, 2.0, 3.0])
    scores = cosine_similarity(v, np.array([v]))
    assert abs(scores[0] - 1.0) < 1e-6


def test_cosine_similarity_orthogonal_vectors_score_zero() -> None:
    query = np.array([1.0, 0.0])
    chunks = np.array([[0.0, 1.0]])
    scores = cosine_similarity(query, chunks)
    assert abs(scores[0]) < 1e-6


def test_cosine_similarity_zero_vector_scores_zero_not_nan() -> None:
    query = np.array([1.0, 1.0])
    chunks = np.array([[0.0, 0.0]])
    scores = cosine_similarity(query, chunks)
    assert scores[0] == 0.0
    assert not np.isnan(scores[0])


def _chunk(id_, content, title="Doc", source="playbook"):
    return {"id": id_, "content": content, "document_title": title, "source": source}


def test_retrieve_top_k_ranks_by_similarity_descending() -> None:
    query = np.array([1.0, 0.0, 0.0])
    chunks = [_chunk("a", "low"), _chunk("b", "high"), _chunk("c", "medium")]
    vectors = np.array([
        [0.1, 0.9, 0.0],   # low similarity to query
        [0.9, 0.1, 0.0],   # high similarity
        [0.5, 0.5, 0.0],   # medium similarity
    ])

    results = retrieve_top_k(query, chunks, vectors, k=3)

    assert [r.chunk_id for r in results] == ["b", "c", "a"]
    assert results[0].score > results[1].score > results[2].score


def test_retrieve_top_k_respects_k() -> None:
    query = np.array([1.0, 0.0])
    chunks = [_chunk(str(i), "x") for i in range(10)]
    vectors = np.tile(np.array([1.0, 0.0]), (10, 1))

    results = retrieve_top_k(query, chunks, vectors, k=3)
    assert len(results) == 3


def test_retrieve_top_k_excludes_below_min_score() -> None:
    query = np.array([1.0, 0.0])
    chunks = [_chunk("relevant", "x"), _chunk("irrelevant", "y")]
    vectors = np.array([[1.0, 0.0], [0.0, 1.0]])  # second is orthogonal -> score 0

    results = retrieve_top_k(query, chunks, vectors, k=5, min_score=0.5)
    assert len(results) == 1
    assert results[0].chunk_id == "relevant"


def test_retrieve_top_k_empty_corpus_returns_empty() -> None:
    query = np.array([1.0, 0.0])
    assert retrieve_top_k(query, [], np.zeros((0, 2)), k=5) == []


def test_retrieve_top_k_mismatched_lengths_raises() -> None:
    query = np.array([1.0, 0.0])
    chunks = [_chunk("a", "x")]
    vectors = np.zeros((2, 2))  # 2 rows but only 1 chunk
    try:
        retrieve_top_k(query, chunks, vectors)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_rerank_boosts_preferred_category() -> None:
    chunks = [
        RetrievedChunk("a", score=0.5, content="x", document_title="Terminology", source="terminology"),
        RetrievedChunk("b", score=0.45, content="y", document_title="Playbook", source="playbook"),
    ]
    reranked = rerank_by_recency_and_category(chunks, category_boost={"playbook": 1.0}, boost_weight=0.1)
    assert reranked[0].chunk_id == "b"  # 0.45 + 0.1 = 0.55 > 0.5


def test_rerank_with_no_boost_config_is_a_no_op() -> None:
    chunks = [
        RetrievedChunk("a", score=0.5, content="x", document_title="A", source="s"),
        RetrievedChunk("b", score=0.3, content="y", document_title="B", source="s"),
    ]
    assert rerank_by_recency_and_category(chunks) == chunks


if __name__ == "__main__":
    test_cosine_similarity_identical_vectors_score_one()
    test_cosine_similarity_orthogonal_vectors_score_zero()
    test_cosine_similarity_zero_vector_scores_zero_not_nan()
    test_retrieve_top_k_ranks_by_similarity_descending()
    test_retrieve_top_k_respects_k()
    test_retrieve_top_k_excludes_below_min_score()
    test_retrieve_top_k_empty_corpus_returns_empty()
    test_retrieve_top_k_mismatched_lengths_raises()
    test_rerank_boosts_preferred_category()
    test_rerank_with_no_boost_config_is_a_no_op()
    print("All retrieval tests passed.")
