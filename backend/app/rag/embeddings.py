"""Embedding provider abstraction (docs/ai/ai-agent.md §2's pattern
applied to embeddings, not just the LLM: never hard-code one provider).

TfidfEmbeddingProvider is a REAL, working implementation — not a mock —
built on scikit-learn's TfidfVectorizer, chosen specifically because it
needs no network access and no API key, so this repo's RAG pipeline is
fully testable and runnable offline today. It's a classical
(non-neural) technique: word/n-gram frequency statistics, not learned
semantic meaning — it will match on shared vocabulary well but won't
generalize across synonyms the way a neural embedding model would (it
won't know "credential stuffing" is related to "brute force" unless they
share words). That's a real, documented limitation, not a hidden one — see
the "Upgrade path" note below.

A neural provider (OpenAI text-embedding-3, a local sentence-transformers
model, etc.) can be dropped in by implementing the same EmbeddingProvider
interface — nothing downstream (chunking, retrieval, storage) needs to
change, since app.models.knowledge.KnowledgeChunk stores a fixed-length
float vector regardless of what produced it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from app.rag.constants import EMBEDDING_DIM


class EmbeddingProvider(ABC):
    @property
    @abstractmethod
    def embedding_dim(self) -> int: ...

    @abstractmethod
    def fit(self, corpus: list[str]) -> None:
        """Some providers (TF-IDF) need to see the corpus vocabulary
        before they can embed anything; neural providers typically don't
        and can make this a no-op. Always call fit() once with the full
        knowledge-base corpus before embed()."""

    @abstractmethod
    def embed(self, texts: list[str]) -> np.ndarray:
        """Returns an (n_texts, embedding_dim) float array."""


class TfidfEmbeddingProvider(EmbeddingProvider):
    def __init__(self, max_features: int = EMBEDDING_DIM) -> None:
        self._max_features = max_features
        self._vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),  # unigrams + bigrams — "brute force" as one concept, not just two words
            stop_words="english",
            sublinear_tf=True,  # log-scaled term frequency; dampens the effect of a term repeated many times
        )
        self._fitted = False

    @property
    def embedding_dim(self) -> int:
        return self._max_features

    def fit(self, corpus: list[str]) -> None:
        if not corpus:
            raise ValueError("Cannot fit TfidfEmbeddingProvider on an empty corpus")
        self._vectorizer.fit(corpus)
        self._fitted = True

    def embed(self, texts: list[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("TfidfEmbeddingProvider.embed() called before fit()")
        sparse = self._vectorizer.transform(texts)
        dense = sparse.toarray().astype(np.float32)

        # TfidfVectorizer's vocabulary may be smaller than max_features if
        # the corpus doesn't have that many distinct terms (common for a
        # small knowledge base) — pad with zeros so every embedding is
        # always exactly embedding_dim long, matching the fixed-width
        # pgvector column (app/models/knowledge.py:KnowledgeChunk.embedding).
        if dense.shape[1] < self._max_features:
            pad = np.zeros((dense.shape[0], self._max_features - dense.shape[1]), dtype=np.float32)
            dense = np.hstack([dense, pad])
        return dense

    def save(self, path: str) -> None:
        """Persists the fitted vectorizer. Required because TF-IDF's
        vocabulary is learned from the training corpus — a query embedded
        at search time MUST use the exact same fitted vectorizer used at
        ingestion time, not a freshly-fit one (a fresh fit on just the
        query text would have a totally different, near-meaningless
        vocabulary). Same persist-what-was-actually-fit principle as
        app/ml/model.py:AnomalyModel.save()."""
        import joblib
        from pathlib import Path

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"vectorizer": self._vectorizer, "max_features": self._max_features, "fitted": self._fitted}, path
        )

    @classmethod
    def load(cls, path: str) -> "TfidfEmbeddingProvider":
        import joblib

        payload = joblib.load(path)
        instance = cls(max_features=payload["max_features"])
        instance._vectorizer = payload["vectorizer"]
        instance._fitted = payload["fitted"]
        return instance


class MockEmbeddingProvider(EmbeddingProvider):
    """Deterministic, dependency-free embedding for tests/CI paths that
    want a stand-in without pulling in sklearn or caring about real
    similarity quality — e.g. exercising the agent's tool-call plumbing
    without needing the RAG corpus to be semantically meaningful."""

    def __init__(self, dim: int = EMBEDDING_DIM) -> None:
        self._dim = dim

    @property
    def embedding_dim(self) -> int:
        return self._dim

    def fit(self, corpus: list[str]) -> None:
        pass  # no vocabulary to learn

    def embed(self, texts: list[str]) -> np.ndarray:
        vectors = []
        for text in texts:
            rng = np.random.default_rng(abs(hash(text)) % (2**32))
            vectors.append(rng.random(self._dim, dtype=np.float64).astype(np.float32))
        return np.vstack(vectors) if vectors else np.zeros((0, self._dim), dtype=np.float32)
