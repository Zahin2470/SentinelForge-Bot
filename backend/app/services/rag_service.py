"""Wires app.rag.chunking / embeddings / retrieval / citation to
persistence. Mirrors the pattern of every other *_service.py in this repo:
pure logic lives in app/rag/, this module is the thin, reviewed-but-not-
executed-here layer that calls it against a real Session.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.rag.chunking import chunk_document
from app.rag.citation import CitationValidationResult, validate_citations
from app.rag.embeddings import TfidfEmbeddingProvider
from app.rag.retrieval import RetrievedChunk, retrieve_top_k
from app.repositories.knowledge_repository import KnowledgeRepository

logger = get_logger(__name__)

# Where the fitted TF-IDF vectorizer is persisted — must be the SAME
# fitted vectorizer at ingest time and query time (see
# app/rag/embeddings.py:TfidfEmbeddingProvider.save's docstring for why).
DEFAULT_VECTORIZER_PATH = "ml/models/rag_tfidf_vectorizer.joblib"


class KnowledgeBaseNotIngested(RuntimeError):
    """Raised when retrieve() is called before any document has been
    ingested (no fitted vectorizer exists yet). Callers should treat this
    like app.services.ml_scoring_service.ModelNotAvailable — a clear,
    catchable "not ready yet" rather than a confusing stack trace."""


class RAGService:
    def __init__(self, knowledge_repo: KnowledgeRepository | None = None, vectorizer_path: str | None = None) -> None:
        self.knowledge_repo = knowledge_repo or KnowledgeRepository()
        self._vectorizer_path = vectorizer_path or DEFAULT_VECTORIZER_PATH
        self._provider: TfidfEmbeddingProvider | None = None

    def ingest_corpus(self, db: Session, kb_dir: str | Path, *, source: str = "internal-kb") -> dict:
        """Chunks and embeds every *.md file under kb_dir, storing
        documents+chunks. Fits ONE TfidfEmbeddingProvider across every
        chunk from every document (a global fit, not per-document) so all
        chunks share a consistent vocabulary/vector space — the same
        reason app.ml.synthetic fixes a canonical window size, applied to
        embeddings instead of features.
        """
        kb_dir = Path(kb_dir)
        md_files = sorted(kb_dir.rglob("*.md"))
        if not md_files:
            return {"documents_ingested": 0, "chunks_ingested": 0}

        # Pass 1: chunk everything first, so the embedding provider can be
        # fit once on the complete corpus before any chunk is embedded.
        per_document_chunks: dict[Path, list] = {}
        all_chunk_texts: list[str] = []
        for path in md_files:
            text = path.read_text()
            chunks = chunk_document(text)
            per_document_chunks[path] = chunks
            all_chunk_texts.extend(c.content for c in chunks)

        provider = TfidfEmbeddingProvider()
        provider.fit(all_chunk_texts)
        provider.save(self._vectorizer_path)
        self._provider = provider

        documents_ingested, chunks_ingested = 0, 0
        for path, chunks in per_document_chunks.items():
            if not chunks:
                continue
            title = path.read_text().splitlines()[0].lstrip("# ").strip()
            category = path.parent.name

            existing = self.knowledge_repo.get_document_by_title_and_source(db, title, source)
            document = existing or self.knowledge_repo.create_document(
                db, title=title, source=source, category=category
            )

            chunk_texts = [c.content for c in chunks]
            embeddings = provider.embed(chunk_texts)
            chunk_rows = [
                {"chunk_index": c.index, "content": c.content, "embedding": embeddings[i].tolist()}
                for i, c in enumerate(chunks)
            ]
            self.knowledge_repo.replace_chunks(db, document.id, chunk_rows)

            documents_ingested += 1
            chunks_ingested += len(chunks)
            logger.info("knowledge_document_ingested", title=title, chunk_count=len(chunks))

        return {"documents_ingested": documents_ingested, "chunks_ingested": chunks_ingested}

    def _get_provider(self) -> TfidfEmbeddingProvider:
        if self._provider is not None:
            return self._provider
        try:
            self._provider = TfidfEmbeddingProvider.load(self._vectorizer_path)
        except FileNotFoundError as exc:
            raise KnowledgeBaseNotIngested(
                f"No fitted embedding vectorizer at {self._vectorizer_path}. Run `make ingest-knowledge-base` first."
            ) from exc
        return self._provider

    def retrieve(self, db: Session, query: str, *, k: int = 5, use_pgvector: bool = True) -> list[RetrievedChunk]:
        """use_pgvector=True: real production path, ANN search in Postgres.
        use_pgvector=False: Python-side cosine ranking over every stored
        chunk — the documented fallback for small corpora
        (app/rag/retrieval.py's module docstring), and what this method
        falls back to if a caller explicitly wants it (e.g. to compare
        against the DB-side result for a sanity check)."""
        try:
            provider = self._get_provider()
        except KnowledgeBaseNotIngested:
            logger.warning("rag_retrieval_skipped_no_corpus")
            return []

        query_vector = provider.embed([query])[0]

        if use_pgvector:
            rows = self.knowledge_repo.search_by_vector(db, query_vector.tolist(), k=k)
            return [
                RetrievedChunk(
                    chunk_id=str(chunk.id),
                    score=score,
                    content=chunk.content,
                    document_title=document.title,
                    source=document.category,
                )
                for chunk, document, score in rows
            ]

        pairs = self.knowledge_repo.list_all_chunks_with_documents(db)
        if not pairs:
            return []
        chunk_dicts = [
            {"id": str(chunk.id), "content": chunk.content, "document_title": doc.title, "source": doc.category}
            for chunk, doc in pairs
        ]
        import numpy as np

        vectors = np.array([chunk.embedding for chunk, _doc in pairs], dtype=np.float32)
        return retrieve_top_k(query_vector, chunk_dicts, vectors, k=k)

    def validate_ai_citations(self, cited_chunk_ids: list[str], retrieved: list[RetrievedChunk]) -> CitationValidationResult:
        return validate_citations(cited_chunk_ids, retrieved)
