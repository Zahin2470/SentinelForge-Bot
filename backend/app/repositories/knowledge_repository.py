"""Data access for the RAG knowledge base. list_chunks_ranked_by_similarity
uses pgvector's native cosine-distance operator (real production path —
the ANN search happens in Postgres via the ivfflat index from
migrations/versions/0001_initial_schema.py, not by pulling every chunk
into Python); to_plain_dicts + Python-side ranking
(app/rag/retrieval.py:retrieve_top_k) remains available as the documented
fallback for small corpora or environments without a live DB, and is what
backend/tests/rag/test_rag_end_to_end.py actually exercises.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.knowledge import KnowledgeChunk, KnowledgeDocument


class KnowledgeRepository:
    def create_document(self, db: Session, *, title: str, source: str, category: str, version: str = "1.0") -> KnowledgeDocument:
        document = KnowledgeDocument(title=title, source=source, category=category, version=version)
        db.add(document)
        db.flush()
        return document

    def get_document_by_title_and_source(self, db: Session, title: str, source: str) -> KnowledgeDocument | None:
        stmt = select(KnowledgeDocument).where(KnowledgeDocument.title == title, KnowledgeDocument.source == source)
        return db.execute(stmt).scalar_one_or_none()

    def replace_chunks(self, db: Session, document_id: uuid.UUID, chunks: list[dict]) -> list[KnowledgeChunk]:
        """Deletes any existing chunks for this document and inserts the
        new set — re-ingesting a document (e.g. after an edit) should
        never leave stale chunks behind from a previous version."""
        existing = db.execute(select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)).scalars().all()
        for chunk in existing:
            db.delete(chunk)
        db.flush()

        rows = []
        for chunk_data in chunks:
            row = KnowledgeChunk(document_id=document_id, **chunk_data)
            db.add(row)
            rows.append(row)
        db.flush()
        return rows

    def list_all_chunks_with_documents(self, db: Session) -> list[tuple[KnowledgeChunk, KnowledgeDocument]]:
        stmt = select(KnowledgeChunk, KnowledgeDocument).join(
            KnowledgeDocument, KnowledgeChunk.document_id == KnowledgeDocument.id
        )
        return list(db.execute(stmt).all())

    def search_by_vector(self, db: Session, query_embedding: list[float], *, k: int = 5) -> list[tuple[KnowledgeChunk, KnowledgeDocument, float]]:
        """Real pgvector ANN search: orders by cosine distance (smaller =
        more similar) using the ivfflat index, returns (chunk, document,
        similarity) where similarity = 1 - distance to match
        app.rag.retrieval's score convention (higher = more similar)."""
        distance = KnowledgeChunk.embedding.cosine_distance(query_embedding)
        stmt = (
            select(KnowledgeChunk, KnowledgeDocument, distance.label("distance"))
            .join(KnowledgeDocument, KnowledgeChunk.document_id == KnowledgeDocument.id)
            .order_by(distance)
            .limit(k)
        )
        rows = db.execute(stmt).all()
        return [(chunk, document, 1.0 - dist) for chunk, document, dist in rows]
