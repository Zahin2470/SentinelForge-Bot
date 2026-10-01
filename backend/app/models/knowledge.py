"""RAG knowledge base (docs/architecture — §11). KnowledgeDocument is a
whole source document (a SOC playbook, ATT&CK reference, etc.);
KnowledgeChunk is what actually gets embedded and retrieved. Every chunk
keeps a back-reference to its document so citations shown to the analyst
(docs/ai/ai-agent.md §8, "evidence_sources") are always resolvable to a real
title/source — the model can never cite a chunk that isn't in this table.
"""

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin

# Matches the dimensionality of the configured EmbeddingProvider
# (docs/ai/ai-agent.md §2). Mock/local providers used in tests must also
# produce vectors of this length so the schema stays consistent across
# environments.
EMBEDDING_DIM = 1536


class KnowledgeDocument(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "knowledge_documents"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "internal-playbook", "mitre-attack"
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # playbook|terminology|ir-procedure|...
    version: Mapped[str] = mapped_column(String(50), default="1.0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class KnowledgeChunk(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "knowledge_chunks"

    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("knowledge_documents.id", ondelete="CASCADE"), nullable=False
    )
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIM), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
