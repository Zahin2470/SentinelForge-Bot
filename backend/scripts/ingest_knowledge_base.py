#!/usr/bin/env python3
"""Chunks, embeds, and stores every document under knowledge-base/ for RAG
retrieval (docs/rag.md). Safe to re-run — re-ingesting a document replaces
its chunks rather than duplicating them.

Usage: python scripts/ingest_knowledge_base.py [knowledge-base-dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.db import SessionLocal  # noqa: E402
from app.core.logging import configure_logging, get_logger  # noqa: E402
from app.services.rag_service import RAGService  # noqa: E402

configure_logging()
logger = get_logger(__name__)


def main(kb_dir: str) -> int:
    db = SessionLocal()
    try:
        result = RAGService().ingest_corpus(db, kb_dir)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print(f"Ingested {result['documents_ingested']} documents, {result['chunks_ingested']} chunks.")
    return 0


if __name__ == "__main__":
    kb_directory = sys.argv[1] if len(sys.argv) > 1 else "knowledge-base"
    sys.exit(main(kb_directory))
