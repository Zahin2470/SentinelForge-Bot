from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.services.rag_service import RAGService

router = APIRouter(prefix="/api/v1/rag", tags=["rag"])

_rag_service = RAGService()


class SearchResult(BaseModel):
    chunk_id: str
    score: float
    content: str
    document_title: str
    source: str


class IngestResult(BaseModel):
    documents_ingested: int
    chunks_ingested: int


@router.get("/search", response_model=list[SearchResult])
def search_knowledge_base(q: str, k: int = 5, db: Session = Depends(get_db)) -> list[SearchResult]:
    results = _rag_service.retrieve(db, q, k=k)
    return [SearchResult(**vars(r)) for r in results]


@router.post("/ingest", response_model=IngestResult)
def ingest_knowledge_base(kb_dir: str = "knowledge-base", db: Session = Depends(get_db)) -> IngestResult:
    result = _rag_service.ingest_corpus(db, kb_dir)
    db.commit()
    return IngestResult(**result)
