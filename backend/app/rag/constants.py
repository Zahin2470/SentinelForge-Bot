"""Constants shared between app.models.knowledge (the SQLAlchemy/pgvector
schema) and app.rag.* (pure embedding/retrieval logic that must stay
importable without sqlalchemy/pgvector installed — see
app/rag/embeddings.py's docstring on why offline testability matters here).

Single source of truth: app.models.knowledge.EMBEDDING_DIM imports this
value rather than redefining it, so the DB column width and the embedding
provider's output width can never silently drift apart.
"""

EMBEDDING_DIM = 1536
