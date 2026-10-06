# RAG (Retrieval-Augmented Generation)

## 1. Pipeline

```
knowledge-base/*.md
      │
      ▼
Chunking (app/rag/chunking.py) — splits on ## headers, falls back to
      │                           fixed-size+overlap for oversized sections
      ▼
Embedding (app/rag/embeddings.py) — TfidfEmbeddingProvider (real, offline)
      │
      ▼
Storage — pgvector (app/models/knowledge.py:KnowledgeChunk), ivfflat index
      │
      ▼
Retrieval (app/rag/retrieval.py) — cosine similarity, top-k
      │
      ▼
Reranking (app/rag/retrieval.py:rerank_by_recency_and_category) — optional
      │                                                            category boost
      ▼
Citation validation (app/rag/citation.py) — strips any source the model
      │                                      wasn't actually shown
      ▼
LLM context (Phase 8, not yet built)
```

Every stage above is implemented and tested (36 tests across
`backend/tests/rag/`), runnable without a database — chunking, embedding,
retrieval, and citation validation are all pure functions over plain
data, in the same style as the detection engine and correlation engine.

## 2. The knowledge base

6 real documents (not placeholders) in `knowledge-base/`, covering exactly
the categories the build spec calls for: SOC playbooks
(`playbooks/brute-force-response.md`, `playbooks/defense-evasion-response.md`),
security terminology, MITRE ATT&CK knowledge, detection rule documentation,
incident response procedures, and security architecture notes. Each is
written to cross-reference the actual rules, models, and docs elsewhere in
this repo (e.g. the brute-force playbook references AUTH-BRUTEFORCE-001 and
AUTH-PRIVCHANGE-003 by ID) rather than being generic security writing
disconnected from what SentinelForge actually does.

## 3. Embedding provider: TF-IDF, chosen and documented honestly

`TfidfEmbeddingProvider` (`app/rag/embeddings.py`) is a **real, working**
implementation — scikit-learn's `TfidfVectorizer`, not a mock. It needs no
network access or API key, so the whole RAG pipeline is testable and
demoable offline today. It's explicitly *not* a neural embedding model,
and the module docstring says so directly: TF-IDF matches on shared
vocabulary (word/n-gram frequency), not learned semantic meaning. A neural
provider (OpenAI `text-embedding-3`, a local `sentence-transformers`
model) can be dropped in later by implementing the same
`EmbeddingProvider` interface — nothing downstream needs to change, since
storage and retrieval only care about fixed-length float vectors, not
where they came from.

## 4. What real testing actually found (not hypothetical limitations)

Building `backend/tests/rag/test_rag_end_to_end.py` — which chunks the
real knowledge base, embeds it with real TF-IDF, and checks that natural
queries retrieve the right document — surfaced two concrete, reproducible
weaknesses, not just the generic "TF-IDF doesn't understand synonyms"
caveat:

**Phrase-density collision.** Querying *"what is the definition of a false
positive versus a true positive?"* ranked the actual terminology
definition **4th**, behind three other documents that each happen to use
the literal phrase "true positive / false positive" in a short, dense
sentence (e.g. a playbook's close-out checklist item). A bag-of-words
model rewards raw phrase density; it has no way to know that one of those
mentions is *the* definition and the others are incidental usage.

**Rare-token dominance.** Querying about technique **T1110** consistently
retrieved the terminology document instead of the actual ATT&CK reference
document — because the terminology doc's TTP definition happens to cite
"T1110" as a parenthetical example, and T1110 is a rare token that
dominates a TF-IDF similarity score wherever it appears, regardless of
whether that mention is the substantive content or a passing example.

**What fixed the first one, partially:** the terminology document
originally had no header structure — all 15 term definitions were one
giant paragraph blob, forced through the fixed-size chunker into 4
oversized, topically-diluted chunks. Restructuring it into one `##`
section per term (visible in `knowledge-base/terminology/security-terminology.md`)
measurably improved retrieval — a direct, verifiable example of why
`app/rag/chunking.py` prefers header-based splitting over fixed-size
chunks. It didn't fully fix the phrase-density issue, because that's a
property of the embedding technique, not the chunking.

**What this means practically:** `docs/evaluation.md` should eventually
track RAG retrieval precision the same rigorous way it tracks detection
and ML metrics, once there's a larger knowledge base and query set to
measure against. For now, the honest scope is: TF-IDF retrieval is
functional and demonstrably better than random (verified: 5 of 6
realistic test queries rank the correct document in the top 3 of 40
chunks on the first honest attempt; the two that initially failed did so
for the specific, now-documented reasons above, not from a bug), but a
neural embedding provider would very likely outperform it on exactly
these two failure modes — that's the concrete, evidence-based case for the
upgrade path, not a generic "neural is better" assumption.

## 5. Citation validation

`app/rag/citation.py:validate_citations` is the direct implementation of
the build spec's "do not allow the AI to fabricate citations" requirement:
given the chunk IDs a model claims to have cited and the chunk IDs that
were *actually* retrieved and shown to it, anything not in the retrieved
set is flagged as fabricated — structurally, not by asking the model to
self-report. `format_evidence_sources` only ever formats chunks it was
handed directly, so there is no code path by which it could print a
source that wasn't actually retrieved.

## 6. Not yet built

- **Storage/retrieval against a live pgvector database** — the DB schema
  (`KnowledgeDocument`, `KnowledgeChunk`, the ivfflat index) exists and is
  reviewed, but untested by execution here (no network to install
  sqlalchemy/pgvector in this dev environment, same caveat as every other
  DB-touching layer in this repo).
- **`KnowledgeRepository` / `RAGService` / the ingestion script and API
  routes** that would wire chunking+embedding+storage to the database —
  not yet written. `app/rag/*` is the tested, reviewed core logic these
  would call.
- **Integration into the AI agent's `search_security_knowledge` tool**
  (Phase 8).
