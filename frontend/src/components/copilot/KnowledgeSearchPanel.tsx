"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/StateMessages";
import type { RagSearchResult } from "@/types/api";

/** Standalone semantic search over the SOC knowledge base
 * (docs/rag.md) — separate from the per-incident investigation
 * (CopilotPanel), since "look something up" and "investigate this
 * specific incident" are different tasks with different inputs. Retrieval
 * is real (TF-IDF cosine similarity against the actual knowledge base,
 * not a mock), so a query's results are exactly what the AI SOC Analyst
 * would see when it calls the same search_security_knowledge tool. */
export function KnowledgeSearchPanel() {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [results, setResults] = useState<RagSearchResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function search(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setStatus("loading");
    setError(null);
    try {
      const response = await api.searchKnowledge(query, 5);
      setResults(response);
      setStatus("done");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the knowledge base search service.");
      setStatus("error");
    }
  }

  return (
    <div>
      <form onSubmit={search} className="flex gap-2">
        <label htmlFor="kb-search" className="sr-only">
          Search the SOC knowledge base
        </label>
        <input
          id="kb-search"
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="e.g. how should I respond to a brute force incident?"
          className="flex-1 rounded border border-border bg-panel px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent"
        />
        <button
          type="submit"
          disabled={status === "loading" || !query.trim()}
          className="rounded bg-accent px-4 py-2 text-sm font-medium text-canvas hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Search
        </button>
      </form>

      <div className="mt-6">
        {status === "loading" && <LoadingState label="Searching knowledge base…" />}
        {status === "error" && error && <ErrorState title="Search unavailable" message={error} />}
        {status === "done" && results.length === 0 && (
          <EmptyState title="No matching documents" description="Try a different phrasing, or broaden the query." />
        )}
        {status === "done" && results.length > 0 && (
          <ul className="space-y-3">
            {results.map((r) => (
              <li key={r.chunk_id} className="rounded border border-border bg-panel p-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-ink">{r.document_title}</span>
                  <span className="font-mono text-[11px] text-ink-faint">{r.score.toFixed(3)}</span>
                </div>
                <div className="mt-0.5 text-[11px] uppercase tracking-wide text-ink-faint">{r.source}</div>
                <p className="mt-2 text-sm leading-relaxed text-ink-muted">{r.content}</p>
              </li>
            ))}
          </ul>
        )}
        {status === "idle" && (
          <EmptyState
            title="Search the SOC knowledge base"
            description="Playbooks, ATT&CK reference, terminology, and incident response procedures — the same corpus the AI SOC Analyst retrieves from during an investigation."
          />
        )}
      </div>
    </div>
  );
}
