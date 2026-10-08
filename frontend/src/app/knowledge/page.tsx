"use client";

import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { api } from "@/lib/api";

const CATEGORIES = [
  { name: "playbooks", label: "SOC Playbooks" },
  { name: "terminology", label: "Security Terminology" },
  { name: "attack", label: "MITRE ATT&CK Reference" },
  { name: "detection", label: "Detection Rule Documentation" },
  { name: "incident-response", label: "Incident Response Procedures" },
  { name: "architecture", label: "Security Architecture Notes" },
];

/** Managing what's in the knowledge base (re-ingesting after an edit) is a
 * distinct task from asking it a question — that's what the Copilot
 * page's search is for. Keeping them separate mirrors the real
 * distinction in docs/rag.md between the corpus and the retrieval over it. */
export default function KnowledgePage() {
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [message, setMessage] = useState<string | null>(null);

  async function ingest() {
    setStatus("loading");
    try {
      const result = await api.ingestKnowledgeBase();
      setMessage(`Ingested ${result.documents_ingested} document(s), ${result.chunks_ingested} chunk(s).`);
      setStatus("done");
    } catch {
      setMessage("Ingestion failed — check the backend is reachable.");
      setStatus("error");
    }
  }

  return (
    <div>
      <PageHeader
        title="Knowledge Base"
        description="SOC reference documents used for retrieval-augmented investigation — see docs/rag.md."
      />
      <div className="p-6">
        <div className="rounded border border-border bg-panel p-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium text-ink">Re-index knowledge base</h3>
              <p className="mt-1 text-xs text-ink-muted">
                Chunks and embeds every document under knowledge-base/, replacing any existing chunks. Run this
                after editing a document.
              </p>
            </div>
            <button
              type="button"
              onClick={ingest}
              disabled={status === "loading"}
              className="rounded bg-accent px-3 py-1.5 text-xs font-medium text-canvas hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {status === "loading" ? "Ingesting…" : "Re-index now"}
            </button>
          </div>
          {message && <p className="mt-3 text-xs text-ink-faint">{message}</p>}
        </div>

        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {CATEGORIES.map((c) => (
            <div key={c.name} className="rounded border border-border bg-panel p-3">
              <div className="text-sm text-ink">{c.label}</div>
              <div className="mt-0.5 text-[11px] text-ink-faint">knowledge-base/{c.name}/</div>
            </div>
          ))}
        </div>

        <p className="mt-6 text-xs text-ink-faint">
          Search this corpus from the{" "}
          <a href="/copilot" className="text-accent hover:underline">
            AI Copilot
          </a>{" "}
          page.
        </p>
      </div>
    </div>
  );
}
