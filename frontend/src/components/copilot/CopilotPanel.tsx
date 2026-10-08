"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { InvestigationReportCard } from "@/components/incidents/InvestigationReportCard";
import { ErrorState, LoadingState } from "@/components/ui/StateMessages";
import type { InvestigateResponse } from "@/types/api";

/** The copilot interface is deliberately NOT a free-text chat box that
 * sends arbitrary prompts to an LLM — it triggers a real, bounded
 * investigation run against a specific incident (docs/ai/ai-agent.md),
 * and shows exactly what came back: a validated report, or a clear
 * failure reason. There is no "type anything" input here because the
 * product's own architecture doesn't work that way; the UI should not
 * imply capabilities the system doesn't have. */
export function CopilotPanel({ incidentId }: { incidentId: string }) {
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [result, setResult] = useState<InvestigateResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runInvestigation() {
    setStatus("loading");
    setError(null);
    try {
      const response = await api.investigateIncident(incidentId);
      setResult(response);
      setStatus("done");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `AI analysis unavailable: ${err.message}`
          : "Could not reach the investigation service.",
      );
      setStatus("error");
    }
  }

  return (
    <div className="rounded border border-border bg-panel p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-ink">AI SOC Analyst</h3>
        <button
          type="button"
          onClick={runInvestigation}
          disabled={status === "loading"}
          className="rounded bg-accent px-3 py-1.5 text-xs font-medium text-canvas hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {status === "loading" ? "Investigating…" : "Run investigation"}
        </button>
      </div>

      <p className="mt-1.5 text-xs text-ink-faint">
        Gathers evidence, checks threat intelligence, and produces an evidence-grounded report. No containment
        action is ever taken automatically.
      </p>

      <div className="mt-4">
        {status === "loading" && <LoadingState label="Running investigation…" />}
        {status === "error" && error && <ErrorState title="Investigation unavailable" message={error} />}
        {status === "done" && result?.report && <InvestigationReportCard report={result.report} />}
        {status === "done" && !result?.report && (
          <ErrorState
            title="Investigation did not complete"
            message={result?.failure_reason ?? "No report was produced."}
          />
        )}
      </div>
    </div>
  );
}
