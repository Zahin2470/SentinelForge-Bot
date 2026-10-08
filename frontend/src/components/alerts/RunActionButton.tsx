"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

/** In a real deployment, detection and correlation run automatically off
 * a worker job (docs/detection-engine.md, docs/architecture — Phase 4) —
 * these buttons exist because this demo has no background worker wired
 * up in the frontend, and an analyst-triggered run is genuinely useful
 * for a live demo walkthrough regardless. */
export function RunActionButton({ action, label }: { action: "detection" | "correlation"; label: string }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setMessage(null);
    try {
      if (action === "detection") {
        const result = await api.runDetection();
        setMessage(`${result.matches} rule match(es) found`);
      } else {
        const result = await api.runCorrelation();
        setMessage(`${result.incidents_created} incident(s) created`);
      }
      router.refresh();
    } catch {
      setMessage("Failed to run — check the backend is reachable.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={run}
        disabled={running}
        className="rounded border border-border bg-elevated px-3 py-1.5 text-xs font-medium text-ink hover:border-accent/40 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {running ? "Running…" : label}
      </button>
      {message && <span className="text-xs text-ink-faint">{message}</span>}
    </div>
  );
}
