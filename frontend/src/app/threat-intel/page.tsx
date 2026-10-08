"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { MonoValue } from "@/components/ui/MonoValue";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/StateMessages";
import { api, ApiError } from "@/lib/api";
import type { IOC } from "@/types/api";

const THREAT_LEVEL_STYLES: Record<string, string> = {
  high: "text-severity-critical",
  medium: "text-severity-medium",
  unknown: "text-ink-faint",
};

/** Client Component (not a Server Component like most other pages)
 * because importing/matching are actions the analyst triggers and wants
 * to see reflected immediately in the same list, without a full page
 * navigation round-trip. */
export default function ThreatIntelPage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [status, setStatus] = useState<"loading" | "done" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionRunning, setActionRunning] = useState(false);

  async function load() {
    setStatus("loading");
    try {
      setIocs(await api.listIOCs());
      setStatus("done");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the backend API.");
      setStatus("error");
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function runImport() {
    setActionRunning(true);
    setActionMessage(null);
    try {
      const result = await api.importThreatIntelFeed();
      setActionMessage(`Imported ${result.imported} indicator(s), ${result.skipped} unsupported pattern(s) skipped.`);
      await load();
    } catch {
      setActionMessage("Import failed — check the backend is reachable.");
    } finally {
      setActionRunning(false);
    }
  }

  async function runMatch() {
    setActionRunning(true);
    setActionMessage(null);
    try {
      const result = await api.runThreatIntelMatch();
      setActionMessage(`${result.alerts_created} alert(s) created from IOC matches.`);
    } catch {
      setActionMessage("Match run failed — check the backend is reachable.");
    } finally {
      setActionRunning(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Threat Intelligence"
        description="Known indicators of compromise — see docs/threat-intelligence.md for the STIX import scope."
      />

      <div className="flex flex-wrap items-center gap-2 border-b border-border px-6 py-3">
        <button
          type="button"
          onClick={runImport}
          disabled={actionRunning}
          className="rounded border border-border bg-elevated px-3 py-1.5 text-xs font-medium text-ink hover:border-accent/40 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Import sample feed
        </button>
        <button
          type="button"
          onClick={runMatch}
          disabled={actionRunning}
          className="rounded border border-border bg-elevated px-3 py-1.5 text-xs font-medium text-ink hover:border-accent/40 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Match against recent events
        </button>
        {actionMessage && <span className="text-xs text-ink-faint">{actionMessage}</span>}
      </div>

      <div className="p-6">
        {status === "loading" && <LoadingState label="Loading indicators…" />}
        {status === "error" && error && <ErrorState title="Could not load threat intelligence" message={error} />}
        {status === "done" && iocs.length === 0 && (
          <EmptyState
            title="No indicators imported yet"
            description="Import the sample STIX-formatted feed to get started."
          />
        )}
        {status === "done" && iocs.length > 0 && (
          <div className="overflow-x-auto rounded border border-border">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border bg-elevated text-xs text-ink-muted">
                  <th className="px-3 py-2 font-medium">Type</th>
                  <th className="px-3 py-2 font-medium">Value</th>
                  <th className="px-3 py-2 font-medium">Threat level</th>
                  <th className="px-3 py-2 font-medium">Confidence</th>
                  <th className="px-3 py-2 font-medium">Source</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="border-b border-border-subtle last:border-0 hover:bg-elevated/40">
                    <td className="px-3 py-2 text-ink-muted uppercase text-xs">{ioc.type}</td>
                    <td className="px-3 py-2">
                      <MonoValue className="text-ink">{ioc.value}</MonoValue>
                    </td>
                    <td className={`px-3 py-2 text-xs font-medium ${THREAT_LEVEL_STYLES[ioc.threat_level] ?? "text-ink-muted"}`}>
                      {ioc.threat_level}
                    </td>
                    <td className="px-3 py-2">
                      <MonoValue>{ioc.confidence.toFixed(2)}</MonoValue>
                    </td>
                    <td className="px-3 py-2 text-ink-muted">{ioc.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
