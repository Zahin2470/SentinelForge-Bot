import React from "react";
import { cn } from "@/lib/cn";
import type { AttackCoverage } from "@/types/api";

/** Every technique the curated reference set knows about (see
 * docs/threat-intelligence.md §1 for why this is a curated subset, not
 * the full framework), grouped by tactic for the matrix layout. Kept in
 * sync by hand with backend/app/attack/reference_data.py — small enough
 * that duplicating it here is more honest than an indirect fetch-time
 * dependency for what's fundamentally static reference data. */
const TECHNIQUES: { id: string; name: string; tactic: string }[] = [
  { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  { id: "T1098", name: "Account Manipulation", tactic: "Privilege Escalation" },
  { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion" },
  { id: "T1595", name: "Active Scanning", tactic: "Discovery" },
  { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" },
];

type CellState = "detected" | "covered" | "uncovered";

function cellState(id: string, coverage: AttackCoverage): CellState {
  if (coverage.detected_technique_ids.includes(id)) return "detected";
  if (coverage.covered_technique_ids.includes(id)) return "covered";
  return "uncovered";
}

const CELL_STYLES: Record<CellState, string> = {
  detected: "bg-severity-critical/20 border-severity-critical/40 text-severity-critical",
  covered: "bg-accent/10 border-accent/30 text-accent",
  uncovered: "bg-elevated border-border-subtle text-ink-faint",
};

const CELL_LABELS: Record<CellState, string> = {
  detected: "Detected — has fired at least once",
  covered: "Covered — a rule exists, no activity yet",
  uncovered: "Uncovered — no rule maps to this technique",
};

export function AttackCoverageMatrix({ coverage }: { coverage: AttackCoverage }) {
  const byTactic = new Map<string, typeof TECHNIQUES>();
  for (const t of TECHNIQUES) {
    const list = byTactic.get(t.tactic) ?? [];
    list.push(t);
    byTactic.set(t.tactic, list);
  }

  return (
    <div>
      <div className="mb-4 flex items-center gap-4 text-xs text-ink-muted">
        {(["detected", "covered", "uncovered"] as CellState[]).map((state) => (
          <div key={state} className="flex items-center gap-1.5">
            <span className={cn("h-2.5 w-2.5 rounded-sm border", CELL_STYLES[state])} aria-hidden="true" />
            {CELL_LABELS[state]}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from(byTactic.entries()).map(([tactic, techniques]) => (
          <div key={tactic} className="rounded border border-border bg-panel p-3">
            <div className="text-xs font-medium text-ink-muted">{tactic}</div>
            <div className="mt-2 space-y-1.5">
              {techniques.map((t) => {
                const state = cellState(t.id, coverage);
                return (
                  <div
                    key={t.id}
                    title={CELL_LABELS[state]}
                    className={cn("rounded-sm border px-2 py-1.5 text-xs", CELL_STYLES[state])}
                  >
                    <div className="font-mono font-medium">{t.id}</div>
                    <div className="mt-0.5 opacity-90">{t.name}</div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
