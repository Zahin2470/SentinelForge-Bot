import React from "react";
import type { Incident } from "@/types/api";

interface Component {
  label: string;
  value: number | null;
  hint: string;
}

/** Renders every risk-score component individually, never just the final
 * number — the whole point of docs/architecture/risk-scoring.md is that
 * an analyst can see exactly what drove a severity judgment, so this
 * component's structure IS that design decision, not just a display of
 * it. A null component renders as "not available" rather than 0, so the
 * gap between "no ML signal yet" and "confirmed zero risk" stays visible. */
export function RiskScoreBreakdown({ incident }: { incident: Incident }) {
  const components: Component[] = [
    { label: "Rule match", value: incident.rule_score, hint: "Highest severity among matched detection rules" },
    { label: "ML anomaly", value: incident.anomaly_score, hint: "Isolation Forest anomaly score" },
    { label: "Correlation", value: incident.correlation_score, hint: "Strength of corroborating alerts" },
    { label: "Threat intel", value: incident.threat_intelligence_score, hint: "Known-indicator match severity" },
    { label: "Asset criticality", value: incident.asset_criticality_score, hint: "Sensitivity of the affected system" },
    { label: "Identity context", value: incident.identity_context_score, hint: "Not yet available — behavioral baseline pending" },
  ];

  return (
    <div className="rounded border border-border bg-panel p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-medium text-ink">Risk score breakdown</h3>
        <span className="font-mono text-lg font-semibold text-ink">
          {incident.final_risk_score !== null ? incident.final_risk_score.toFixed(2) : "—"}
        </span>
      </div>

      <ul className="mt-3 space-y-2">
        {components.map((c) => (
          <li key={c.label}>
            <div className="flex items-center justify-between text-xs">
              <span className="text-ink-muted">{c.label}</span>
              <span className="font-mono text-ink-muted">{c.value !== null ? c.value.toFixed(2) : "n/a"}</span>
            </div>
            <div className="mt-1 h-1.5 rounded-full bg-elevated" role="presentation">
              {c.value !== null && (
                <div
                  className="h-full rounded-full bg-accent"
                  style={{ width: `${Math.round(c.value * 100)}%` }}
                />
              )}
            </div>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[11px] leading-relaxed text-ink-faint">
        Components with no signal yet are excluded and the remaining weights renormalized — not treated as zero.
      </p>
    </div>
  );
}
