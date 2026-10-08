import React from "react";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import type { InvestigationReport } from "@/types/api";

/** AI-generated content gets a visually distinct treatment (the dashed
 * accent-tinted border, the "AI-generated" label) from ground-truth
 * system data everywhere else in the product — a deliberate reflection of
 * docs/architecture/architecture.md's stated principle that AI is one
 * component of the system, not the system itself. An analyst should never
 * be able to mistake a model's summary for a raw event. */
export function InvestigationReportCard({ report }: { report: InvestigationReport }) {
  return (
    <div className="rounded border border-dashed border-accent/40 bg-accent/[0.04] p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="rounded-sm bg-accent/15 px-1.5 py-0.5 text-[10px] font-medium text-accent">
            AI-generated
          </span>
          <SeverityBadge severity={report.severity} />
        </div>
        <span className="font-mono text-xs text-ink-muted">
          confidence {(report.confidence * 100).toFixed(0)}%
        </span>
      </div>

      <h3 className="mt-3 text-sm font-medium text-ink">{report.classification.replace(/_/g, " ")}</h3>
      <p className="mt-1.5 text-sm leading-relaxed text-ink-muted">{report.summary}</p>

      {report.attack_mapping.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {report.attack_mapping.map((m) => (
            <span
              key={m.technique_id}
              className="rounded-sm border border-border bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-ink-muted"
            >
              {m.technique_id} · {m.technique_name}
            </span>
          ))}
        </div>
      )}

      {report.recommended_next_steps.length > 0 && (
        <div className="mt-4">
          <div className="text-xs font-medium text-ink-muted">Recommended next steps</div>
          <ul className="mt-1.5 space-y-1 text-sm text-ink">
            {report.recommended_next_steps.map((step, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-ink-faint">–</span>
                {step}
              </li>
            ))}
          </ul>
        </div>
      )}

      {report.evidence_sources.length > 0 && (
        <div className="mt-4">
          <div className="text-xs font-medium text-ink-muted">Evidence sources</div>
          <ul className="mt-1.5 space-y-0.5 text-xs text-ink-faint">
            {report.evidence_sources.map((source, i) => (
              <li key={i}>{source}</li>
            ))}
          </ul>
        </div>
      )}

      <p className="mt-4 border-t border-border-subtle pt-3 text-xs italic text-ink-faint">
        {report.human_approval_statement}
      </p>
    </div>
  );
}
