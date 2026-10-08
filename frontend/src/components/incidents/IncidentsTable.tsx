import Link from "next/link";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { EmptyState } from "@/components/ui/StateMessages";
import { MonoValue } from "@/components/ui/MonoValue";
import type { Incident } from "@/types/api";

const STATUS_LABELS: Record<Incident["status"], string> = {
  OPEN: "Open",
  TRIAGED: "Triaged",
  INVESTIGATING: "Investigating",
  CONTAINMENT_RECOMMENDED: "Containment recommended",
  AWAITING_REVIEW: "Awaiting review",
  RESOLVED: "Resolved",
  FALSE_POSITIVE: "False positive",
  CLOSED: "Closed",
};

export function IncidentsTable({ incidents }: { incidents: Incident[] }) {
  if (incidents.length === 0) {
    return (
      <EmptyState
        title="No incidents"
        description="Incidents appear here once correlated alerts are grouped. Run correlation from the Alerts page to generate one from current activity."
      />
    );
  }

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-border bg-elevated text-xs text-ink-muted">
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">ID</th>
            <th className="px-3 py-2 font-medium">Title</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Entity</th>
            <th className="px-3 py-2 font-medium">Risk score</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id} className="border-b border-border-subtle last:border-0 hover:bg-elevated/40">
              <td className="px-3 py-2">
                <SeverityBadge severity={incident.severity} />
              </td>
              <td className="px-3 py-2">
                <MonoValue>{incident.display_id}</MonoValue>
              </td>
              <td className="px-3 py-2">
                <Link href={`/incidents/${incident.id}`} className="text-ink hover:text-accent hover:underline">
                  {incident.title}
                </Link>
              </td>
              <td className="px-3 py-2 text-ink-muted">{STATUS_LABELS[incident.status]}</td>
              <td className="px-3 py-2 text-ink-muted">
                {incident.primary_user ?? incident.primary_host ?? <span className="text-ink-faint">—</span>}
              </td>
              <td className="px-3 py-2">
                <MonoValue className="text-ink">
                  {incident.final_risk_score !== null ? incident.final_risk_score.toFixed(2) : "—"}
                </MonoValue>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
