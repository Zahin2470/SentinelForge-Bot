import Link from "next/link";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { EmptyState } from "@/components/ui/StateMessages";
import { MonoValue, formatTimestamp, truncateId } from "@/components/ui/MonoValue";
import type { Alert } from "@/types/api";

const SOURCE_LABELS: Record<Alert["source"], string> = {
  rule: "Rule",
  ml: "ML",
  threat_intel: "Threat Intel",
};

export function AlertsTable({ alerts }: { alerts: Alert[] }) {
  if (alerts.length === 0) {
    return (
      <EmptyState
        title="No unassigned alerts"
        description="Every alert has been grouped into an incident, or none have fired yet. Run detection or correlation to generate activity."
      />
    );
  }

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-border bg-elevated text-xs text-ink-muted">
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Title</th>
            <th className="px-3 py-2 font-medium">Source</th>
            <th className="px-3 py-2 font-medium">Entity</th>
            <th className="px-3 py-2 font-medium">Detected</th>
            <th className="px-3 py-2 font-medium">Alert ID</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-b border-border-subtle last:border-0 hover:bg-elevated/40">
              <td className="px-3 py-2">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="px-3 py-2 text-ink">{alert.title}</td>
              <td className="px-3 py-2 text-ink-muted">{SOURCE_LABELS[alert.source]}</td>
              <td className="px-3 py-2 text-ink-muted">
                {alert.entity_username ?? alert.entity_hostname ?? (
                  <span className="text-ink-faint">—</span>
                )}
              </td>
              <td className="px-3 py-2">
                <MonoValue>{formatTimestamp(alert.created_at)}</MonoValue>
              </td>
              <td className="px-3 py-2">
                <MonoValue>{truncateId(alert.id)}</MonoValue>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function IncidentAlertLink({ incidentId, children }: { incidentId: string; children: React.ReactNode }) {
  return (
    <Link href={`/incidents/${incidentId}`} className="text-accent hover:underline">
      {children}
    </Link>
  );
}
