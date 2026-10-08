import { PageHeader } from "@/components/layout/PageHeader";
import { AlertsTable } from "@/components/alerts/AlertsTable";
import { ErrorState } from "@/components/ui/StateMessages";
import { RunActionButton } from "@/components/alerts/RunActionButton";
import { api, ApiError } from "@/lib/api";
import type { Alert } from "@/types/api";

export const dynamic = "force-dynamic"; // always fresh — this is the live triage view

export default async function AlertsPage() {
  let alerts: Alert[] = [];
  let loadError: string | null = null;

  try {
    alerts = await api.listUnassignedAlerts();
  } catch (err) {
    loadError = err instanceof ApiError ? err.message : "Could not reach the backend API.";
  }

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Alerts not yet grouped into an incident. Correlation groups related alerts automatically."
      />

      <div className="flex items-center gap-2 border-b border-border px-6 py-3">
        <RunActionButton action="detection" label="Run detection" />
        <RunActionButton action="correlation" label="Run correlation" />
      </div>

      <div className="p-6">
        {loadError ? <ErrorState title="Could not load alerts" message={loadError} /> : <AlertsTable alerts={alerts} />}
      </div>
    </div>
  );
}
