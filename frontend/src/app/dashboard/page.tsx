import { PageHeader } from "@/components/layout/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { AlertsTable } from "@/components/alerts/AlertsTable";
import { IncidentsTable } from "@/components/incidents/IncidentsTable";
import { ErrorState } from "@/components/ui/StateMessages";
import { api, ApiError } from "@/lib/api";
import type { Alert, Incident } from "@/types/api";

/** Server Component: fetches on the server so the dashboard's first paint
 * already has real data, no client-side loading flash for the primary
 * view an analyst lands on. */
export default async function DashboardPage() {
  let incidents: Incident[] = [];
  let alerts: Alert[] = [];
  let loadError: string | null = null;

  try {
    [incidents, alerts] = await Promise.all([api.listIncidents(), api.listUnassignedAlerts()]);
  } catch (err) {
    loadError = err instanceof ApiError ? err.message : "Could not reach the backend API.";
  }

  const openIncidents = incidents.filter((i) => !["RESOLVED", "FALSE_POSITIVE", "CLOSED"].includes(i.status));
  const criticalCount = openIncidents.filter((i) => i.severity === "critical").length;
  const highCount = openIncidents.filter((i) => i.severity === "high").length;

  return (
    <div>
      <PageHeader title="Dashboard" description="Current SOC posture at a glance." />

      <div className="p-6">
        {loadError && (
          <div className="mb-6">
            <ErrorState title="Could not load dashboard data" message={loadError} />
          </div>
        )}

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard label="Open incidents" value={openIncidents.length} />
          <StatCard label="Critical" value={criticalCount} tone={criticalCount > 0 ? "critical" : "default"} />
          <StatCard label="High" value={highCount} tone={highCount > 0 ? "high" : "default"} />
          <StatCard label="Unassigned alerts" value={alerts.length} />
        </div>

        <section className="mt-8">
          <h2 className="mb-3 text-sm font-medium text-ink">Recent incidents</h2>
          <IncidentsTable incidents={incidents.slice(0, 8)} />
        </section>

        <section className="mt-8">
          <h2 className="mb-3 text-sm font-medium text-ink">Unassigned alerts</h2>
          <AlertsTable alerts={alerts.slice(0, 8)} />
        </section>
      </div>
    </div>
  );
}
