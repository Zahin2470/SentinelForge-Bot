import { PageHeader } from "@/components/layout/PageHeader";
import { IncidentsTable } from "@/components/incidents/IncidentsTable";
import { ErrorState } from "@/components/ui/StateMessages";
import { api, ApiError } from "@/lib/api";
import type { Incident } from "@/types/api";

export const dynamic = "force-dynamic";

export default async function IncidentsPage() {
  let incidents: Incident[] = [];
  let loadError: string | null = null;

  try {
    incidents = await api.listIncidents();
  } catch (err) {
    loadError = err instanceof ApiError ? err.message : "Could not reach the backend API.";
  }

  return (
    <div>
      <PageHeader title="Incidents" description="Correlated alert groups, ranked by risk score." />
      <div className="p-6">
        {loadError ? (
          <ErrorState title="Could not load incidents" message={loadError} />
        ) : (
          <IncidentsTable incidents={incidents} />
        )}
      </div>
    </div>
  );
}
