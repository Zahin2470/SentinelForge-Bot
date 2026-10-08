import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { RiskScoreBreakdown } from "@/components/incidents/RiskScoreBreakdown";
import { CopilotPanel } from "@/components/copilot/CopilotPanel";
import { MonoValue } from "@/components/ui/MonoValue";
import { ApiError, api } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function IncidentDetailPage({ params }: { params: { id: string } }) {
  let incident;
  try {
    incident = await api.getIncident(params.id);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }

  return (
    <div>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <MonoValue className="text-ink-faint">{incident.display_id}</MonoValue>
            {incident.title}
          </span>
        }
      />

      <div className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <div className="rounded border border-border bg-panel p-4">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <span className="text-xs text-ink-muted">{incident.status.replace(/_/g, " ").toLowerCase()}</span>
            </div>
            <dl className="mt-4 grid grid-cols-2 gap-4 text-sm">
              <div>
                <dt className="text-xs text-ink-muted">Primary user</dt>
                <dd className="mt-0.5 text-ink">{incident.primary_user ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-xs text-ink-muted">Primary host</dt>
                <dd className="mt-0.5 text-ink">{incident.primary_host ?? "—"}</dd>
              </div>
            </dl>
          </div>

          <CopilotPanel incidentId={incident.id} />
        </div>

        <div>
          <RiskScoreBreakdown incident={incident} />
        </div>
      </div>

      <div className="px-6 pb-6">
        <Link href="/incidents" className="text-xs text-ink-muted hover:text-accent hover:underline">
          ← Back to incidents
        </Link>
      </div>
    </div>
  );
}
