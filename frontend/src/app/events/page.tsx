import { PageHeader } from "@/components/layout/PageHeader";
import { EventsTable } from "@/components/events/EventsTable";
import { ErrorState } from "@/components/ui/StateMessages";
import { api, ApiError } from "@/lib/api";
import type { SecurityEvent } from "@/types/api";

export const dynamic = "force-dynamic";

interface EventsPageProps {
  searchParams: { username?: string; hostname?: string; event_type?: string };
}

/** Raw normalized event search — the ground-truth layer everything else
 * (alerts, incidents, AI reports) is ultimately built from. Filters are
 * plain query params rather than client state so a filtered view is a
 * shareable, bookmarkable URL. */
export default async function EventsPage({ searchParams }: EventsPageProps) {
  let events: SecurityEvent[] = [];
  let loadError: string | null = null;

  try {
    events = await api.searchEvents({ ...searchParams, limit: "100" });
  } catch (err) {
    loadError = err instanceof ApiError ? err.message : "Could not reach the backend API.";
  }

  return (
    <div>
      <PageHeader title="Events" description="Normalized security events, most recent first." />
      <div className="p-6">
        {loadError ? <ErrorState title="Could not load events" message={loadError} /> : <EventsTable events={events} />}
      </div>
    </div>
  );
}
