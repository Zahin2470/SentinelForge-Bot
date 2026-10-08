import React from "react";
import { EmptyState } from "@/components/ui/StateMessages";
import { MonoValue, formatTimestamp, truncateId } from "@/components/ui/MonoValue";
import type { SecurityEvent } from "@/types/api";

export function EventsTable({ events }: { events: SecurityEvent[] }) {
  if (events.length === 0) {
    return (
      <EmptyState
        title="No events found"
        description="Ingest events via the API, or replay a demo scenario with `make simulate`."
      />
    );
  }

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-border bg-elevated text-xs text-ink-muted">
            <th className="px-3 py-2 font-medium">Timestamp</th>
            <th className="px-3 py-2 font-medium">Type</th>
            <th className="px-3 py-2 font-medium">User</th>
            <th className="px-3 py-2 font-medium">Host</th>
            <th className="px-3 py-2 font-medium">Source IP</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Event ID</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} className="border-b border-border-subtle last:border-0 hover:bg-elevated/40">
              <td className="px-3 py-2">
                <MonoValue>{formatTimestamp(event.timestamp)}</MonoValue>
              </td>
              <td className="px-3 py-2 text-ink">{event.event_type}</td>
              <td className="px-3 py-2 text-ink-muted">{event.username ?? <span className="text-ink-faint">—</span>}</td>
              <td className="px-3 py-2 text-ink-muted">{event.hostname ?? <span className="text-ink-faint">—</span>}</td>
              <td className="px-3 py-2">
                <MonoValue>{event.source_ip ?? "—"}</MonoValue>
              </td>
              <td className="px-3 py-2 text-ink-muted">{event.status ?? <span className="text-ink-faint">—</span>}</td>
              <td className="px-3 py-2">
                <MonoValue>{truncateId(event.id)}</MonoValue>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
