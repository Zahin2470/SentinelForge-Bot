import React from "react";
interface EmptyStateProps {
  title: string;
  description?: string;
}

/** An empty screen is an invitation to act, not a dead end — always says
 * what's missing and, where possible, what would fill it. */
export function EmptyState({ title, description }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded border border-dashed border-border px-6 py-16 text-center">
      <div className="text-sm font-medium text-ink">{title}</div>
      {description && <div className="mt-1.5 max-w-sm text-sm text-ink-muted">{description}</div>}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-6 py-16 text-sm text-ink-muted" role="status">
      <span
        className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-border border-t-accent"
        aria-hidden="true"
      />
      {label}
    </div>
  );
}

interface ErrorStateProps {
  title?: string;
  message: string;
}

/** Errors don't apologize and are never vague about what happened —
 * states exactly what failed. */
export function ErrorState({ title = "Something went wrong", message }: ErrorStateProps) {
  return (
    <div className="rounded border border-severity-critical/30 bg-severity-critical-bg px-4 py-3">
      <div className="text-sm font-medium text-severity-critical">{title}</div>
      <div className="mt-1 text-sm text-ink-muted">{message}</div>
    </div>
  );
}
