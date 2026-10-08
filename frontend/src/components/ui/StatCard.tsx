import React from "react";
import { cn } from "@/lib/cn";

interface StatCardProps {
  label: string;
  value: string | number;
  tone?: "default" | "critical" | "high";
  hint?: string;
}

/** A big-number summary tile. Tone is used sparingly — only when the
 * number itself represents something that should draw the eye (e.g. open
 * critical incidents), never decoratively. */
export function StatCard({ label, value, tone = "default", hint }: StatCardProps) {
  return (
    <div className="rounded border border-border bg-panel p-4">
      <div className="text-xs font-medium text-ink-muted">{label}</div>
      <div
        className={cn(
          "mt-1.5 font-mono text-2xl font-semibold tabular-nums",
          tone === "critical" && "text-severity-critical",
          tone === "high" && "text-severity-high",
          tone === "default" && "text-ink",
        )}
      >
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-ink-faint">{hint}</div>}
    </div>
  );
}
