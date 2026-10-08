import React from "react";
import { cn } from "@/lib/cn";
import type { Severity } from "@/types/api";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "text-severity-critical bg-severity-critical-bg border-severity-critical/30",
  high: "text-severity-high bg-severity-high-bg border-severity-high/30",
  medium: "text-severity-medium bg-severity-medium-bg border-severity-medium/30",
  low: "text-severity-low bg-severity-low-bg border-severity-low/30",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

/** The single source of truth for how severity is rendered anywhere in
 * the product — every list, table, and detail panel uses this component
 * rather than reimplementing the color mapping, so severity always means
 * the same thing everywhere it appears. */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-xs font-medium",
        SEVERITY_STYLES[severity],
        className,
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
