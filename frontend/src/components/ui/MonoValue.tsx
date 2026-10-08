import React from "react";
import { cn } from "@/lib/cn";

/** Wraps a piece of technical data (event ID, hash, IP, timestamp) in the
 * monospace face. Used specifically for values an analyst needs to scan,
 * compare, and copy exactly — never applied to ordinary labels or prose,
 * where monospace would just be decoration. */
export function MonoValue({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[13px] text-ink-muted", className)}>{children}</span>;
}

export function truncateId(id: string, length = 8): string {
  return id.length > length ? `${id.slice(0, length)}…` : id;
}

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}
