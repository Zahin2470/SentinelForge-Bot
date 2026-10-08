import React from "react";
export function PageHeader({ title, description }: { title: React.ReactNode; description?: string }) {
  return (
    <div className="border-b border-border px-6 py-4">
      <h1 className="text-base font-semibold text-ink">{title}</h1>
      {description && <p className="mt-0.5 text-sm text-ink-muted">{description}</p>}
    </div>
  );
}
