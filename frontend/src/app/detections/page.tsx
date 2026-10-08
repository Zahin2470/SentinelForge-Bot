import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { EmptyState, ErrorState } from "@/components/ui/StateMessages";
import { RunActionButton } from "@/components/alerts/RunActionButton";
import { MonoValue } from "@/components/ui/MonoValue";
import { api, ApiError } from "@/lib/api";
import type { DetectionRule } from "@/types/api";

export const dynamic = "force-dynamic";

export default async function DetectionRulesPage() {
  let rules: DetectionRule[] = [];
  let loadError: string | null = null;

  try {
    rules = await api.listDetectionRules();
  } catch (err) {
    loadError = err instanceof ApiError ? err.message : "Could not reach the backend API.";
  }

  return (
    <div>
      <PageHeader
        title="Detection Rules"
        description="Sigma-style rules — see docs/detection-engine.md for the supported condition grammar."
      />
      <div className="flex items-center gap-2 border-b border-border px-6 py-3">
        <RunActionButton action="detection" label="Run detection now" />
      </div>
      <div className="p-6">
        {loadError && <ErrorState title="Could not load detection rules" message={loadError} />}
        {!loadError && rules.length === 0 && (
          <EmptyState
            title="No rules indexed yet"
            description="Run `make sync-detection-rules` (backend/scripts/sync_detection_rules.py) to index the YAML rules under detection-rules/ into the database."
          />
        )}
        {!loadError && rules.length > 0 && (
          <div className="overflow-x-auto rounded border border-border">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border bg-elevated text-xs text-ink-muted">
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Rule</th>
                  <th className="px-3 py-2 font-medium">Category</th>
                  <th className="px-3 py-2 font-medium">Technique</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Rule key</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-border-subtle last:border-0 hover:bg-elevated/40">
                    <td className="px-3 py-2">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="px-3 py-2 text-ink">{rule.title}</td>
                    <td className="px-3 py-2 text-ink-muted">{rule.category}</td>
                    <td className="px-3 py-2">
                      <MonoValue>{rule.attack_technique_id ?? "—"}</MonoValue>
                    </td>
                    <td className="px-3 py-2 text-ink-muted">{rule.enabled ? "Enabled" : "Disabled"}</td>
                    <td className="px-3 py-2">
                      <MonoValue>{rule.rule_key}</MonoValue>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
