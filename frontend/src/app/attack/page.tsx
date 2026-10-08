import { PageHeader } from "@/components/layout/PageHeader";
import { AttackCoverageMatrix } from "@/components/attack/AttackCoverageMatrix";
import { StatCard } from "@/components/ui/StatCard";
import { ErrorState } from "@/components/ui/StateMessages";
import { api, ApiError } from "@/lib/api";

export default async function AttackPage() {
  try {
    const coverage = await api.getAttackCoverage();
    return (
      <div>
        <PageHeader
          title="ATT&CK Coverage"
          description="Which MITRE ATT&CK techniques have a detection rule, and which have actually fired."
        />
        <div className="p-6">
          <div className="mb-6 grid grid-cols-3 gap-3">
            <StatCard label="Coverage" value={`${coverage.coverage_percent}%`} />
            <StatCard label="Techniques covered" value={coverage.covered_technique_ids.length} />
            <StatCard label="Techniques detected" value={coverage.detected_technique_ids.length} />
          </div>
          <AttackCoverageMatrix coverage={coverage} />
        </div>
      </div>
    );
  } catch (err) {
    return (
      <div>
        <PageHeader title="ATT&CK Coverage" />
        <div className="p-6">
          <ErrorState
            title="Could not load coverage data"
            message={err instanceof ApiError ? err.message : "Could not reach the backend API."}
          />
        </div>
      </div>
    );
  }
}
