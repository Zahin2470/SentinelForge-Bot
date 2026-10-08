import { PageHeader } from "@/components/layout/PageHeader";
import { KnowledgeSearchPanel } from "@/components/copilot/KnowledgeSearchPanel";

export default function CopilotPage() {
  return (
    <div>
      <PageHeader
        title="AI Copilot"
        description="Search SOC playbooks and reference knowledge, or open an incident to run a full investigation."
      />
      <div className="p-6">
        <KnowledgeSearchPanel />
      </div>
    </div>
  );
}
