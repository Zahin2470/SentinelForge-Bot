/**
 * Render smoke tests — actually renders components with react-dom/server
 * against data shaped exactly like the real backend API responses
 * (see frontend/src/types/api.ts), and asserts on the output markup.
 *
 * Scope note: this environment has no network access, so `next`, its
 * types, and this project's own node_modules can't be installed here —
 * only the globally-available react/react-dom/typescript packages are
 * usable. Components that import next/link or next/navigation
 * (Sidebar, RunActionButton, the Link cells in AlertsTable/IncidentsTable)
 * can't be rendered in this environment for that reason and are reviewed
 * by hand instead — the same "written and reviewed, not executed" caveat
 * as every DB-touching backend module. Every other presentational
 * component — the ones that carry the real visual/logic weight of the
 * design (severity encoding, risk-score breakdown, ATT&CK matrix, the
 * AI-content treatment) — IS rendered here for real.
 *
 * Run with:
 *   NODE_PATH=/home/claude/.npm-global/lib/node_modules npx tsx tests/render-smoke.tsx
 */

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { SeverityBadge } from "../src/components/ui/SeverityBadge";
import { StatCard } from "../src/components/ui/StatCard";
import { EmptyState, ErrorState, LoadingState } from "../src/components/ui/StateMessages";
import { MonoValue, formatTimestamp, truncateId } from "../src/components/ui/MonoValue";
import { PageHeader } from "../src/components/layout/PageHeader";
import { RiskScoreBreakdown } from "../src/components/incidents/RiskScoreBreakdown";
import { AttackCoverageMatrix } from "../src/components/attack/AttackCoverageMatrix";
import { InvestigationReportCard } from "../src/components/incidents/InvestigationReportCard";
import { EventsTable } from "../src/components/events/EventsTable";
import type { Incident, AttackCoverage, InvestigationReport, SecurityEvent } from "../src/types/api";

let failures = 0;
let passed = 0;

function check(name: string, condition: boolean, detail?: string) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${name}`);
  } else {
    failures++;
    console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function render(el: React.ReactElement): string {
  return renderToStaticMarkup(el);
}

// --- SeverityBadge: the single most important visual signal in the product ---
console.log("SeverityBadge");
{
  const critical = render(<SeverityBadge severity="critical" />);
  const low = render(<SeverityBadge severity="low" />);
  check("critical renders the word Critical", critical.includes("Critical"));
  check("low renders the word Low", low.includes("Low"));
  check("critical and low use different color classes", critical !== low);
  check("critical uses the severity-critical color token", critical.includes("severity-critical"));
}

// --- StatCard: tone must actually change the rendered class ---
console.log("StatCard");
{
  const defaultCard = render(<StatCard label="Open incidents" value={12} />);
  const criticalCard = render(<StatCard label="Critical" value={3} tone="critical" />);
  check("renders the label", defaultCard.includes("Open incidents"));
  check("renders the numeric value", defaultCard.includes("12"));
  check("critical tone applies the critical color class", criticalCard.includes("severity-critical"));
  check("default tone does NOT apply the critical color class", !defaultCard.includes("severity-critical"));
}

// --- State messages ---
console.log("State messages");
{
  const empty = render(<EmptyState title="No incidents" description="Nothing here yet." />);
  const error = render(<ErrorState message="Backend unreachable" />);
  const loading = render(<LoadingState />);
  check("empty state renders title and description", empty.includes("No incidents") && empty.includes("Nothing here yet"));
  check("error state renders the message", error.includes("Backend unreachable"));
  check("error state has a role/visual marker for critical color", error.includes("severity-critical"));
  check("loading state has a status role for screen readers", loading.includes('role="status"'));
}

// --- MonoValue / formatting helpers ---
console.log("MonoValue helpers");
{
  const mono = render(<MonoValue>evt-00000000-abcd</MonoValue>);
  check("renders in a font-mono span", mono.includes("font-mono"));
  check("truncateId shortens a long id", truncateId("evt-00000000-abcd-1234", 8) === "evt-0000…");
  check("truncateId leaves a short id untouched", truncateId("short", 8) === "short");
  const ts = formatTimestamp("2026-01-01T09:05:00.123Z");
  check("formatTimestamp produces a readable, space-separated format", ts === "2026-01-01 09:05:00Z", ts);
}

// --- PageHeader ---
console.log("PageHeader");
{
  const header = render(<PageHeader title="Incidents" description="Correlated alert groups." />);
  check("renders title and description", header.includes("Incidents") && header.includes("Correlated alert groups."));
}

// --- RiskScoreBreakdown: the transparent-scoring UI requirement ---
console.log("RiskScoreBreakdown");
{
  const incidentAllComponents: Incident = {
    id: "inc-1", display_id: "INC-0001", title: "Brute force", severity: "critical", status: "OPEN",
    rule_score: 1.0, anomaly_score: null, correlation_score: 0.2, threat_intelligence_score: 1.0,
    asset_criticality_score: null, identity_context_score: null, final_risk_score: 0.76,
    primary_host: "corp-vpn-gw", primary_user: "jdoe",
  };
  const markup = render(<RiskScoreBreakdown incident={incidentAllComponents} />);
  check("renders the final risk score", markup.includes("0.76"));
  check("renders a value for an available component (rule score 1.00)", markup.includes("1.00"));
  check("renders 'n/a' for a null component (anomaly_score), not 0", markup.includes("n/a"));
  check("does NOT silently render a null component as 0.00", !markup.match(/n\/a.*0\.00|0\.00.*n\/a/));

  const noScoreYet: Incident = { ...incidentAllComponents, final_risk_score: null };
  const noScoreMarkup = render(<RiskScoreBreakdown incident={noScoreYet} />);
  check("renders an em-dash placeholder when final_risk_score is null, not '0.00' or 'null'", noScoreMarkup.includes("—") && !noScoreMarkup.includes("null"));
}

// --- AttackCoverageMatrix ---
console.log("AttackCoverageMatrix");
{
  const coverage: AttackCoverage = {
    total_techniques: 9,
    covered_technique_ids: ["T1110", "T1562"],
    uncovered_technique_ids: ["T1078", "T1098", "T1059.001", "T1071", "T1595", "T1499"],
    detected_technique_ids: ["T1110"],
    coverage_percent: 22.2,
  };
  const markup = render(<AttackCoverageMatrix coverage={coverage} />);
  check("renders a detected technique's ID", markup.includes("T1110"));
  check("renders a covered-but-not-detected technique's ID", markup.includes("T1562"));
  check("renders an uncovered technique's ID", markup.includes("T1078"));
  check("groups by tactic (Credential Access appears)", markup.includes("Credential Access"));
  check("legend explains all three states", markup.includes("Detected") && markup.includes("Covered") && markup.includes("Uncovered"));
}

// --- InvestigationReportCard: AI content must be visually distinct ---
console.log("InvestigationReportCard");
{
  const report: InvestigationReport = {
    classification: "brute_force_credential_access",
    severity: "critical",
    confidence: 0.88,
    summary: "Repeated failed logins from a known-malicious IP.",
    evidence: ["evt-1", "evt-2"],
    attack_mapping: [{ technique_id: "T1110", technique_name: "Brute Force" }],
    recommended_next_steps: ["Reset the account credentials.", "Re-enable the disabled logging control."],
    evidence_sources: ["Internal SOC Playbook — Brute Force / Credential Access Incident (playbooks)"],
    human_approval_statement: "No automatic containment action was executed. Human analyst approval is required.",
  };
  const markup = render(<InvestigationReportCard report={report} />);
  check("labels the content as AI-generated", markup.includes("AI-generated"));
  check("renders the confidence percentage", markup.includes("88%"));
  check("renders the ATT&CK technique chip", markup.includes("T1110") && markup.includes("Brute Force"));
  check("renders recommended next steps", markup.includes("Reset the account credentials."));
  check("renders the evidence source citation", markup.includes("Internal SOC Playbook"));
  check("always renders the human-approval statement", markup.includes("Human analyst approval is required"));
  check("uses a visually distinct (dashed accent border) treatment", markup.includes("border-dashed"));
}

// --- EventsTable ---
console.log("EventsTable");
{
  const events: SecurityEvent[] = [
    {
      id: "evt-1", timestamp: "2026-01-01T09:00:00Z", ingested_at: "2026-01-01T09:00:01Z",
      source: "corp_vpn", source_type: "authentication", hostname: "corp-vpn-gw", username: "jdoe",
      source_ip: "198.51.100.23", destination_ip: null, destination_port: null, process_name: null,
      command_line: null, event_type: "authentication", action: null, status: "failure", severity: "info",
    },
  ];
  const markup = render(<EventsTable events={events} />);
  check("renders the username", markup.includes("jdoe"));
  check("renders the source IP", markup.includes("198.51.100.23"));
  check("empty state shown for zero events", render(<EventsTable events={[]} />).includes("No events found"));
}

console.log(`\n${passed} passed, ${failures} failed.`);
if (failures > 0) process.exit(1);
