// Mirrors backend/app/schemas/* and backend/app/api/*'s response models.
// Kept as one file since the whole surface is still small — split by
// domain (events.ts, incidents.ts, ...) if this grows past a few hundred
// lines.

export type Severity = "low" | "medium" | "high" | "critical";

export type IncidentStatus =
  | "OPEN"
  | "TRIAGED"
  | "INVESTIGATING"
  | "CONTAINMENT_RECOMMENDED"
  | "AWAITING_REVIEW"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | "CLOSED";

export interface SecurityEvent {
  id: string;
  timestamp: string;
  ingested_at: string;
  source: string;
  source_type: string;
  hostname: string | null;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  process_name: string | null;
  command_line: string | null;
  event_type: string;
  action: string | null;
  status: string | null;
  severity: string;
}

export interface Alert {
  id: string;
  created_at: string;
  source: "rule" | "ml" | "threat_intel";
  detection_rule_id: string | null;
  title: string;
  severity: Severity;
  matched_event_ids: string[];
  entity_username: string | null;
  entity_hostname: string | null;
  incident_id: string | null;
}

export interface Incident {
  id: string;
  display_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  rule_score: number | null;
  anomaly_score: number | null;
  correlation_score: number | null;
  threat_intelligence_score: number | null;
  asset_criticality_score: number | null;
  identity_context_score: number | null;
  final_risk_score: number | null;
  primary_host: string | null;
  primary_user: string | null;
}

export interface DetectionRule {
  id: string;
  rule_key: string;
  title: string;
  category: string;
  severity: Severity;
  tags: string[];
  attack_technique_id: string | null;
  enabled: boolean;
}

export interface AttackCoverage {
  total_techniques: number;
  covered_technique_ids: string[];
  uncovered_technique_ids: string[];
  detected_technique_ids: string[];
  coverage_percent: number;
}

export interface IOC {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  threat_level: string;
}

export interface RagSearchResult {
  chunk_id: string;
  score: number;
  content: string;
  document_title: string;
  source: string;
}

export interface AttackMapping {
  technique_id: string;
  technique_name: string;
}

export interface InvestigationReport {
  classification: string;
  severity: Severity;
  confidence: number;
  summary: string;
  evidence: string[];
  attack_mapping: AttackMapping[];
  recommended_next_steps: string[];
  evidence_sources: string[];
  human_approval_statement: string;
}

export interface InvestigateResponse {
  run_id: string;
  incident_id: string;
  status: string;
  report: InvestigationReport | null;
  failure_reason: string | null;
}
