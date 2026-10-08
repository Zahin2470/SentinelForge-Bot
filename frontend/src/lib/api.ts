// Thin typed fetch wrapper. Server Components call these directly; the
// rewrite in next.config.js means a relative "/api/..." path always
// reaches the backend, in both server-side and client-side calls, without
// CORS configuration.

import type {
  Alert,
  AttackCoverage,
  DetectionRule,
  Incident,
  InvestigateResponse,
  IOC,
  RagSearchResult,
  SecurityEvent,
} from "@/types/api";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    // Dashboard data should always be fresh — an analyst triaging live
    // alerts must never see a stale cached response.
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, body || res.statusText);
  }
  return res.json() as Promise<T>;
}

export const api = {
  listIncidents: (status?: string) =>
    request<Incident[]>(`/api/v1/incidents${status ? `?status_filter=${status}` : ""}`),

  getIncident: (id: string) => request<Incident>(`/api/v1/incidents/${id}`),

  runCorrelation: () => request<{ incidents_created: number; incident_display_ids: string[] }>(
    "/api/v1/incidents/correlate",
    { method: "POST" },
  ),

  listUnassignedAlerts: () => request<Alert[]>("/api/v1/alerts/unassigned"),

  searchEvents: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request<SecurityEvent[]>(`/api/v1/events/search${qs ? `?${qs}` : ""}`);
  },

  listDetectionRules: () => request<DetectionRule[]>("/api/v1/detection-rules"),

  runDetection: () =>
    request<{ rules_evaluated: number; matches: number; unsupported: number }>(
      "/api/v1/detection-rules/run",
      { method: "POST" },
    ),

  getAttackCoverage: () => request<AttackCoverage>("/api/v1/attack/coverage"),

  listIOCs: () => request<IOC[]>("/api/v1/threat-intel/iocs"),

  importThreatIntelFeed: (feedPath = "threat-intel/sample_feed.json") =>
    request<{ imported: number; skipped: number; skip_reasons: string[] }>("/api/v1/threat-intel/import", {
      method: "POST",
      body: JSON.stringify({ feed_path: feedPath }),
    }),

  runThreatIntelMatch: () =>
    request<{ alerts_created: number; matches: unknown[] }>("/api/v1/threat-intel/match", { method: "POST" }),

  ingestKnowledgeBase: () =>
    request<{ documents_ingested: number; chunks_ingested: number }>(
      `/api/v1/rag/ingest?${new URLSearchParams({ kb_dir: "knowledge-base" })}`,
      { method: "POST" },
    ),

  searchKnowledge: (q: string, k = 5) =>
    request<RagSearchResult[]>(`/api/v1/rag/search?${new URLSearchParams({ q, k: String(k) })}`),

  investigateIncident: (incidentId: string, actorRole = "SOC_ANALYST") =>
    request<InvestigateResponse>(
      `/api/v1/agent/investigate/${incidentId}?actor_role=${actorRole}`,
      { method: "POST" },
    ),
};

export { ApiError };
