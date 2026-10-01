# SentinelForge AI — Architecture

## 1. Purpose

SentinelForge AI is a defensive Security Operations Center (SOC) platform.
It ingests security telemetry, applies deterministic detection rules and a
statistical anomaly model, correlates related events into incidents, and
gives a human analyst an evidence-grounded, tool-using AI assistant to help
investigate those incidents. The AI never takes autonomous action; every
containment or remediation step is a recommendation requiring human approval.

This is a defensive simulation and analytics platform. It does not perform
exploitation, scanning of real external targets, credential theft, malware
generation, or destructive/attack automation of any kind.

## 2. Guiding principle

> AI is one component of the security system, not the security system itself.

```
Deterministic Systems  +  Statistical Models  +  Knowledge Retrieval  +  AI Reasoning
```

Not:

```
User → LLM → Everything
```

Concretely, this means:
- Alerts are never generated *by* the LLM. They come from Sigma-style rule
  matches or from the ML anomaly model.
- Risk scores are a transparent, auditable weighted sum of explicit
  components (rule score, anomaly score, correlation score, threat-intel
  score, asset criticality, identity context) — never a number the LLM
  invents.
- The LLM only sees data through typed, authorized, audited tool calls. It
  never has direct database or shell access.
- Every AI claim in an investigation report must be traceable to a specific
  event ID, detection rule ID, retrieved document, or tool result.

## 3. High-level data flow

```
Security Telemetry
      │
      ▼
Log Ingestion  (batch + near-real-time)
      │
      ▼
Normalization  (→ common security_event schema)
      │
      ▼
Rule-Based Detection (Sigma-style YAML rules)         ──┐
      │                                                  │
      ▼                                                  │  both feed
ML Anomaly Detection (Isolation Forest)               ──┘  risk scoring
      │
      ▼
Alert Correlation (temporal + entity-based)
      │
      ▼
Incident Creation
      │
      ▼
AI SOC Analyst (tool-using agent)
   ├─ Evidence Collection (search_security_events, get_event_by_id, ...)
   ├─ Threat Intelligence / IOC lookup
   ├─ Security Knowledge Retrieval (RAG over pgvector)
   ├─ MITRE ATT&CK mapping
   └─ Risk & Confidence Assessment
      │
      ▼
Analyst Recommendation + Structured Incident Report
      │
      ▼
Human Approval / Resolution  (analyst actions: acknowledge, assign,
                               escalate, note, mark FP, resolve, reopen)
      │
      ▼
Audit Log
```

## 4. System components

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | Next.js + TypeScript + Tailwind | SOC dashboard, incident workspace, live alert stream, copilot UI |
| Backend API | Python + FastAPI + Pydantic | REST/WebSocket API, auth, orchestration entrypoints |
| Worker | Python (RQ/Celery-style background worker) | Ingestion processing, detection execution, correlation, ML scoring |
| ML service | scikit-learn (Isolation Forest) | Feature extraction, anomaly scoring, model persistence |
| Agent layer | Backend module (`app/agents`) | AI SOC Analyst state machine + tool registry |
| RAG | PostgreSQL + pgvector | Chunked SOC knowledge base, semantic retrieval |
| Database | PostgreSQL | System of record: events, alerts, incidents, IOCs, audit log |
| Cache/Queue | Redis | Background job queue, pub/sub for live alert stream |
| Detection rules | Sigma-style YAML | Portable, declarative detection logic |

## 5. Backend module layout

```
backend/app/
├── api/            # FastAPI routers (thin — validate, call services, return schemas)
├── core/            config, security, logging, dependency wiring
├── models/           SQLAlchemy ORM models
├── schemas/          Pydantic request/response schemas
├── repositories/      data-access layer (no business logic)
├── services/         business logic, orchestrates repositories
├── detection/         Sigma-style rule parser, validator, executor
├── correlation/       temporal + entity correlation engine
├── ml/                feature engineering, Isolation Forest training/inference
├── agents/            agent state machine, tool registry, tool implementations
├── rag/               chunking, embeddings, retrieval, reranking
├── threat_intel/      IOC store, STIX/TAXII import, lookups
├── attack/            MITRE ATT&CK data + mapping helpers
├── ingest/            log ingestion + normalization
└── workers/           background job handlers
```

The layering rule: **API → services → repositories → database**. Business
logic never lives in API routers. The agent layer only reaches the database
through the same services layer other code uses — it does not get a private
shortcut.

## 6. Agent architecture (detail in `docs/ai/ai-agent.md`)

```
LLM
 │  (only ever emits: text, or a tool call with typed arguments)
 ▼
Agent tool  (typed input/output, authorization check, audit log)
 ▼
Authorized service  (same service layer as the REST API)
 ▼
Database / intelligence source
```

The LLM never receives raw database access or shell access. Every tool call
is logged with the run ID, incident ID, user, tool name, and a summary of
the result.

## 7. Risk scoring model (detail in `docs/architecture/risk-scoring.md` — TODO)

```
final_risk_score = f(
    rule_score,
    anomaly_score,
    correlation_score,
    threat_intelligence_score,
    asset_criticality,
    identity_context
)
```

Each component is computed by a deterministic, testable function and stored
alongside the final score — never hidden inside an LLM call.

## 8. Non-goals / explicit exclusions

- No autonomous containment (no auto-isolate host, auto-disable account,
  auto-block IP). These surface as *recommended* actions only.
- No offensive tooling: no real scanning, exploitation, or malware
  generation, even in "simulation" framing.
- No reliance on a single external commercial threat-intel API for core
  functionality — STIX/TAXII import uses local/sample intelligence for the
  demo.

## 9. Related documents

- `docs/setup.md` — local development setup
- `docs/security/threat-model.md` — STRIDE-style threat model + prompt
  injection defenses
- `docs/ml/ml-pipeline.md` — feature engineering & anomaly model
- `docs/ai/ai-agent.md` — agent state machine, tools, and safety controls
- `docs/detection-engine.md` — Sigma-style rule format and execution engine
- `docs/evaluation.md` — detection, ML, and agent evaluation methodology
