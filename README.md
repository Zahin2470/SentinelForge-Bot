# SentinelForge AI

**AI-Powered Security Operations Center — Detect → Correlate → Investigate → Explain**

> ⚠️ **Status: scaffolding / Phase 5.** What's implemented and actually
> tested right now: full architecture/security/ML/agent/evaluation docs;
> the repo skeleton; the SQLAlchemy data model + an initial Alembic
> migration (hand-written, not yet run against a live DB); a FastAPI app
> with health, event ingestion/search, detection-rule listing + manual run,
> alert listing, incident listing + manual correlation-run, and ML
> scoring endpoints; source normalizers for 5 log formats; a rule-type
> detection executor; a pure entity+temporal correlation engine; a
> transparent, renormalizing risk-scoring model; **a real trained
> Isolation Forest anomaly model** (feature extraction, training,
> persistence, and evaluation — not a stub); and a synthetic scenario
> pipeline proving the full chain — raw events → normalize → detect →
> correlate → risk-score — works correctly end-to-end, down to an exact
> asserted risk-score value. **72 tests pass in this environment**, all
> actually executed, including tests that train and score real sklearn
> models and assert the resulting precision/recall numbers (detection
> engine, correlation engine, risk scoring, normalizer, ML feature
> extraction + model training, and a full multi-stage scenario replay —
> the DB-backed repository/service/API layer is written and reviewed but
> unverified by execution here, since this dev environment has no network
> to install
> Postgres/SQLAlchemy/FastAPI). The dashboard, RAG, and the agent's tool
> implementations are not built yet — see
> `docs/architecture/architecture.md`'s "Development Phases" for what's
> next. Nothing below is asserted without a test behind it.

## What this is

SentinelForge AI is a defensive SOC platform: it ingests security telemetry
(synthetic, for demo/dev purposes), normalizes it, runs it through
deterministic Sigma-style detection rules **and** a real unsupervised ML
anomaly model, correlates related alerts into incidents, and gives a human
analyst a tool-using AI assistant that investigates an incident with
evidence-grounded reasoning — never autonomous action.

```
Security Telemetry → Ingestion → Normalization → Detection Rules
   → ML Anomaly Scoring → Correlation → Incident → AI SOC Analyst
   → Evidence + ATT&CK Mapping + Risk Score → Report → Human Approval
```

**Guiding principle:** AI is one component of the security system, not the
security system itself. Alerts come from rules or the ML model, never from
an LLM guessing. Risk scores are a transparent, auditable sum of explicit
components. The LLM only ever touches data through typed, authorized,
audited tool calls.

## What this is *not*

This is a portfolio-grade engineering and research project using synthetic
telemetry and public security knowledge sources. It is **not** a production
SIEM, EDR, or SOAR, does not replace a human security team, and does not
claim perfect accuracy, zero false positives, or "detects all attacks." It
also contains no offensive tooling: no real scanning, exploitation, malware,
persistence, or destructive automation — see
`docs/security/threat-model.md` §71/"Defensive Cybersecurity Only" for the
explicit boundary.

## Architecture

See `docs/architecture/architecture.md` for the full write-up. Summary of
components:

| Layer | Technology |
|---|---|
| Frontend | Next.js + TypeScript + Tailwind |
| Backend API | Python + FastAPI + Pydantic + SQLAlchemy + Alembic |
| Background workers | Python |
| Database | PostgreSQL + pgvector |
| Cache / queue | Redis |
| ML | scikit-learn (Isolation Forest) |
| Detection rules | Sigma-style YAML |
| AI agent | Provider-agnostic `LLMProvider` abstraction (Anthropic / OpenAI / local / mock) |

## Repository layout

```
sentinelforge-ai/
├── frontend/            Next.js SOC dashboard
├── backend/              FastAPI app (api, services, detection, ml, agents, rag, ...)
├── worker/                background job handlers
├── ml/                    training pipeline, notebooks
├── detection-rules/       Sigma-style YAML rules, by category
├── knowledge-base/        SOC playbooks & docs for RAG
├── scenarios/              labeled demo/evaluation scenarios
├── simulator/               synthetic telemetry generator
├── scripts/                  operational scripts (seed, train, evaluate)
├── evaluation/                generated evaluation results/reports
├── docs/                       architecture, security, ai, ml, api, deployment docs
├── tests/                      cross-cutting/e2e tests
├── docker/                     Dockerfiles / compose support files
└── docker-compose.yml
```

## Getting started

See `docs/setup.md` for the full guide. Quick version:

```bash
cp .env.example .env
docker compose up --build
docker compose exec backend alembic upgrade head
make seed
make simulate SCENARIO=brute_force_privilege_escalation
```

Then open the dashboard at `http://localhost:3000` and the API at
`http://localhost:8000/docs`.

## Detection engine

Sigma-style rules under `detection-rules/`, organized by
authentication/endpoint/network/cloud/application/correlation. See
`docs/detection-engine.md` for the rule format, engine design, and testing
approach.

## ML anomaly detection

Isolation Forest over windowed, per-entity behavioral features, producing an
`anomaly_score` with supporting features and stated limitations — never a
bare "malicious" verdict. See `docs/ml/ml-pipeline.md`.

## AI SOC Analyst

A state-machine-driven, tool-using agent with a fixed tool registry, strict
loop limits, prompt-injection defenses, and a validated structured output
schema. See `docs/ai/ai-agent.md`.

## Security

RBAC, audit logging, prompt-injection defenses, tool authorization, and a
full threat model are documented in `docs/security/threat-model.md`.

## Evaluation

Detection, ML, and agent components are measured against labeled scenarios
— see `docs/evaluation.md` for methodology. Results are generated (not
hand-written) into `evaluation/report.md` via `make evaluate`.

## Limitations

- Uses synthetic telemetry and public/sample security knowledge, not real
  organizational data.
- The ML model is unsupervised and can flag legitimate-but-rare behavior;
  see `docs/ml/ml-pipeline.md` §8.
- The AI agent's investigation depends on the events and documents it is
  given access to via tools; it does not have independent ground truth.
- Not a substitute for a production SIEM/EDR/SOAR or a human security team.

## License

See `LICENSE`.
