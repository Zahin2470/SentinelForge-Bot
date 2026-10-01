# Setup Guide (macOS + VS Code)

## Prerequisites

- macOS with Docker Desktop installed and running
- VS Code
- Git
- Node.js (LTS) — only needed if you want to run the frontend outside Docker
- Python 3.12+ — only needed if you want to run backend tools outside Docker

This project is designed to run primarily through Docker Compose so you do
not need a locally-matching Python/Node version. Native installs are only
useful for editor tooling (autocomplete, linting) and running scripts
directly.

## 1. Clone and configure

```bash
git clone <repo-url> sentinelforge-ai
cd sentinelforge-ai
cp .env.example .env
```

Open `.env` and set:
- `LLM_PROVIDER` and the matching API key (or leave unset to run in
  rule/ML-only mode — the agent layer degrades gracefully, see
  `docs/ai/ai-agent.md`)
- `POSTGRES_PASSWORD` — any local dev value is fine

## 2. Start the stack

```bash
docker compose up --build
```

This brings up:

| Service | Port | Purpose |
|---|---|---|
| frontend | 3000 | Next.js SOC dashboard |
| backend | 8000 | FastAPI API + WebSocket/SSE |
| worker | — | Background ingestion/detection/correlation |
| postgres | 5432 | Primary datastore (+ pgvector) |
| redis | 6379 | Queue + pub/sub |

Health checks:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/health/ready
```

## 3. Run database migrations

```bash
docker compose exec backend alembic upgrade head
```

## 4. Seed demo data

```bash
make seed
# or, without Make:
docker compose exec backend python scripts/seed_demo_data.py
```

## 5. Run a demo scenario

```bash
make simulate SCENARIO=brute_force_privilege_escalation
```

This replays a scripted sequence of normalized events through the ingestion
pipeline so you can watch detection → correlation → incident → AI
investigation happen end-to-end. See `docs/security/threat-model.md` and
`scenarios/` for what's included.

## 6. Common commands

```bash
make setup      # first-time environment setup
make dev        # docker compose up --build
make test       # run backend + frontend test suites
make lint       # Ruff + mypy + ESLint
make format     # Ruff format + Prettier
make seed       # load demo data
make simulate   # replay a scenario
make evaluate   # run detection/ML/agent evaluation suite
make clean      # tear down containers + volumes
```

If `make` is unavailable, the equivalent direct commands are documented
inline in the `Makefile` itself — each target is a one-line wrapper around a
`docker compose exec ...` or `docker compose run ...` call.

## 7. Editor setup (VS Code)

Recommended extensions (see `.vscode/extensions.json` once scaffolded):
- Python (with Ruff + mypy integration)
- ESLint + Prettier
- Docker
- YAML (for Sigma-style detection rules)

No paths in this project are hard-coded to `/home/...` or `/usr/bin/...`;
everything is resolved relative to the repo root or through environment
variables so it behaves the same on macOS, Linux CI runners, and inside
containers.

## 8. Troubleshooting

- **Port already in use** — another local Postgres/Redis on 5432/6379 will
  conflict; stop it or remap the port in `docker-compose.override.yml`.
- **pgvector extension missing** — the `postgres` service uses an image with
  `pgvector` preinstalled; the first migration enables the extension with
  `CREATE EXTENSION IF NOT EXISTS vector`.
- **LLM calls failing** — if no `LLM_PROVIDER` key is set, the AI SOC
  Analyst endpoints return a clear "AI analysis unavailable — no model
  configured" response rather than failing silently; rules/ML/correlation
  still work fully without it.
