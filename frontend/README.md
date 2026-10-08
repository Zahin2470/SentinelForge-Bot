# SentinelForge AI — Frontend

Next.js 14 (App Router) + TypeScript + Tailwind. See
`docs/architecture/architecture.md` for how this fits into the rest of the
system.

## Status

Built and reviewed; **not executable in this dev environment** — there is
no network access to `npm install` (`next`, `react`, `@types/react`, etc.
all fail to fetch), so this could never be `next dev`'d or `next build`'t
here. What *was* verified in this environment, for real:

- **37 render smoke tests** (`tests/render-smoke.tsx`) actually render the
  9 framework-agnostic presentational components — `SeverityBadge`,
  `StatCard`, `EmptyState`/`LoadingState`/`ErrorState`, `MonoValue`,
  `PageHeader`, `RiskScoreBreakdown`, `AttackCoverageMatrix`,
  `InvestigationReportCard`, `EventsTable` — with `react-dom/server`
  against data shaped exactly like the real backend API responses, and
  assert on the actual output markup (e.g. "a null risk-score component
  renders as `n/a`, never silently as `0.00`"; "the AI report card always
  renders the human-approval statement"). Run with:
  ```bash
  NODE_PATH=<path-to-global-node_modules> npx tsx tests/render-smoke.tsx
  ```
- Every internal `@/...` import was cross-checked against real file paths
  and real named exports — no broken imports anywhere in the tree.
- Components that import `next/link` or `next/navigation` (`Sidebar`,
  `RunActionButton`, the link cells in `AlertsTable`/`IncidentsTable`)
  could not be rendered here (`next` itself isn't installable offline) —
  reviewed by hand instead, same "written and reviewed, not executed"
  caveat that applies to every DB-touching backend module in this repo.
- Full `tsc` type-checking against the real `next`/`@types/react` type
  definitions wasn't possible for the same reason (no network to install
  them). The 9 rendered components were confirmed to compile and run
  correctly via `tsx` (which transpiles but doesn't type-check), and every
  cross-file import/export pair was verified to match by direct
  inspection — real evidence, just not the same as a clean `tsc` pass.

Once you `npm install` in a real environment, `npm run typecheck` and
`npm run dev` are the first things to run to close that gap.

## Design system

See the reasoning in `docs/architecture/architecture.md`'s frontend
section and the code comments in `src/app/globals.css` /
`tailwind.config.ts`. Summary: a deep steel-navy palette (not generic
near-black), severity color reserved as the *only* saturated color in the
entire UI, Inter for interface text paired with IBM Plex Mono specifically
for technical data (event IDs, hashes, IPs, timestamps) — not decoration.
AI-generated content (`InvestigationReportCard`) always gets a visually
distinct treatment from ground-truth system data, reinforcing the
product's own stated philosophy that AI is one component of the system,
not the whole system.

## Structure

```
src/
├── app/                  Next.js App Router pages
│   ├── dashboard/
│   ├── alerts/
│   ├── incidents/[id]/    per-incident investigation view
│   ├── events/
│   ├── detections/
│   ├── threat-intel/
│   ├── attack/            ATT&CK coverage matrix
│   ├── copilot/           knowledge-base search
│   └── knowledge/         corpus management (re-index)
├── components/
│   ├── ui/                 SeverityBadge, StatCard, StateMessages, MonoValue
│   ├── layout/              Sidebar, PageHeader
│   ├── alerts/ incidents/ events/ attack/ copilot/
├── lib/
│   ├── api.ts               typed fetch client (proxied via next.config.js rewrites)
│   └── cn.ts
└── types/api.ts             mirrors backend/app/schemas + api response shapes
```

## Local development (once `npm install` can reach the network)

```bash
npm install
npm run dev       # http://localhost:3000, proxies /api/* to the backend
npm run typecheck
npm run lint
NODE_PATH=$(npm root -g) npx tsx tests/render-smoke.tsx
```

Or via Docker Compose from the repo root: `docker compose up` brings up
the frontend alongside the backend, Postgres, and Redis.
