# Security Architecture Notes

**Category:** architecture

Background context an analyst or the AI SOC Analyst may need when
investigating an incident that touches SentinelForge's own environment
model — what an asset's criticality actually means, and how identity and
network context factor into an investigation.

## Asset criticality

Every known host/system in `assets` has a criticality tier (low, medium,
high, critical) and a numeric `criticality_score` (0–1) used directly as
the `asset_criticality_score` risk-scoring component
(`docs/architecture/risk-scoring.md`). Rough guidance for what belongs in
each tier:

- **Critical (0.85–1.0)** — domain controllers, identity providers,
  systems holding regulated data, core production databases. Compromise
  here has organization-wide blast radius.
- **High (0.7–0.85)** — VPN gateways, cloud control-plane access (e.g. the
  account/role that manages CloudTrail, IAM), CI/CD systems with broad
  deploy permissions.
- **Medium (0.35–0.6)** — ordinary employee workstations, internal
  line-of-business applications.
- **Low (0–0.3)** — test/staging systems, sandboxes, systems with no
  production data or broad access.

An anomaly on a critical asset should never be triaged with the same
urgency as the identical anomaly on a low-criticality asset — this is
exactly why asset criticality is a first-class, explicit risk-scoring
component rather than something left to an analyst's memory of which
hostnames matter.

## Network zones (conceptual model)

SentinelForge's synthetic environment models three loose zones:

- **Corporate/VPN** — where employee authentication and endpoint activity
  originates (`corp-vpn-gw`, workstations).
- **Cloud control plane** — where infrastructure-management actions
  happen (`aws-cloudtrail-main` and similar).
- **Application/data** — internal services and their data stores.

A single incident spanning multiple zones (e.g. a VPN login followed by a
cloud-control-plane logging change) is inherently higher-priority than an
incident confined to one zone, because it suggests lateral movement across
trust boundaries rather than activity contained to one system.

## Identity context (planned, not yet implemented)

`identity_context_score` in the risk-scoring model is reserved for signals
like: is this a privileged account, is this login consistent with the
account's established behavioral baseline (impossible travel, unusual
hour, new device), has this account been involved in a recent incident
before. None of this is implemented yet — it depends on the
behavioral-baseline service referenced throughout `docs/detection-engine.md`
and `docs/ml/ml-pipeline.md` as a documented gap, not a hidden one. Until
it exists, `identity_context_score` is always `None`, and
`compute_risk_score` correctly renormalizes around its absence rather than
treating "unknown identity risk" as "confirmed zero identity risk."

## Why this matters for investigation

When investigating an incident, always check both the technical evidence
(events, rule matches) *and* the environmental context (asset criticality,
network zone, what else is known about this identity) — a technically
identical alert can warrant very different urgency depending on where it
happened and to whom.
