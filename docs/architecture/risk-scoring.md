# Risk Scoring

Implemented in `app/services/risk_scoring.py`, tested in
`backend/tests/services/test_risk_scoring.py` (8 passing tests). This
document explains the *why* behind the implementation; see the module
docstring for the current numbers.

## The rule

`final_risk_score` is a transparent, auditable combination of independently
computed components. It is never a number an LLM produces — every incident
stores each component alongside the final score
(`app/models/incident.py`: `rule_score`, `anomaly_score`,
`correlation_score`, `threat_intelligence_score`, `asset_criticality_score`,
`identity_context_score`, `final_risk_score`), so an analyst (or the AI SOC
Analyst, reading it as evidence) can always see exactly what drove a
severity judgment.

## Components

| Component | Source | Status |
|---|---|---|
| `rule_score` | Highest severity among the incident's rule-sourced alerts | ✅ implemented |
| `correlation_score` | How many independently-corroborating alerts got grouped into this incident | ✅ implemented |
| `asset_criticality_score` | The primary host's `Asset.criticality_score`, when known | ✅ implemented |
| `anomaly_score` | ML anomaly model output | ⏳ Phase 5 — not yet built |
| `threat_intelligence_score` | IOC/threat-intel match strength | ⏳ Phase 6 — not yet built |
| `identity_context_score` | Identity risk signals (impossible travel, privileged-account context) | ⏳ depends on the baseline service — not yet built |

## Why max, not average

Both `rule_score` (via `rule_score_from_alerts`) and an incident's overall
`severity` (via `app/correlation/engine.py`'s `group_severity`) take the
**maximum** severity across contributing alerts, never an average. A
critical alert bundled with three low-severity noise alerts is still a
critical incident — averaging it down to "medium" would bury the signal
that matters most. This is deliberate and tested
(`test_rule_score_takes_max_not_average`,
`test_group_severity_takes_the_max_not_the_average`).

## Why missing components are renormalized, not zeroed

Right now only `rule_score`, `correlation_score`, and (when the host is a
known asset) `asset_criticality_score` are computable — ML, threat intel,
and identity context haven't been built yet (see table above). If those
missing components were treated as `0`, every incident's risk score would
be artificially deflated by roughly 40% (their combined weight) until those
phases land, which would be actively misleading. Instead,
`compute_risk_score` excludes `None` components and renormalizes the
weights of whatever's left — so a rule-only incident today gets a risk
score that means exactly what `rule_score` means, not a fraction of it.
This is tested directly
(`test_compute_risk_score_renormalizes_when_components_missing`).

## Weights

```python
COMPONENT_WEIGHTS = {
    "rule_score": 0.35,
    "anomaly_score": 0.20,
    "correlation_score": 0.15,
    "threat_intelligence_score": 0.15,
    "asset_criticality_score": 0.10,
    "identity_context_score": 0.05,
}
```

These are a documented starting point based on which signals are hardest to
fake/most directly tied to confirmed malicious behavior (a matched
detection rule) versus softer corroborating context (asset criticality) —
**not** a tuned or validated model. Once `evaluation/` (docs/evaluation.md)
has enough labeled incident outcomes from the scenario library, these
weights should be revisited against actual precision/recall, not left as
launch-day guesses forever.

## Worked example

From `tests/test_scenario_pipeline.py`'s
`test_full_pipeline_correlates_brute_force_alerts_into_one_incident` — the
`brute_force_privilege_escalation` scenario produces two alerts
(`AUTH-BRUTEFORCE-001`, severity `high`; `CLOUD-SECCONTROL-001`, severity
`critical`) that correlate into one incident:

```
rule_score          = severity_to_score("critical") = 1.0   (max of the two)
correlation_score   = correlation_score_from_group_size(2)  = 0.2
(anomaly / threat_intel / asset_criticality / identity_context: not available)

final_risk_score = (0.35 × 1.0 + 0.15 × 0.2) / (0.35 + 0.15)
                  = (0.35 + 0.03) / 0.5
                  = 0.76
```

This exact value is asserted in the test, so this document can't drift from
what the code actually does.
