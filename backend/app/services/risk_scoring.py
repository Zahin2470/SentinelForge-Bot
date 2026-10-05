"""Risk scoring (docs/architecture/architecture.md §7, docs/architecture/risk-scoring.md).

final_risk_score = weighted combination of explicit, independently-computed
components — never a number the LLM invents, and never silently degraded to
zero just because a component (ML, threat intel) isn't wired up yet.
Missing components are excluded and the remaining weights are renormalized,
which is why `compute_risk_score` takes a dict where any value may be
`None` rather than requiring every component up front.
"""

from __future__ import annotations

# Relative importance of each component. These are a documented starting
# point, not a tuned model — revisit once evaluation.md's scenario library
# has enough labeled incidents to actually validate them against outcomes.
COMPONENT_WEIGHTS: dict[str, float] = {
    "rule_score": 0.35,
    "anomaly_score": 0.20,
    "correlation_score": 0.15,
    "threat_intelligence_score": 0.15,
    "asset_criticality_score": 0.10,
    "identity_context_score": 0.05,
}

_SEVERITY_TO_SCORE = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def severity_to_score(severity: str) -> float:
    return _SEVERITY_TO_SCORE.get(severity, 0.5)


def rule_score_from_alerts(alert_severities: list[str]) -> float:
    """rule_score is the highest severity among the incident's contributing
    rule-sourced alerts — deliberately not an average, for the same reason
    group_severity() in app/correlation/engine.py isn't an average."""
    if not alert_severities:
        return 0.0
    return max(severity_to_score(s) for s in alert_severities)


def correlation_score_from_group_size(alert_count: int) -> float:
    """More independently-corroborating alerts in one incident is itself
    signal — a single alert scores 0 (no corroboration yet), each
    additional correlated alert adds 0.2, capped at 1.0."""
    return min(1.0, max(0, alert_count - 1) * 0.2)


def threat_intelligence_score_from_alerts(alerts: list[dict]) -> float | None:
    """Highest severity among the incident's threat-intel-sourced alerts
    (Alert.source == "threat_intel", created by
    app.services.threat_intel_service when a known IOC matches an event).
    Returns None — not 0 — when none of the correlated alerts came from a
    threat-intel match, the same way rule_score_from_alerts distinguishes
    "nothing to score" from "scored and it's low"; compute_risk_score
    renormalizes over None components rather than treating them as zero."""
    ti_severities = [a["severity"] for a in alerts if a.get("source") == "threat_intel"]
    if not ti_severities:
        return None
    return max(severity_to_score(s) for s in ti_severities)


def compute_risk_score(components: dict[str, float | None]) -> float | None:
    """Renormalized weighted average over whatever components are actually
    available. Returns None only if every component is None (nothing to
    score at all — should not happen in practice since rule_score is always
    computable for a rule-sourced incident).
    """
    available = {k: v for k, v in components.items() if v is not None and k in COMPONENT_WEIGHTS}
    if not available:
        return None

    total_weight = sum(COMPONENT_WEIGHTS[k] for k in available)
    weighted_sum = sum(COMPONENT_WEIGHTS[k] * v for k, v in available.items())
    return round(weighted_sum / total_weight, 4)


def score_to_severity(score: float) -> str:
    """Maps a final numeric risk score back to a display severity band —
    used when an incident's severity should reflect the *combined* risk
    picture rather than just the max alert severity (e.g. after
    correlation and threat intel are folded in)."""
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"
