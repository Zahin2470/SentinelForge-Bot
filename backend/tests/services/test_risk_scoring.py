"""Tests for app.services.risk_scoring — pure functions, no DB needed."""

from app.services.risk_scoring import (
    compute_risk_score,
    correlation_score_from_group_size,
    rule_score_from_alerts,
    score_to_severity,
    severity_to_score,
    threat_intelligence_score_from_alerts,
)


def test_severity_to_score_ordering() -> None:
    assert severity_to_score("low") < severity_to_score("medium") < severity_to_score("high") < severity_to_score("critical")


def test_rule_score_takes_max_not_average() -> None:
    score = rule_score_from_alerts(["low", "critical", "medium"])
    assert score == severity_to_score("critical")


def test_rule_score_empty_list_is_zero() -> None:
    assert rule_score_from_alerts([]) == 0.0


def test_correlation_score_increases_with_group_size_and_caps_at_one() -> None:
    assert correlation_score_from_group_size(1) == 0.0
    assert correlation_score_from_group_size(2) == 0.2
    assert correlation_score_from_group_size(3) == 0.4
    assert correlation_score_from_group_size(100) == 1.0


def test_compute_risk_score_with_all_components() -> None:
    score = compute_risk_score(
        {
            "rule_score": 1.0,
            "anomaly_score": 1.0,
            "correlation_score": 1.0,
            "threat_intelligence_score": 1.0,
            "asset_criticality_score": 1.0,
            "identity_context_score": 1.0,
        }
    )
    assert score == 1.0  # all components maxed -> weights sum to 1.0 -> score is 1.0


def test_compute_risk_score_renormalizes_when_components_missing() -> None:
    """Only rule_score available (the only component the detection engine
    can currently produce) — score should equal rule_score itself, not be
    artificially deflated by the other components defaulting to zero."""
    score = compute_risk_score(
        {
            "rule_score": 0.75,
            "anomaly_score": None,
            "correlation_score": None,
            "threat_intelligence_score": None,
            "asset_criticality_score": None,
            "identity_context_score": None,
        }
    )
    assert score == 0.75


def test_compute_risk_score_two_components_weighted_correctly() -> None:
    # rule_score weight 0.35, correlation_score weight 0.15 -> renormalized
    # weights: 0.35/0.5=0.7 and 0.15/0.5=0.3
    score = compute_risk_score(
        {"rule_score": 1.0, "correlation_score": 0.0, "anomaly_score": None,
         "threat_intelligence_score": None, "asset_criticality_score": None, "identity_context_score": None}
    )
    assert abs(score - 0.7) < 1e-6


def test_compute_risk_score_all_none_returns_none() -> None:
    score = compute_risk_score(
        {k: None for k in
         ["rule_score", "anomaly_score", "correlation_score", "threat_intelligence_score",
          "asset_criticality_score", "identity_context_score"]}
    )
    assert score is None


def test_threat_intelligence_score_from_alerts_no_ti_alerts_returns_none() -> None:
    alerts = [{"source": "rule", "severity": "high"}, {"source": "ml", "severity": "critical"}]
    assert threat_intelligence_score_from_alerts(alerts) is None


def test_threat_intelligence_score_from_alerts_takes_max_ti_severity() -> None:
    alerts = [
        {"source": "rule", "severity": "critical"},  # ignored — not threat_intel sourced
        {"source": "threat_intel", "severity": "low"},
        {"source": "threat_intel", "severity": "medium"},
    ]
    score = threat_intelligence_score_from_alerts(alerts)
    assert score == severity_to_score("medium")


def test_score_to_severity_bands() -> None:
    assert score_to_severity(0.9) == "critical"
    assert score_to_severity(0.85) == "critical"
    assert score_to_severity(0.7) == "high"
    assert score_to_severity(0.5) == "medium"
    assert score_to_severity(0.1) == "low"


if __name__ == "__main__":
    test_severity_to_score_ordering()
    test_rule_score_takes_max_not_average()
    test_rule_score_empty_list_is_zero()
    test_correlation_score_increases_with_group_size_and_caps_at_one()
    test_compute_risk_score_with_all_components()
    test_compute_risk_score_renormalizes_when_components_missing()
    test_compute_risk_score_two_components_weighted_correctly()
    test_compute_risk_score_all_none_returns_none()
    test_threat_intelligence_score_from_alerts_no_ti_alerts_returns_none()
    test_threat_intelligence_score_from_alerts_takes_max_ti_severity()
    test_score_to_severity_bands()
    print("All risk scoring tests passed.")
