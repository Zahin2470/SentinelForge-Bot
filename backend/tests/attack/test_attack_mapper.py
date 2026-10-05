"""Tests for app.attack.reference_data and app.attack.coverage — pure
functions, no DB needed. test_every_rule_technique_is_in_reference_data is
the important one: it's what stops the curated ATT&CK reference set and
the actual detection rule library from silently drifting apart.
"""

from app.attack.coverage import compute_coverage
from app.attack.reference_data import TECHNIQUES, get_tactic, get_technique, map_technique
from app.detection.parser import load_rules_from_dir


def test_get_technique_known_id() -> None:
    technique = get_technique("T1110")
    assert technique is not None
    assert technique.name == "Brute Force"
    assert technique.tactic_id == "TA0006"


def test_get_technique_unknown_id_returns_none() -> None:
    assert get_technique("T9999") is None


def test_get_tactic_known_id() -> None:
    tactic = get_tactic("TA0006")
    assert tactic is not None
    assert tactic.name == "Credential Access"


def test_map_technique_full_mapping() -> None:
    mapping = map_technique("T1110")
    assert mapping == {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "is_subtechnique": False,
        "parent_technique_id": None,
    }


def test_map_technique_subtechnique_includes_parent() -> None:
    mapping = map_technique("T1059.001")
    assert mapping is not None
    assert mapping["is_subtechnique"] is True
    assert mapping["parent_technique_id"] == "T1059"


def test_map_technique_unknown_returns_none() -> None:
    assert map_technique("T0000") is None


def test_every_rule_technique_is_in_reference_data() -> None:
    """If a rule cites a technique this reference set doesn't know about,
    the dashboard's coverage numbers and ATT&CK mapping would silently
    miss it. This test is the tripwire."""
    rules = load_rules_from_dir("detection-rules", only_enabled=False)
    rule_technique_ids = {r["attack"]["technique_id"] for r in rules if "attack" in r}
    reference_ids = {t.technique_id for t in TECHNIQUES}

    missing = rule_technique_ids - reference_ids
    assert not missing, f"Rules cite techniques missing from app.attack.reference_data: {missing}"


def test_compute_coverage_basic() -> None:
    report = compute_coverage(rule_technique_ids=["T1110", "T1078"])
    assert "T1110" in report.covered_technique_ids
    assert "T1078" in report.covered_technique_ids
    assert "T1499" in report.uncovered_technique_ids
    assert report.total_techniques == len(TECHNIQUES)
    expected_pct = round(100 * 2 / len(TECHNIQUES), 1)
    assert report.coverage_percent == expected_pct


def test_compute_coverage_with_detected_techniques() -> None:
    report = compute_coverage(
        rule_technique_ids=["T1110", "T1078", "T1562"],
        detected_technique_ids=["T1110"],
    )
    assert report.detected_technique_ids == ["T1110"]
    # detected must be a subset of covered in any sane deployment, though
    # this function doesn't enforce that — it just reports what it's given
    assert set(report.detected_technique_ids).issubset(set(report.covered_technique_ids))


def test_compute_coverage_no_rules_means_everything_uncovered() -> None:
    report = compute_coverage(rule_technique_ids=[])
    assert report.covered_technique_ids == []
    assert len(report.uncovered_technique_ids) == report.total_techniques
    assert report.coverage_percent == 0.0


def test_compute_coverage_full_coverage() -> None:
    all_ids = [t.technique_id for t in TECHNIQUES]
    report = compute_coverage(rule_technique_ids=all_ids)
    assert report.uncovered_technique_ids == []
    assert report.coverage_percent == 100.0


def test_coverage_report_to_dict() -> None:
    report = compute_coverage(rule_technique_ids=["T1110"])
    d = report.to_dict()
    assert d["covered_technique_ids"] == ["T1110"]
    assert "coverage_percent" in d


if __name__ == "__main__":
    test_get_technique_known_id()
    test_get_technique_unknown_id_returns_none()
    test_get_tactic_known_id()
    test_map_technique_full_mapping()
    test_map_technique_subtechnique_includes_parent()
    test_map_technique_unknown_returns_none()
    test_every_rule_technique_is_in_reference_data()
    test_compute_coverage_basic()
    test_compute_coverage_with_detected_techniques()
    test_compute_coverage_no_rules_means_everything_uncovered()
    test_compute_coverage_full_coverage()
    test_coverage_report_to_dict()
    print("All ATT&CK mapping/coverage tests passed.")
