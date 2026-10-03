"""End-to-end test of the parts of the pipeline that don't require a live
database: raw scenario events -> app.ingest.normalizer -> app.detection.executor.
This is the strongest test in the repo right now, because it exercises the
same code path simulator/replay.py uses against a real DB, just with the
persistence layer swapped for plain lists — so a passing run here is real
evidence the detection logic is correct end-to-end, not just unit-correct
in isolation.

Run with PYTHONPATH set to both the repo root (for `simulator`) and
backend/ (for `app`):
    PYTHONPATH=.:backend python3 tests/test_scenario_pipeline.py
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (_REPO_ROOT, _REPO_ROOT / "backend"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.detection.executor import evaluate_rule  # noqa: E402
from app.detection.parser import load_rules_from_dir  # noqa: E402
from app.ingest.normalizer import normalize  # noqa: E402
from simulator.scenarios import get_scenario  # noqa: E402

_id_counter = itertools.count(1)


def _run_scenario_in_memory(scenario_name: str) -> tuple[set[str], set[str]]:
    """Returns (matched_rule_ids, unsupported_rule_ids)."""
    scenario = get_scenario(scenario_name)

    normalized_events = []
    for source_format, raw in scenario.events:
        event = normalize(source_format, raw)
        event["id"] = f"evt-{next(_id_counter)}"
        normalized_events.append(event)

    rules = load_rules_from_dir("detection-rules", only_enabled=True)

    matched_rule_ids: set[str] = set()
    unsupported_rule_ids: set[str] = set()
    for rule in rules:
        if rule["logsource"]["category"] == "correlation":
            continue  # meta-rules are consumed by the correlation engine, not the per-rule executor
        for result in evaluate_rule(rule, normalized_events):
            if result.matched:
                matched_rule_ids.add(result.rule_id)
            elif result.status == "unsupported":
                unsupported_rule_ids.add(result.rule_id)

    return matched_rule_ids, unsupported_rule_ids


def test_brute_force_scenario_matches_ground_truth() -> None:
    scenario = get_scenario("brute_force_privilege_escalation")
    matched, _unsupported = _run_scenario_in_memory("brute_force_privilege_escalation")

    expected = set(scenario.ground_truth["expected_rule_matches"])
    expected_no_match = set(scenario.ground_truth["expected_no_match"])

    assert expected.issubset(matched), f"missing expected matches: {expected - matched}"
    assert not (matched & expected_no_match), f"unexpected matches: {matched & expected_no_match}"


def test_benign_scenario_triggers_nothing() -> None:
    scenario = get_scenario("benign_noise_only")
    matched, _unsupported = _run_scenario_in_memory("benign_noise_only")

    expected_no_match = set(scenario.ground_truth["expected_no_match"])
    assert not (matched & expected_no_match), f"benign scenario unexpectedly matched: {matched}"


if __name__ == "__main__":
    test_brute_force_scenario_matches_ground_truth()
    test_benign_scenario_triggers_nothing()
    print("All end-to-end scenario pipeline tests passed.")
