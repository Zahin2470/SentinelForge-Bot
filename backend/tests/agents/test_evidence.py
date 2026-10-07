"""Tests for app.agents.evidence — pure, no DB/LLM needed."""

from app.agents.evidence import collect_evidence_ids, validate_report_grounding
from app.agents.schemas import InvestigationReport, ToolResult


def _tool_result(call_id="c1", tool_name="search_security_events", success=True, authorized=True, evidence_ids=None, output=None):
    return ToolResult(
        call_id=call_id,
        tool_name=tool_name,
        authorized=authorized,
        success=success,
        evidence_ids=evidence_ids or [],
        output=output or {},
    )


def _report(**overrides):
    base = dict(
        classification="brute_force",
        severity="high",
        confidence=0.9,
        summary="Brute force detected.",
        evidence=["evt-1", "evt-2"],
    )
    base.update(overrides)
    return InvestigationReport(**base)


def test_collect_evidence_ids_unions_successful_authorized_results() -> None:
    results = [
        _tool_result(evidence_ids=["evt-1", "evt-2"]),
        _tool_result(call_id="c2", evidence_ids=["evt-3"]),
    ]
    assert collect_evidence_ids(results) == {"evt-1", "evt-2", "evt-3"}


def test_collect_evidence_ids_excludes_failed_calls() -> None:
    results = [_tool_result(success=False, evidence_ids=["evt-1"])]
    assert collect_evidence_ids(results) == set()


def test_collect_evidence_ids_excludes_unauthorized_calls() -> None:
    """A denied tool call must never contribute evidence — whatever the
    model hoped to find there was never actually shown to it."""
    results = [_tool_result(authorized=False, success=False, evidence_ids=["evt-1"])]
    assert collect_evidence_ids(results) == set()


def test_report_fully_grounded_when_all_evidence_available() -> None:
    results = [_tool_result(evidence_ids=["evt-1", "evt-2"])]
    report = _report(evidence=["evt-1", "evt-2"])

    grounding = validate_report_grounding(report, results)

    assert grounding.is_fully_grounded
    assert grounding.hallucination_rate == 0.0


def test_report_with_fabricated_evidence_is_caught() -> None:
    """The core check: a claimed event ID that was never returned by any
    tool call must be flagged, no matter how plausible it looks."""
    results = [_tool_result(evidence_ids=["evt-1"])]
    report = _report(evidence=["evt-1", "evt-99-never-seen"])

    grounding = validate_report_grounding(report, results)

    assert not grounding.is_fully_grounded
    assert grounding.fabricated_evidence == ["evt-99-never-seen"]
    assert grounding.grounded_evidence == ["evt-1"]
    assert grounding.hallucination_rate == 0.5


def test_evidence_sources_validated_against_knowledge_tool_output() -> None:
    results = [
        _tool_result(
            tool_name="search_security_knowledge",
            output={"evidence_sources": ["Brute Force Response Playbook (playbook)"]},
        )
    ]
    report = _report(evidence=[], evidence_sources=["Brute Force Response Playbook (playbook)"])

    grounding = validate_report_grounding(report, results)

    assert grounding.is_fully_grounded
    assert grounding.grounded_sources == ["Brute Force Response Playbook (playbook)"]


def test_fabricated_evidence_source_is_caught() -> None:
    results = [_tool_result(tool_name="search_security_knowledge", output={"evidence_sources": ["Real Doc (playbook)"]})]
    report = _report(evidence=[], evidence_sources=["Real Doc (playbook)", "Completely Made Up Doc (playbook)"])

    grounding = validate_report_grounding(report, results)

    assert not grounding.is_fully_grounded
    assert grounding.fabricated_sources == ["Completely Made Up Doc (playbook)"]


def test_investigation_report_validate_catches_structural_problems() -> None:
    bad = InvestigationReport(classification="", severity="extreme", confidence=1.5, summary="", evidence=[])
    problems = bad.validate()

    assert len(problems) == 5  # severity, confidence, classification, summary, evidence all invalid
    assert any("severity" in p for p in problems)
    assert any("confidence" in p for p in problems)
    assert any("evidence" in p for p in problems)


def test_investigation_report_validate_passes_for_good_report() -> None:
    good = _report()
    assert good.validate() == []


if __name__ == "__main__":
    test_collect_evidence_ids_unions_successful_authorized_results()
    test_collect_evidence_ids_excludes_failed_calls()
    test_collect_evidence_ids_excludes_unauthorized_calls()
    test_report_fully_grounded_when_all_evidence_available()
    test_report_with_fabricated_evidence_is_caught()
    test_evidence_sources_validated_against_knowledge_tool_output()
    test_fabricated_evidence_source_is_caught()
    test_investigation_report_validate_catches_structural_problems()
    test_investigation_report_validate_passes_for_good_report()
    print("All evidence grounding tests passed.")
