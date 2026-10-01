"""Positive/negative tests for ENDPOINT-POWERSHELL-001
(process_execution.command_line matches any command_line_patterns)."""

from app.detection.executor import evaluate_rule
from app.detection.parser import load_rule
from tests.detection.fixtures import at, make_event

RULE_PATH = "detection-rules/endpoint/endpoint_suspicious_powershell_001.yml"


def _rule() -> dict:
    return load_rule(RULE_PATH)


def test_encoded_command_flag_triggers() -> None:
    rule = _rule()
    events = [
        make_event(
            at(0),
            event_type="process_start",
            process_name="powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA...",
        )
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1


def test_hidden_windowstyle_triggers() -> None:
    rule = _rule()
    events = [
        make_event(
            at(0),
            event_type="process_start",
            process_name="powershell.exe",
            command_line="powershell.exe -WindowStyle Hidden -File update.ps1",
        )
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert len(matched) == 1


def test_plain_powershell_invocation_does_not_trigger() -> None:
    """A completely ordinary PowerShell call with no evasive flags must
    NOT trigger — this is the negative case for a pattern-match rule."""
    rule = _rule()
    events = [
        make_event(
            at(0),
            event_type="process_start",
            process_name="powershell.exe",
            command_line="powershell.exe -File deploy_config.ps1",
        )
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


def test_non_powershell_process_with_matching_text_does_not_trigger() -> None:
    """The sub-filter requires process_name == powershell.exe; a different
    process merely containing similar text in its command line must not
    match — this exercises the filter, not just the pattern check."""
    rule = _rule()
    events = [
        make_event(
            at(0),
            event_type="process_start",
            process_name="cmd.exe",
            command_line="echo -enc just talking about -enc here",
        )
    ]

    results = evaluate_rule(rule, events)
    matched = [r for r in results if r.matched]

    assert matched == []


if __name__ == "__main__":
    test_encoded_command_flag_triggers()
    test_hidden_windowstyle_triggers()
    test_plain_powershell_invocation_does_not_trigger()
    test_non_powershell_process_with_matching_text_does_not_trigger()
    print("All ENDPOINT-POWERSHELL-001 tests passed.")
