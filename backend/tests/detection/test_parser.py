"""Tests for app.detection.parser — structural loading/validation, and that
load_rules_from_dir actually discovers all the example rules checked into
detection-rules/.
"""

import tempfile
from pathlib import Path

from app.detection.parser import RuleLoadError, load_rule, load_rules_from_dir


def test_load_rule_succeeds_on_a_real_rule() -> None:
    rule = load_rule("detection-rules/authentication/auth_bruteforce_001.yml")
    assert rule["id"] == "AUTH-BRUTEFORCE-001"


def test_load_rule_rejects_missing_required_keys() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        broken = Path(tmp) / "broken.yml"
        broken.write_text("id: FOO-001\ntitle: Missing stuff\n")
        try:
            load_rule(broken)
            raise AssertionError("expected RuleLoadError")
        except RuleLoadError as exc:
            assert "missing required key" in str(exc).lower()


def test_load_rule_rejects_non_mapping_yaml() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        broken = Path(tmp) / "broken.yml"
        broken.write_text("- just\n- a\n- list\n")
        try:
            load_rule(broken)
            raise AssertionError("expected RuleLoadError")
        except RuleLoadError as exc:
            assert "mapping" in str(exc).lower()


def test_load_rules_from_dir_finds_all_example_rules() -> None:
    rules = load_rules_from_dir("detection-rules/", only_enabled=True)
    rule_ids = {r["id"] for r in rules}

    expected = {
        "AUTH-BRUTEFORCE-001",
        "AUTH-NEWLOGINIP-002",
        "AUTH-PRIVCHANGE-003",
        "ENDPOINT-POWERSHELL-001",
        "NETWORK-OUTBOUND-001",
        "CLOUD-SECCONTROL-001",
        "APP-ACCESSDENIED-001",
        "CORRELATION-MULTIHOST-001",
    }
    assert expected.issubset(rule_ids)


if __name__ == "__main__":
    test_load_rule_succeeds_on_a_real_rule()
    test_load_rule_rejects_missing_required_keys()
    test_load_rule_rejects_non_mapping_yaml()
    test_load_rules_from_dir_finds_all_example_rules()
    print("All parser tests passed.")
