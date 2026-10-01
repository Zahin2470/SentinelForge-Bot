"""Loads detection rule YAML files for the executor.

Full schema validation (docs/detection-engine.md §3, "Validator") happens in
scripts/validate_detection_rules.py via jsonschema, run in CI on every push.
This module does a minimal, dependency-free structural check instead of
duplicating that schema as a second source of truth — it exists so the
executor fails with a clear error on a broken rule file rather than a
confusing KeyError three calls deep.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REQUIRED_KEYS = ("id", "title", "status", "description", "severity", "detection", "logsource")


class RuleLoadError(ValueError):
    """Raised when a rule file is missing or structurally invalid."""


def load_rule(path: str | Path) -> dict:
    path = Path(path)
    with path.open() as f:
        rule = yaml.safe_load(f)

    if not isinstance(rule, dict):
        raise RuleLoadError(f"{path}: rule file did not parse to a YAML mapping")

    missing = [k for k in REQUIRED_KEYS if k not in rule]
    if missing:
        raise RuleLoadError(f"{path}: missing required key(s) {missing}")

    return rule


def load_rules_from_dir(rules_dir: str | Path, only_enabled: bool = True) -> list[dict]:
    """Loads every *.yml/*.yaml rule under rules_dir, recursively.

    Raises RuleLoadError immediately on the first structurally broken file
    — a silently-skipped bad rule is worse than a loud failure at startup.
    """
    rules_dir = Path(rules_dir)
    rules: list[dict] = []
    seen_paths = set()

    for pattern in ("*.yml", "*.yaml"):
        for rule_path in sorted(rules_dir.rglob(pattern)):
            if rule_path in seen_paths:
                continue
            seen_paths.add(rule_path)
            rule = load_rule(rule_path)
            if only_enabled and rule.get("status") != "enabled":
                continue
            rules.append(rule)

    return rules
