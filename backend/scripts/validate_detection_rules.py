#!/usr/bin/env python3
"""Validate every Sigma-style detection rule YAML file against the rule
schema (app/detection/rule_schema.json).

Usage:
    python scripts/validate_detection_rules.py <detection-rules-dir>

Exits non-zero (and prints every failure, not just the first) if any rule
fails schema validation or has a duplicate ID — this is what CI runs on
every push (see .github/workflows/ci.yml, job "detection-rules-validate").
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft7Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "app" / "detection" / "rule_schema.json"


def load_schema() -> dict:
    with SCHEMA_PATH.open() as f:
        return json.load(f)


def main(rules_dir: str) -> int:
    schema = load_schema()
    validator = Draft7Validator(schema)

    rule_files = sorted(Path(rules_dir).rglob("*.yml")) + sorted(Path(rules_dir).rglob("*.yaml"))
    if not rule_files:
        print(f"No rule files found under {rules_dir}")
        return 1

    seen_ids: dict[str, Path] = {}
    failures = 0

    for path in rule_files:
        with path.open() as f:
            try:
                rule = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                print(f"[YAML ERROR] {path}: {exc}")
                failures += 1
                continue

        errors = sorted(validator.iter_errors(rule), key=lambda e: e.path)
        if errors:
            failures += 1
            print(f"[SCHEMA FAIL] {path}")
            for err in errors:
                loc = ".".join(str(p) for p in err.path) or "<root>"
                print(f"    - {loc}: {err.message}")
            continue

        rule_id = rule["id"]
        if rule_id in seen_ids:
            failures += 1
            print(f"[DUPLICATE ID] {rule_id} in {path} (already used in {seen_ids[rule_id]})")
        else:
            seen_ids[rule_id] = path

    total = len(rule_files)
    ok = total - failures
    print(f"\n{ok}/{total} rule files valid.")
    return 1 if failures else 0


if __name__ == "__main__":
    rules_directory = sys.argv[1] if len(sys.argv) > 1 else "detection-rules"
    sys.exit(main(rules_directory))
