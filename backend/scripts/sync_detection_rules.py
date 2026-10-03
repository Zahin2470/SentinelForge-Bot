#!/usr/bin/env python3
"""Syncs every enabled rule under detection-rules/ into the detection_rules
table (app/repositories/detection_rule_repository.py:upsert_from_definition).
The YAML files remain the source of truth for detection logic; this just
keeps the DB index (used for fast listing + the detection service's rule
lookup) in step with them. Safe to re-run — it's an upsert by rule_key.

Usage:
    python scripts/sync_detection_rules.py [detection-rules-dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.db import SessionLocal  # noqa: E402
from app.core.logging import configure_logging, get_logger  # noqa: E402
from app.detection.parser import load_rules_from_dir  # noqa: E402
from app.repositories.detection_rule_repository import DetectionRuleRepository  # noqa: E402

configure_logging()
logger = get_logger(__name__)


def main(rules_dir: str) -> int:
    rules = load_rules_from_dir(rules_dir, only_enabled=False)  # sync disabled rules too, just marked disabled
    repo = DetectionRuleRepository()

    db = SessionLocal()
    try:
        for rule in rules:
            source_path = str(Path(rules_dir) / rule["logsource"]["category"] / f"{rule['id'].lower()}.yml")
            repo.upsert_from_definition(db, rule, source_path=source_path)
            logger.info("synced_detection_rule", rule_id=rule["id"], enabled=rule.get("status") == "enabled")
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print(f"Synced {len(rules)} detection rules into the database.")
    return 0


if __name__ == "__main__":
    rules_directory = sys.argv[1] if len(sys.argv) > 1 else "detection-rules"
    sys.exit(main(rules_directory))
