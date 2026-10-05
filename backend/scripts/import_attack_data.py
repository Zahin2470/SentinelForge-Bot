#!/usr/bin/env python3
"""Seeds AttackTactic and AttackTechnique from the curated reference set in
app.attack.reference_data (see that module's docstring for the honest
scope note: this is a curated subset covering what the current rule
library cites, not the full MITRE ATT&CK framework — a real deployment
would point this at MITRE's published STIX bundle instead).

Idempotent — safe to re-run.

Usage: python scripts/import_attack_data.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.attack.reference_data import ATTACK_VERSION, TACTICS, TECHNIQUES  # noqa: E402
from app.core.db import SessionLocal  # noqa: E402
from app.core.logging import configure_logging, get_logger  # noqa: E402
from app.models.attack import AttackTactic, AttackTechnique  # noqa: E402

configure_logging()
logger = get_logger(__name__)


def main() -> int:
    db = SessionLocal()
    try:
        existing_tactics = {t.tactic_id for t in db.execute(select(AttackTactic)).scalars().all()}
        for tactic in TACTICS:
            if tactic.tactic_id in existing_tactics:
                continue
            db.add(AttackTactic(tactic_id=tactic.tactic_id, name=tactic.name, description=tactic.description))
            logger.info("seeded_attack_tactic", tactic_id=tactic.tactic_id, name=tactic.name)

        existing_techniques = {t.technique_id for t in db.execute(select(AttackTechnique)).scalars().all()}
        for technique in TECHNIQUES:
            if technique.technique_id in existing_techniques:
                continue
            db.add(
                AttackTechnique(
                    technique_id=technique.technique_id,
                    name=technique.name,
                    description=technique.description,
                    tactic_id=technique.tactic_id,
                    is_subtechnique=technique.is_subtechnique,
                    parent_technique_id=technique.parent_technique_id,
                )
            )
            logger.info("seeded_attack_technique", technique_id=technique.technique_id, name=technique.name)

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print(f"Seeded {len(TACTICS)} tactics and {len(TECHNIQUES)} techniques (curated against ATT&CK v{ATTACK_VERSION}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
