#!/usr/bin/env python3
"""Replays a synthetic scenario through the real pipeline: ingestion
service (normalize + persist) → detection service (evaluate enabled rules,
create alerts) — against the live database. This is what `make simulate
SCENARIO=...` runs (docs/setup.md §5).

Usage (from inside the backend container, or with PYTHONPATH set to both
the repo root and backend/):
    python -m simulator.replay --scenario brute_force_privilege_escalation

Prints a pass/fail summary against the scenario's declared ground_truth
rather than just "N events ingested" — so a broken rule shows up as a
visibly failed demo, not a silent no-op.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make both the repo root (for `simulator`) and backend/ (for `app`)
# importable regardless of cwd — mirrors how docker-compose mounts them
# into the backend container (see docker-compose.yml).
_REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (_REPO_ROOT, _REPO_ROOT / "backend"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.core.db import SessionLocal  # noqa: E402
from app.core.logging import configure_logging, get_logger  # noqa: E402
from app.schemas.security_event import IngestEventRequest  # noqa: E402
from app.services.correlation_service import CorrelationService  # noqa: E402
from app.services.detection_service import DetectionService  # noqa: E402
from app.services.ingestion_service import IngestionService  # noqa: E402
from simulator.scenarios import Scenario, get_scenario  # noqa: E402

configure_logging()
logger = get_logger(__name__)


def replay(scenario: Scenario) -> int:
    print(f"\n=== Replaying scenario: {scenario.name} ===")
    print(scenario.description)
    print(f"{len(scenario.events)} raw events to ingest.\n")

    requests = [IngestEventRequest(source_format=fmt, raw=raw) for fmt, raw in scenario.events]

    db = SessionLocal()
    exit_code = 0
    try:
        ingest_result = IngestionService().ingest_batch(db, requests)
        db.commit()
        print(f"Ingested: {ingest_result.accepted} accepted, {ingest_result.rejected} rejected")
        if ingest_result.rejected_reasons:
            for reason in ingest_result.rejected_reasons:
                print(f"  - rejected: {reason}")

        detection_results = DetectionService().run_enabled_rules(db)
        db.commit()

        matched_rule_ids = sorted({r.rule_id for r in detection_results if r.matched})
        unsupported_rule_ids = sorted({r.rule_id for r in detection_results if r.status == "unsupported"})

        print(f"\nRules matched: {matched_rule_ids or '(none)'}")
        print(f"Rules unsupported (skipped honestly): {unsupported_rule_ids or '(none)'}")

        expected = set(scenario.ground_truth.get("expected_rule_matches", []))
        expected_no_match = set(scenario.ground_truth.get("expected_no_match", []))
        actual = set(matched_rule_ids)

        missing = expected - actual
        unexpected = actual & expected_no_match

        if missing:
            print(f"\n❌ FAIL — expected these rules to match but they didn't: {sorted(missing)}")
            exit_code = 1
        if unexpected:
            print(f"\n❌ FAIL — these rules matched but were expected to stay quiet: {sorted(unexpected)}")
            exit_code = 1
        if not missing and not unexpected:
            print("\n✅ PASS — detection results match the scenario's ground truth.")

        incidents = CorrelationService().run_correlation(db)
        db.commit()
        print(f"\nIncidents created: {len(incidents)}")
        for incident in incidents:
            print(
                f"  {incident.display_id} — {incident.title} "
                f"(severity={incident.severity}, risk={incident.final_risk_score})"
            )

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, help="Scenario name, e.g. brute_force_privilege_escalation")
    args = parser.parse_args()

    try:
        scenario = get_scenario(args.scenario)
    except KeyError as exc:
        print(str(exc))
        return 2

    return replay(scenario)


if __name__ == "__main__":
    sys.exit(main())
