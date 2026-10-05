"""ATT&CK coverage calculation (docs/architecture — §12: "Detected
Techniques / Covered Techniques / Uncovered Techniques / Detection
Coverage"). Pure functions over plain data — no DB — so the dashboard's
coverage numbers and this module's tests are computing the exact same
thing.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.attack.reference_data import TECHNIQUES, Technique


@dataclass(frozen=True)
class CoverageReport:
    total_techniques: int
    covered_technique_ids: list[str]  # has at least one detection rule mapped to it
    uncovered_technique_ids: list[str]  # in the reference set, no rule covers it
    detected_technique_ids: list[str]  # has actually fired at least one alert/incident
    coverage_percent: float  # covered / total, as a percentage

    def to_dict(self) -> dict:
        return {
            "total_techniques": self.total_techniques,
            "covered_technique_ids": self.covered_technique_ids,
            "uncovered_technique_ids": self.uncovered_technique_ids,
            "detected_technique_ids": self.detected_technique_ids,
            "coverage_percent": self.coverage_percent,
        }


def compute_coverage(
    rule_technique_ids: list[str],
    detected_technique_ids: list[str] | None = None,
    *,
    reference_techniques: list[Technique] = TECHNIQUES,
) -> CoverageReport:
    """
    rule_technique_ids: technique IDs cited by at least one enabled
        detection rule (DetectionRule.attack_technique_id across the
        library) — "we have a detection for this".
    detected_technique_ids: technique IDs that have actually produced a
        real alert/incident in this environment — "this has actually
        happened here at least once". Optional; an empty deployment with
        rules but no alerts yet still gets a meaningful covered/uncovered
        breakdown.
    """
    all_ids = {t.technique_id for t in reference_techniques}
    covered = sorted(all_ids & set(rule_technique_ids))
    uncovered = sorted(all_ids - set(rule_technique_ids))
    detected = sorted(all_ids & set(detected_technique_ids or []))

    coverage_percent = round(100 * len(covered) / len(all_ids), 1) if all_ids else 0.0

    return CoverageReport(
        total_techniques=len(all_ids),
        covered_technique_ids=covered,
        uncovered_technique_ids=uncovered,
        detected_technique_ids=detected,
        coverage_percent=coverage_percent,
    )
