"""Rule execution engine (docs/detection-engine.md §3).

This is a **rule-type-based engine**: it recognizes a specific, documented
set of condition shapes (below) and compiles each into a direct evaluation
over a list of normalized events — it is not a general expression-language
interpreter. That's a deliberate scope choice: a small, well-tested set of
supported shapes beats a clever generic parser that's subtly wrong on edge
cases nobody wrote a test for.

Supported condition shapes:
    count(<sub>) >= N followed_by <sub2>     — e.g. AUTH-BRUTEFORCE-001
    count(<sub>) >= N                        — e.g. APP-ACCESSDENIED-001
    <sub>.<field> matches any <patterns_key> — e.g. ENDPOINT-POWERSHELL-001
    <sub>                                    — bare existence match, e.g. CLOUD-SECCONTROL-001

Explicitly NOT yet implemented (rules using these parse fine and *run*, but
return a status="unsupported" result rather than a wrong answer):
    - "not in baseline" / "frequency(baseline)" conditions — depend on the
      behavioral-baseline service, which is a separate, not-yet-built
      component (see docs/ml/ml-pipeline.md's feature-baseline discussion;
      AUTH-NEWLOGINIP-002 and NETWORK-OUTBOUND-001 use this).
    - conditions that reference another rule's match via `rule_ref` — this
      is rule-chaining, which belongs to the correlation engine, not the
      per-rule executor (AUTH-PRIVCHANGE-003 uses this).
    - CORRELATION-MULTIHOST-001-style meta-rules are intentionally never
      run by this module at all — they're consumed by the correlation
      engine (docs/architecture/architecture.md §3-5), which operates on
      *alert* output, not raw events.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

_TIMEFRAME_RE = re.compile(r"^(\d+)\s*([smhd])$")

_TIMEFRAME_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def parse_timeframe(value: str) -> timedelta:
    match = _TIMEFRAME_RE.match(value.strip())
    if not match:
        raise ValueError(f"Unrecognized timeframe format: {value!r} (expected e.g. '10m', '30d')")
    amount, unit = match.groups()
    return timedelta(**{_TIMEFRAME_UNITS[unit]: int(amount)})


@dataclass
class DetectionResult:
    rule_id: str
    severity: str
    matched_event_ids: list[str] = field(default_factory=list)
    group_key: tuple[Any, ...] | None = None
    status: str = "matched"  # "matched" | "unsupported"
    reason: str | None = None

    @property
    def matched(self) -> bool:
        return self.status == "matched" and bool(self.matched_event_ids)


def _event_matches_filter(event: dict, filt: dict) -> bool:
    for field_name, expected in filt.items():
        actual = event.get(field_name)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _group_key(event: dict, group_by: list[str]) -> tuple:
    return tuple(event.get(f) for f in group_by)


_THRESHOLD_FOLLOWED_BY_RE = re.compile(
    r"^count\((?P<sub>\w+)\)\s*>=\s*(?P<n>\d+)\s*followed_by\s*(?P<sub2>\w+)$"
)
_THRESHOLD_RE = re.compile(r"^count\((?P<sub>\w+)\)\s*>=\s*(?P<n>\d+)$")
_PATTERN_MATCH_RE = re.compile(
    r"^(?P<sub>\w+)\.(?P<field>\w+)\s+matches\s+any\s+(?P<patterns_key>\w+)$"
)
_BARE_SUB_RE = re.compile(r"^(?P<sub>[A-Za-z_]\w*)$")


def evaluate_rule(rule: dict, events: list[dict]) -> list[DetectionResult]:
    """Evaluate one rule against a list of normalized event dicts.

    Each event dict is expected to have at least: id, timestamp (a
    timezone-aware datetime), and whatever fields the rule's filters check.
    Events do not need to be pre-sorted or pre-filtered to a time window —
    that's this function's job.
    """
    detection = rule["detection"]
    condition = str(detection.get("condition", "")).strip()
    rule_id = rule["id"]
    severity = rule["severity"]

    events_sorted = sorted(events, key=lambda e: e["timestamp"])

    if match := _THRESHOLD_FOLLOWED_BY_RE.match(condition):
        return _evaluate_threshold_followed_by(rule_id, severity, detection, events_sorted, match)

    if "not in baseline" in condition or "frequency(baseline)" in condition:
        return [
            DetectionResult(
                rule_id,
                severity,
                status="unsupported",
                reason="Requires the behavioral-baseline service, which is not yet implemented.",
            )
        ]

    if "rule_ref" in str(detection):
        return [
            DetectionResult(
                rule_id,
                severity,
                status="unsupported",
                reason="Requires rule-chaining, which belongs to the correlation engine (planned).",
            )
        ]

    if match := _THRESHOLD_RE.match(condition):
        return _evaluate_threshold(rule_id, severity, detection, events_sorted, match)

    if match := _PATTERN_MATCH_RE.match(condition):
        return _evaluate_pattern_match(rule_id, severity, detection, events_sorted, match)

    if match := _BARE_SUB_RE.match(condition):
        return _evaluate_bare(rule_id, severity, detection, events_sorted, match)

    return [
        DetectionResult(
            rule_id,
            severity,
            status="unsupported",
            reason=f"Unrecognized condition grammar: {condition!r}",
        )
    ]


def _evaluate_threshold_followed_by(
    rule_id: str, severity: str, detection: dict, events: list[dict], match: re.Match
) -> list[DetectionResult]:
    sub_name, sub2_name, n = match.group("sub"), match.group("sub2"), int(match.group("n"))
    timeframe = parse_timeframe(detection["timeframe"])
    group_by = detection.get("group_by", [])
    sub_filter, sub2_filter = detection[sub_name], detection[sub2_name]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in events:
        if _event_matches_filter(e, sub_filter) or _event_matches_filter(e, sub2_filter):
            groups[_group_key(e, group_by)].append(e)

    results: list[DetectionResult] = []
    for key, group_events in groups.items():
        group_events.sort(key=lambda e: e["timestamp"])
        window: deque = deque()
        i = 0
        while i < len(group_events):
            e = group_events[i]
            if _event_matches_filter(e, sub_filter):
                window.append(e)
                while window and e["timestamp"] - window[0]["timestamp"] > timeframe:
                    window.popleft()
                if len(window) >= n:
                    deadline = window[0]["timestamp"] + timeframe
                    for j in range(i + 1, len(group_events)):
                        candidate = group_events[j]
                        if candidate["timestamp"] > deadline:
                            break
                        if _event_matches_filter(candidate, sub2_filter):
                            matched_ids = [str(x["id"]) for x in window] + [str(candidate["id"])]
                            results.append(DetectionResult(rule_id, severity, matched_ids, group_key=key))
                            window.clear()
                            i = j
                            break
            i += 1
    return results


def _evaluate_threshold(
    rule_id: str, severity: str, detection: dict, events: list[dict], match: re.Match
) -> list[DetectionResult]:
    sub_name, n = match.group("sub"), int(match.group("n"))
    timeframe = parse_timeframe(detection["timeframe"])
    group_by = detection.get("group_by", [])
    sub_filter = detection[sub_name]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in events:
        if _event_matches_filter(e, sub_filter):
            groups[_group_key(e, group_by)].append(e)

    results: list[DetectionResult] = []
    for key, group_events in groups.items():
        group_events.sort(key=lambda e: e["timestamp"])
        window: deque = deque()
        for e in group_events:
            window.append(e)
            while window and e["timestamp"] - window[0]["timestamp"] > timeframe:
                window.popleft()
            if len(window) >= n:
                matched_ids = [str(x["id"]) for x in window]
                results.append(DetectionResult(rule_id, severity, matched_ids, group_key=key))
                window.clear()
    return results


def _evaluate_pattern_match(
    rule_id: str, severity: str, detection: dict, events: list[dict], match: re.Match
) -> list[DetectionResult]:
    sub_name, field_name, patterns_key = (
        match.group("sub"),
        match.group("field"),
        match.group("patterns_key"),
    )
    sub_filter = detection[sub_name]
    patterns = detection[patterns_key]

    results: list[DetectionResult] = []
    for e in events:
        if not _event_matches_filter(e, sub_filter):
            continue
        value = e.get(field_name) or ""
        if any(p.lower() in value.lower() for p in patterns):
            results.append(DetectionResult(rule_id, severity, [str(e["id"])]))
    return results


def _evaluate_bare(
    rule_id: str, severity: str, detection: dict, events: list[dict], match: re.Match
) -> list[DetectionResult]:
    sub_name = match.group("sub")
    sub_filter = detection.get(sub_name)
    if sub_filter is None or not isinstance(sub_filter, dict):
        return [
            DetectionResult(
                rule_id,
                severity,
                status="unsupported",
                reason=f"No detection sub-block named {sub_name!r} to evaluate.",
            )
        ]

    results: list[DetectionResult] = []
    for e in events:
        if _event_matches_filter(e, sub_filter):
            results.append(DetectionResult(rule_id, severity, [str(e["id"])]))
    return results
