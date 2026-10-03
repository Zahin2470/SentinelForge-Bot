"""Synthetic event scenarios (docs/architecture/architecture.md — no real
attack telemetry anywhere in this project). Each scenario function returns
a chronological list of (source_format, raw_event_dict) tuples matching the
raw shapes app.ingest.normalizer expects — i.e. exactly what a real log
source would send to the ingestion API, not pre-normalized events.

Every scenario also declares `ground_truth`: what's expected to happen,
used both by `make simulate` (to print a pass/fail summary) and by the
evaluation suite (docs/evaluation.md §1).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, NamedTuple


class Scenario(NamedTuple):
    name: str
    description: str
    events: list[tuple[str, dict]]
    ground_truth: dict


def _t(base: datetime, minutes: float) -> str:
    return (base + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def brute_force_privilege_escalation(base: datetime | None = None) -> Scenario:
    base = base or datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    user = "jdoe"
    attacker_ip = "198.51.100.23"
    vpn_host = "corp-vpn-gw"

    events: list[tuple[str, dict]] = []

    # 1. Five failed logins in quick succession — brute force attempt.
    for i in range(5):
        events.append((
            "generic_auth",
            {
                "time": _t(base, i),
                "user": user,
                "src_ip": attacker_ip,
                "outcome": "failure",
                "hostname": vpn_host,
                "_source_name": "corp_vpn",
            },
        ))

    # 2. Then a successful login — the attacker got in.
    events.append((
        "generic_auth",
        {
            "time": _t(base, 5),
            "user": user,
            "src_ip": attacker_ip,
            "outcome": "success",
            "hostname": vpn_host,
            "_source_name": "corp_vpn",
        },
    ))

    # 3. Minutes later, a security control gets disabled from a cloud
    #    console session — classic post-compromise defense evasion.
    events.append((
        "generic_cloud_audit",
        {
            "time": _t(base, 8),
            "actor": user,
            "action": "disable_logging",
            "resource": "arn:aws:cloudtrail:us-east-1:111111111111:trail/main",
            "_source_name": "aws_cloudtrail",
        },
    ))

    # 4. Noise: an unrelated, entirely normal login from a different user —
    #    included so a scenario replay also demonstrates rules staying
    #    quiet on benign activity, not just firing on the interesting part.
    events.append((
        "generic_auth",
        {
            "time": _t(base, 2),
            "user": "asmith",
            "src_ip": "203.0.113.44",
            "outcome": "success",
            "hostname": vpn_host,
            "_source_name": "corp_vpn",
        },
    ))

    return Scenario(
        name="brute_force_privilege_escalation",
        description=(
            "Five failed VPN logins for jdoe from an external IP, followed by a "
            "success, followed by a cloud-logging control being disabled from "
            "the same account — a classic brute-force-then-defense-evasion chain."
        ),
        events=events,
        ground_truth={
            "expected_rule_matches": ["AUTH-BRUTEFORCE-001", "CLOUD-SECCONTROL-001"],
            "expected_no_match": ["APP-ACCESSDENIED-001", "ENDPOINT-POWERSHELL-001"],
            "primary_entity": {"username": user, "source_ip": attacker_ip},
        },
    )


def benign_noise_only(base: datetime | None = None) -> Scenario:
    """A scenario with no attack signal at all — the negative-control
    counterpart to brute_force_privilege_escalation, useful for confirming
    the pipeline doesn't cry wolf on ordinary daily activity."""
    base = base or datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    events: list[tuple[str, dict]] = [
        (
            "generic_auth",
            {
                "time": _t(base, i * 5),
                "user": f"user{i}",
                "src_ip": f"10.0.0.{10 + i}",
                "outcome": "success",
                "hostname": "corp-vpn-gw",
                "_source_name": "corp_vpn",
            },
        )
        for i in range(5)
    ]

    return Scenario(
        name="benign_noise_only",
        description="Five ordinary successful logins from five different internal users — no attack signal.",
        events=events,
        ground_truth={"expected_rule_matches": [], "expected_no_match": ["AUTH-BRUTEFORCE-001"]},
    )


SCENARIOS: dict[str, Callable[[], Scenario]] = {
    "brute_force_privilege_escalation": brute_force_privilege_escalation,
    "benign_noise_only": benign_noise_only,
}


def get_scenario(name: str) -> Scenario:
    factory = SCENARIOS.get(name)
    if factory is None:
        raise KeyError(f"Unknown scenario {name!r}. Available: {sorted(SCENARIOS)}")
    return factory()
