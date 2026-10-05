"""Curated MITRE ATT&CK reference data (docs/architecture — §12).

Honest scope note: the master build spec says to "consume machine-readable
ATT&CK data where possible" rather than manually duplicating it — the
canonical source is MITRE's STIX bundle
(https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json).
This environment has no network access, so `scripts/import_attack_data.py`
(the real ingestion path, written but not runnable here) is what should be
used against that bundle in a connected environment. What's below is a
small, hand-curated reference set covering exactly the techniques the
current detection rule library (detection-rules/) actually cites, plus
their parent tactics — enough to make ATT&CK mapping and coverage
calculation real and testable today, without claiming full framework
coverage it doesn't have. ATTACK_VERSION documents which release this was
curated against.
"""

from __future__ import annotations

from dataclasses import dataclass

ATTACK_VERSION = "16.1"  # the MITRE ATT&CK release this curated subset reflects


@dataclass(frozen=True)
class Tactic:
    tactic_id: str
    name: str
    description: str


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    description: str
    tactic_id: str
    is_subtechnique: bool = False
    parent_technique_id: str | None = None


TACTICS: list[Tactic] = [
    Tactic("TA0001", "Initial Access", "Techniques used to gain an initial foothold within a network."),
    Tactic("TA0004", "Privilege Escalation", "Techniques used to gain higher-level permissions."),
    Tactic("TA0005", "Defense Evasion", "Techniques used to avoid detection throughout a compromise."),
    Tactic("TA0006", "Credential Access", "Techniques for stealing account names and credentials."),
    Tactic("TA0007", "Discovery", "Techniques an adversary uses to gain knowledge about the system and network."),
    Tactic("TA0002", "Execution", "Techniques that result in adversary-controlled code running on a local or remote system."),
    Tactic("TA0011", "Command and Control", "Techniques used to communicate with systems under adversary control."),
    Tactic("TA0040", "Impact", "Techniques used to disrupt availability or compromise integrity."),
]

# Every technique_id referenced by any rule in detection-rules/ MUST appear
# here — this invariant is checked by
# backend/tests/threat_intel/test_attack_mapper.py so the rule library and
# this reference set can't silently drift apart.
TECHNIQUES: list[Technique] = [
    Technique("T1110", "Brute Force", "Adversaries may use brute force techniques to gain access to accounts.", "TA0006"),
    Technique("T1078", "Valid Accounts", "Adversaries may obtain and abuse credentials of existing accounts.", "TA0001"),
    Technique("T1098", "Account Manipulation", "Adversaries may manipulate accounts to maintain access.", "TA0004"),
    Technique(
        "T1059.001", "PowerShell", "Adversaries may abuse PowerShell commands and scripts for execution.",
        "TA0002", is_subtechnique=True, parent_technique_id="T1059",
    ),
    Technique("T1059", "Command and Scripting Interpreter", "Adversaries may abuse command and script interpreters to execute commands.", "TA0002"),
    Technique("T1071", "Application Layer Protocol", "Adversaries may communicate using OSI application layer protocols to blend in.", "TA0011"),
    Technique("T1562", "Impair Defenses", "Adversaries may maliciously modify components of a victim environment to hinder defenses.", "TA0005"),
    Technique("T1595", "Active Scanning", "Adversaries may execute active reconnaissance scans to gather information.", "TA0007"),
    Technique("T1499", "Endpoint Denial of Service", "Adversaries may perform Endpoint DoS attacks to degrade availability.", "TA0040"),
]

TACTICS_BY_ID: dict[str, Tactic] = {t.tactic_id: t for t in TACTICS}
TECHNIQUES_BY_ID: dict[str, Technique] = {t.technique_id: t for t in TECHNIQUES}


def get_technique(technique_id: str) -> Technique | None:
    return TECHNIQUES_BY_ID.get(technique_id)


def get_tactic(tactic_id: str) -> Tactic | None:
    return TACTICS_BY_ID.get(tactic_id)


def map_technique(technique_id: str) -> dict | None:
    """Returns the full tactic+technique mapping shown in the dashboard
    (docs/architecture — §12's "Tactic / Technique / Name" example), or
    None if the ID isn't in this curated set."""
    technique = get_technique(technique_id)
    if technique is None:
        return None
    tactic = get_tactic(technique.tactic_id)
    return {
        "technique_id": technique.technique_id,
        "technique_name": technique.name,
        "tactic_id": technique.tactic_id,
        "tactic_name": tactic.name if tactic else None,
        "is_subtechnique": technique.is_subtechnique,
        "parent_technique_id": technique.parent_technique_id,
    }
