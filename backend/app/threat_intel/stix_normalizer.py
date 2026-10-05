"""Lightweight STIX 2.1 indicator normalization (docs — §13, "implement
STIX/TAXII as an advanced module, do not make it a blocker for MVP").

This deliberately does NOT implement the full STIX pattern grammar (STIX
patterning is its own mini-language with boolean logic, comparison
operators, and dozens of object types) — that would be a project on its
own. It handles the common simple case: a single `ObjectType:property =
'value'` comparison, which covers the overwhelming majority of real-world
indicator objects (a single IP, domain, URL, or hash). Anything more
complex (boolean AND/OR patterns, multiple observables) is explicitly
reported as unsupported rather than silently mis-parsed — same "honest
unsupported" pattern as app/detection/executor.py.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_SIMPLE_PATTERN_RE = re.compile(
    r"^\[\s*(?P<stix_type>[\w-]+):(?P<property>[\w.'\"-]+)\s*=\s*'(?P<value>[^']+)'\s*\]$"
)

# Maps STIX SCO (STIX Cyber-observable Object) type + property to our IOC
# type enum (app/models/threat_intel.py:IOCType). Property names are
# compared after stripping quote characters (STIX allows both
# `hashes.SHA-256` and `hashes.'SHA-256'` — hash algorithm names contain a
# hyphen, so some producers quote them to avoid ambiguity with the pattern
# grammar's own use of `-`), so only the unquoted canonical form needs a
# map entry.
_STIX_TYPE_MAP = {
    ("ipv4-addr", "value"): "ipv4",
    ("ipv6-addr", "value"): "ipv6",
    ("domain-name", "value"): "domain",
    ("url", "value"): "url",
    ("file", "hashes.SHA-256"): "sha256",
    ("file", "hashes.SHA-1"): "sha1",
    ("file", "hashes.MD5"): "md5",
}


class UnsupportedStixPattern(ValueError):
    """Raised for STIX patterns beyond the simple single-comparison form
    this module supports — e.g. boolean-combined patterns like
    `[ipv4-addr:value = '1.2.3.4' OR domain-name:value = 'evil.com']`."""


def normalize_stix_indicator(indicator: dict) -> dict:
    """Converts one STIX 2.1 `indicator` SDO into an IOC row-shaped dict
    (matching app/models/threat_intel.py:IOC's fields, minus id/timestamps
    the DB assigns). Raises UnsupportedStixPattern for anything beyond a
    single simple comparison, and ValueError for a structurally invalid
    indicator (missing pattern/required fields) — callers should treat
    both as "skip and log this one", not "abort the whole import".
    """
    if indicator.get("type") != "indicator":
        raise ValueError(f"Not a STIX indicator object: type={indicator.get('type')!r}")

    pattern = indicator.get("pattern")
    if not pattern:
        raise ValueError("Indicator missing required 'pattern' field")

    match = _SIMPLE_PATTERN_RE.match(pattern.strip())
    if not match:
        raise UnsupportedStixPattern(f"Unsupported STIX pattern grammar: {pattern!r}")

    stix_type, prop, value = match.group("stix_type"), match.group("property"), match.group("value")
    prop_normalized = prop.replace("'", "").replace('"', "")
    ioc_type = _STIX_TYPE_MAP.get((stix_type, prop_normalized))
    if ioc_type is None:
        raise UnsupportedStixPattern(f"Unrecognized observable type/property: {stix_type}:{prop}")

    valid_from = indicator.get("valid_from")
    first_seen = _parse_stix_timestamp(valid_from) if valid_from else datetime.now(tz=timezone.utc)

    return {
        "type": ioc_type,
        "value": value,
        "source": indicator.get("created_by_ref", "stix_import"),
        "confidence": (indicator.get("confidence", 50)) / 100.0,  # STIX confidence is 0-100
        "first_seen": first_seen,
        "last_seen": first_seen,
        "tags": indicator.get("labels", indicator.get("indicator_types", [])),
        "threat_level": _labels_to_threat_level(indicator.get("labels", indicator.get("indicator_types", []))),
        "related_campaign": None,
        "related_techniques": _extract_attack_technique_refs(indicator),
    }


def _parse_stix_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _labels_to_threat_level(labels: list[str]) -> str:
    labels_lower = {label.lower() for label in labels}
    if "malicious-activity" in labels_lower or "malware" in labels_lower:
        return "high"
    if "suspicious-activity" in labels_lower or "anomalous-activity" in labels_lower:
        return "medium"
    return "unknown"


def _extract_attack_technique_refs(indicator: dict) -> list[str]:
    """STIX indicators sometimes carry ATT&CK technique IDs in
    external_references (the standard place MITRE's own CTI bundle puts
    them) — pulled out here so an imported IOC can pre-populate
    related_techniques instead of always starting empty."""
    refs = indicator.get("external_references", [])
    technique_ids = []
    for ref in refs:
        external_id = ref.get("external_id", "")
        if re.match(r"^T\d{4}(\.\d{3})?$", external_id):
            technique_ids.append(external_id)
    return technique_ids
