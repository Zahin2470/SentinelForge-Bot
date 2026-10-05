"""Tests for app.threat_intel.stix_normalizer — pure functions, no DB
needed. Runs against the actual sample feed checked into
threat-intel/sample_feed.json, not just hand-built fixtures, so a change to
that file that breaks parsing is caught here too.
"""

import json

from app.threat_intel.stix_normalizer import UnsupportedStixPattern, normalize_stix_indicator

SAMPLE_FEED_PATH = "threat-intel/sample_feed.json"


def _load_sample_feed() -> list[dict]:
    with open(SAMPLE_FEED_PATH) as f:
        bundle = json.load(f)
    return bundle["objects"]


def test_normalize_ipv4_indicator() -> None:
    indicator = {
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '198.51.100.23']",
        "valid_from": "2026-01-01T00:00:00Z",
        "labels": ["malicious-activity"],
        "confidence": 85,
    }
    ioc = normalize_stix_indicator(indicator)
    assert ioc["type"] == "ipv4"
    assert ioc["value"] == "198.51.100.23"
    assert ioc["confidence"] == 0.85
    assert ioc["threat_level"] == "high"


def test_normalize_domain_indicator() -> None:
    indicator = {
        "type": "indicator",
        "pattern": "[domain-name:value = 'evil.example']",
        "labels": ["suspicious-activity"],
        "confidence": 50,
    }
    ioc = normalize_stix_indicator(indicator)
    assert ioc["type"] == "domain"
    assert ioc["value"] == "evil.example"
    assert ioc["threat_level"] == "medium"


def test_normalize_sha256_indicator() -> None:
    indicator = {
        "type": "indicator",
        "pattern": "[file:hashes.'SHA-256' = 'aaaa1111']",
        "labels": [],
        "confidence": 30,
    }
    ioc = normalize_stix_indicator(indicator)
    assert ioc["type"] == "sha256"
    assert ioc["value"] == "aaaa1111"
    assert ioc["threat_level"] == "unknown"


def test_normalize_extracts_attack_technique_refs() -> None:
    indicator = {
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "confidence": 50,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1110"},
            {"source_name": "some-other-source", "external_id": "CVE-2024-1234"},  # not a technique ID, must be excluded
        ],
    }
    ioc = normalize_stix_indicator(indicator)
    assert ioc["related_techniques"] == ["T1110"]


def test_normalize_rejects_non_indicator_object() -> None:
    try:
        normalize_stix_indicator({"type": "malware", "pattern": "[ipv4-addr:value = '1.1.1.1']"})
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "not a stix indicator" in str(exc).lower()


def test_normalize_rejects_missing_pattern() -> None:
    try:
        normalize_stix_indicator({"type": "indicator"})
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "pattern" in str(exc).lower()


def test_normalize_rejects_unsupported_boolean_pattern() -> None:
    """Confirms the normalizer is honest about its scope: a boolean-OR
    pattern is explicitly unsupported, never silently mis-parsed into a
    single IOC."""
    indicator = {
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '1.1.1.1' OR ipv4-addr:value = '2.2.2.2']",
        "confidence": 50,
    }
    try:
        normalize_stix_indicator(indicator)
        raise AssertionError("expected UnsupportedStixPattern")
    except UnsupportedStixPattern:
        pass


def test_sample_feed_parses_three_of_four_indicators() -> None:
    """The sample feed intentionally includes one unsupported boolean
    pattern (indicator--0004) to prove the normalizer handles a mixed
    batch correctly: parse what it can, report what it can't, never crash
    the whole import."""
    objects = _load_sample_feed()
    indicators = [o for o in objects if o.get("type") == "indicator"]
    assert len(indicators) == 4

    parsed, unsupported = [], []
    for indicator in indicators:
        try:
            parsed.append(normalize_stix_indicator(indicator))
        except UnsupportedStixPattern:
            unsupported.append(indicator["id"])

    assert len(parsed) == 3
    assert unsupported == ["indicator--0004"]

    values = {ioc["value"] for ioc in parsed}
    assert "198.51.100.23" in values  # the attacker IP our scenario uses


if __name__ == "__main__":
    test_normalize_ipv4_indicator()
    test_normalize_domain_indicator()
    test_normalize_sha256_indicator()
    test_normalize_extracts_attack_technique_refs()
    test_normalize_rejects_non_indicator_object()
    test_normalize_rejects_missing_pattern()
    test_normalize_rejects_unsupported_boolean_pattern()
    test_sample_feed_parses_three_of_four_indicators()
    print("All STIX normalizer tests passed.")
