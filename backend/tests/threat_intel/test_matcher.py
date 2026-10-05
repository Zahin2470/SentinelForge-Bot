"""Tests for app.threat_intel.matcher — pure functions, no DB needed."""

from app.threat_intel.matcher import find_ioc_matches


def _ioc(**fields) -> dict:
    base = {"id": "ioc-1", "type": "ipv4", "value": "1.2.3.4", "confidence": 0.5, "threat_level": "unknown"}
    base.update(fields)
    return base


def _event(**fields) -> dict:
    base = {"id": "evt-1"}
    base.update(fields)
    return base


def test_ipv4_ioc_matches_source_ip() -> None:
    events = [_event(source_ip="198.51.100.23")]
    iocs = [_ioc(type="ipv4", value="198.51.100.23", confidence=0.85, threat_level="high")]

    matches = find_ioc_matches(events, iocs)

    assert len(matches) == 1
    assert matches[0].event_id == "evt-1"
    assert matches[0].matched_field == "source_ip"
    assert matches[0].confidence == 0.85


def test_ipv4_ioc_matches_destination_ip_too() -> None:
    events = [_event(destination_ip="198.51.100.23")]
    iocs = [_ioc(type="ipv4", value="198.51.100.23")]

    matches = find_ioc_matches(events, iocs)

    assert len(matches) == 1
    assert matches[0].matched_field == "destination_ip"


def test_no_match_when_ip_not_in_events() -> None:
    events = [_event(source_ip="10.0.0.5")]
    iocs = [_ioc(type="ipv4", value="198.51.100.23")]

    assert find_ioc_matches(events, iocs) == []


def test_domain_ioc_matches_domain_field_case_insensitively() -> None:
    events = [_event(domain="EVIL.EXAMPLE")]
    iocs = [_ioc(type="domain", value="evil.example")]

    matches = find_ioc_matches(events, iocs)

    assert len(matches) == 1
    assert matches[0].matched_field == "domain"


def test_domain_ioc_matches_as_substring_of_url() -> None:
    events = [_event(url="https://evil.example/payload.exe")]
    iocs = [_ioc(type="domain", value="evil.example")]

    matches = find_ioc_matches(events, iocs)

    assert len(matches) == 1
    assert matches[0].matched_field == "url"


def test_sha256_ioc_matches_file_hash_exactly() -> None:
    events = [_event(file_hash="aaaa1111")]
    iocs = [_ioc(type="sha256", value="aaaa1111")]

    matches = find_ioc_matches(events, iocs)
    assert len(matches) == 1


def test_hash_ioc_does_not_partially_match() -> None:
    events = [_event(file_hash="aaaa1111bbbb")]
    iocs = [_ioc(type="sha256", value="aaaa1111")]

    assert find_ioc_matches(events, iocs) == []  # exact match only, no substring


def test_multiple_events_and_iocs_all_combinations_checked() -> None:
    events = [
        _event(id="evt-1", source_ip="1.1.1.1"),
        _event(id="evt-2", source_ip="2.2.2.2"),
        _event(id="evt-3", source_ip="3.3.3.3"),
    ]
    iocs = [_ioc(id="ioc-a", type="ipv4", value="1.1.1.1"), _ioc(id="ioc-b", type="ipv4", value="3.3.3.3")]

    matches = find_ioc_matches(events, iocs)
    matched_event_ids = {m.event_id for m in matches}

    assert matched_event_ids == {"evt-1", "evt-3"}
    assert len(matches) == 2


def test_empty_events_or_iocs_returns_empty() -> None:
    assert find_ioc_matches([], [_ioc()]) == []
    assert find_ioc_matches([_event(source_ip="1.1.1.1")], []) == []


if __name__ == "__main__":
    test_ipv4_ioc_matches_source_ip()
    test_ipv4_ioc_matches_destination_ip_too()
    test_no_match_when_ip_not_in_events()
    test_domain_ioc_matches_domain_field_case_insensitively()
    test_domain_ioc_matches_as_substring_of_url()
    test_sha256_ioc_matches_file_hash_exactly()
    test_hash_ioc_does_not_partially_match()
    test_multiple_events_and_iocs_all_combinations_checked()
    test_empty_events_or_iocs_returns_empty()
    print("All IOC matcher tests passed.")
