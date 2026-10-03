"""Tests for app.ingest.normalizer — pure functions, no DB needed, so these
run directly in any environment including CI's fastest/earliest job."""

from datetime import timezone

from app.ingest.normalizer import NormalizationError, normalize


def test_normalize_generic_auth_success() -> None:
    raw = {
        "time": "2026-01-01T10:00:00Z",
        "user": "alice",
        "src_ip": "1.2.3.4",
        "outcome": "failure",
        "user_agent": "Mozilla/5.0",
        "extra_vendor_field": "some_value",
    }

    event = normalize("generic_auth", raw)

    assert event["source_type"] == "authentication"
    assert event["username"] == "alice"
    assert event["source_ip"] == "1.2.3.4"
    assert event["status"] == "failure"
    assert event["event_type"] == "authentication"
    assert event["timestamp"].tzinfo == timezone.utc
    assert event["raw_event"] == raw
    # unknown vendor field preserved in metadata_, not dropped
    assert event["metadata_"]["extra_vendor_field"] == "some_value"


def test_normalize_generic_auth_rejects_bad_outcome() -> None:
    raw = {"time": "2026-01-01T10:00:00Z", "user": "alice", "src_ip": "1.2.3.4", "outcome": "maybe"}
    try:
        normalize("generic_auth", raw)
        raise AssertionError("expected NormalizationError")
    except NormalizationError as exc:
        assert "outcome" in str(exc).lower()


def test_normalize_generic_auth_rejects_missing_field() -> None:
    raw = {"time": "2026-01-01T10:00:00Z", "user": "alice", "outcome": "success"}  # missing src_ip
    try:
        normalize("generic_auth", raw)
        raise AssertionError("expected NormalizationError")
    except NormalizationError as exc:
        assert "src_ip" in str(exc)


def test_normalize_generic_endpoint() -> None:
    raw = {
        "time": "2026-01-01T10:05:00Z",
        "host": "WIN-DESKTOP-01",
        "process": "powershell.exe",
        "pid": 4821,
        "cmdline": "powershell.exe -enc AAAA",
        "user": "bob",
    }

    event = normalize("generic_endpoint", raw)

    assert event["source_type"] == "endpoint"
    assert event["hostname"] == "WIN-DESKTOP-01"
    assert event["process_name"] == "powershell.exe"
    assert event["process_id"] == 4821
    assert event["command_line"] == "powershell.exe -enc AAAA"
    assert event["username"] == "bob"


def test_normalize_generic_network() -> None:
    raw = {
        "time": "2026-01-01T10:10:00Z",
        "host": "WIN-DESKTOP-01",
        "dst_ip": "203.0.113.9",
        "dst_port": 4444,
        "protocol": "tcp",
        "direction": "outbound",
    }

    event = normalize("generic_network", raw)

    assert event["source_type"] == "network"
    assert event["destination_ip"] == "203.0.113.9"
    assert event["destination_port"] == 4444
    assert event["action"] == "outbound"


def test_normalize_generic_cloud_audit() -> None:
    raw = {"time": "2026-01-01T10:15:00Z", "actor": "admin@example.com", "action": "disable_logging"}

    event = normalize("generic_cloud_audit", raw)

    assert event["source_type"] == "cloud"
    assert event["event_type"] == "cloud_audit"
    assert event["action"] == "disable_logging"
    assert event["username"] == "admin@example.com"


def test_normalize_generic_application() -> None:
    raw = {"time": "2026-01-01T10:20:00Z", "src_ip": "198.51.100.7", "status": 403, "path": "/api/admin"}

    event = normalize("generic_application", raw)

    assert event["source_type"] == "application"
    assert event["status"] == 403
    assert event["url"] == "/api/admin"


def test_normalize_unknown_source_format_raises() -> None:
    try:
        normalize("totally_unknown_format", {})
        raise AssertionError("expected NormalizationError")
    except NormalizationError as exc:
        assert "Unknown source_format" in str(exc)


def test_normalize_unparsable_timestamp_raises() -> None:
    raw = {"time": "not-a-timestamp", "user": "alice", "src_ip": "1.2.3.4", "outcome": "success"}
    try:
        normalize("generic_auth", raw)
        raise AssertionError("expected NormalizationError")
    except NormalizationError as exc:
        assert "timestamp" in str(exc).lower()


def test_raw_event_always_preserved_untouched() -> None:
    """Whatever normalization does, the original raw dict must be
    recoverable byte-for-byte from raw_event — this is the recoverability
    guarantee docs/architecture/architecture.md promises."""
    raw = {
        "time": "2026-01-01T10:00:00Z",
        "user": "alice",
        "src_ip": "1.2.3.4",
        "outcome": "success",
        "weird_nested": {"a": [1, 2, 3]},
    }
    event = normalize("generic_auth", raw)
    assert event["raw_event"] == raw
    assert event["raw_event"] is raw  # not a lossy copy


if __name__ == "__main__":
    test_normalize_generic_auth_success()
    test_normalize_generic_auth_rejects_bad_outcome()
    test_normalize_generic_auth_rejects_missing_field()
    test_normalize_generic_endpoint()
    test_normalize_generic_network()
    test_normalize_generic_cloud_audit()
    test_normalize_generic_application()
    test_normalize_unknown_source_format_raises()
    test_normalize_unparsable_timestamp_raises()
    test_raw_event_always_preserved_untouched()
    print("All normalizer tests passed.")
