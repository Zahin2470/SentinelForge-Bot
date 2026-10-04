"""Tests for app.ml.features — pure functions, no DB/sklearn needed."""

from datetime import datetime, timedelta, timezone

from app.ml.features import FEATURE_NAMES, build_feature_table, extract_entity_features, features_to_vector

_HOUR = timedelta(hours=1)


def _event(hour: int, minute: int = 0, **fields) -> dict:
    e = {"timestamp": datetime(2026, 1, 1, hour, minute, tzinfo=timezone.utc)}
    e.update(fields)
    return e


def test_empty_events_returns_all_zero_features() -> None:
    features = extract_entity_features([], _HOUR)
    assert set(features.keys()) == set(FEATURE_NAMES)
    assert all(v == 0.0 for v in features.values())


def test_failed_and_successful_login_counts() -> None:
    events = [
        _event(9, event_type="authentication", status="failure", source_ip="1.1.1.1"),
        _event(9, event_type="authentication", status="failure", source_ip="1.1.1.1"),
        _event(9, event_type="authentication", status="success", source_ip="1.1.1.1"),
    ]
    features = extract_entity_features(events, _HOUR)
    assert features["failed_login_count"] == 2.0
    assert features["successful_login_count"] == 1.0
    assert features["total_events"] == 3.0


def test_unique_source_ips_and_countries_deduplicate() -> None:
    events = [
        _event(9, source_ip="1.1.1.1", country="US"),
        _event(9, source_ip="1.1.1.1", country="US"),
        _event(9, source_ip="2.2.2.2", country="FR"),
    ]
    features = extract_entity_features(events, _HOUR)
    assert features["unique_source_ips"] == 2.0
    assert features["unique_countries"] == 2.0


def test_night_time_ratio() -> None:
    events = [
        _event(23, event_type="x"),  # night
        _event(2, event_type="x"),  # night
        _event(14, event_type="x"),  # day
        _event(14, event_type="x"),  # day
    ]
    features = extract_entity_features(events, _HOUR)
    assert features["night_time_event_ratio"] == 0.5


def test_event_rate_per_minute_scales_with_window() -> None:
    events = [_event(9, minute=i) for i in range(6)]
    features_1h = extract_entity_features(events, timedelta(minutes=60))
    features_2h = extract_entity_features(events, timedelta(minutes=120))
    assert features_1h["event_rate_per_minute"] == 6 / 60
    assert features_2h["event_rate_per_minute"] == 6 / 120
    assert features_1h["event_rate_per_minute"] > features_2h["event_rate_per_minute"]


def test_privilege_change_count() -> None:
    events = [
        _event(9, event_type="privilege_modification"),
        _event(9, event_type="privilege_modification"),
        _event(9, event_type="authentication", status="success"),
    ]
    features = extract_entity_features(events, _HOUR)
    assert features["privilege_change_count"] == 2.0


def test_build_feature_table_groups_by_entity_and_skips_none() -> None:
    events = [
        _event(9, username="alice", event_type="authentication", status="success"),
        _event(9, username="alice", event_type="authentication", status="failure"),
        _event(9, username="bob", event_type="authentication", status="success"),
        _event(9, username=None, event_type="authentication", status="success"),  # skipped
    ]
    table = build_feature_table(events, entity_field="username", window=_HOUR)
    assert set(table.keys()) == {"alice", "bob"}
    assert table["alice"]["total_events"] == 2.0
    assert table["bob"]["total_events"] == 1.0


def test_features_to_vector_matches_feature_names_order() -> None:
    features = extract_entity_features([_event(9, event_type="authentication", status="success")], _HOUR)
    vector = features_to_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    for name, value in zip(FEATURE_NAMES, vector):
        assert value == features[name]


def test_features_to_vector_raises_on_missing_key() -> None:
    incomplete = {"failed_login_count": 1.0}
    try:
        features_to_vector(incomplete)
        raise AssertionError("expected KeyError")
    except KeyError:
        pass


if __name__ == "__main__":
    test_empty_events_returns_all_zero_features()
    test_failed_and_successful_login_counts()
    test_unique_source_ips_and_countries_deduplicate()
    test_night_time_ratio()
    test_event_rate_per_minute_scales_with_window()
    test_privilege_change_count()
    test_build_feature_table_groups_by_entity_and_skips_none()
    test_features_to_vector_matches_feature_names_order()
    test_features_to_vector_raises_on_missing_key()
    print("All ML feature extraction tests passed.")
