"""Normalization: converts source-specific raw log dicts into the common
security_event schema (app/models/security_event.py). Pure functions, no
DB/network — this is what makes the ingestion pipeline testable without a
running database, and what lets app/services/ingestion_service.py stay a
thin orchestration layer instead of burying parsing logic inside it.

Each `normalize_<source>` function maps a source's raw field names onto the
common schema and always preserves the untouched input under `raw_event`
(docs/architecture/architecture.md §2 — an event is a historical fact,
recoverable even if a normalizer has a bug). Unknown/source-specific fields
that don't fit the standard schema go into `metadata_`, never silently
dropped.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

REQUIRED_OUTPUT_FIELDS = ("timestamp", "source", "source_type", "event_type", "raw_event")


class NormalizationError(ValueError):
    """Raised when a raw event can't be normalized — e.g. missing a
    required source field, or an unparsable timestamp. Ingestion should
    quarantine (log + skip) events that raise this rather than crash the
    whole batch — see app/services/ingestion_service.py."""


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizationError(f"Unparsable timestamp: {value!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise NormalizationError(f"Unsupported timestamp type: {type(value)!r}")


def normalize_generic_authentication(raw: dict) -> dict:
    """Expects raw fields: time, user, src_ip, outcome (success|failure),
    [user_agent], [country]. Used by simulator/ + the 'generic_auth' source
    in ingest, and as the template for a real IdP-specific normalizer
    (Okta/Azure AD/etc.) later."""
    try:
        timestamp = _parse_timestamp(raw["time"])
        username = raw["user"]
        source_ip = raw["src_ip"]
        outcome = raw["outcome"]
    except KeyError as exc:
        raise NormalizationError(f"generic_authentication event missing field {exc}") from exc

    if outcome not in ("success", "failure"):
        raise NormalizationError(f"Unrecognized authentication outcome: {outcome!r}")

    known_keys = {"time", "user", "src_ip", "outcome", "user_agent", "country", "hostname"}

    return {
        "timestamp": timestamp,
        "source": raw.get("_source_name", "generic_auth"),
        "source_type": "authentication",
        "username": username,
        "source_ip": source_ip,
        "hostname": raw.get("hostname"),
        "event_type": "authentication",
        "status": outcome,
        "severity": "info",
        "user_agent": raw.get("user_agent"),
        "country": raw.get("country"),
        "metadata_": {k: v for k, v in raw.items() if k not in known_keys and not k.startswith("_")},
        "raw_event": raw,
    }


def normalize_generic_endpoint(raw: dict) -> dict:
    """Expects raw fields: time, host, process, pid, [cmdline], [parent_process]."""
    try:
        timestamp = _parse_timestamp(raw["time"])
        hostname = raw["host"]
        process_name = raw["process"]
    except KeyError as exc:
        raise NormalizationError(f"generic_endpoint event missing field {exc}") from exc

    known_keys = {"time", "host", "process", "pid", "cmdline", "parent_process", "user"}

    return {
        "timestamp": timestamp,
        "source": raw.get("_source_name", "generic_endpoint"),
        "source_type": "endpoint",
        "hostname": hostname,
        "username": raw.get("user"),
        "process_name": process_name,
        "process_id": raw.get("pid"),
        "command_line": raw.get("cmdline"),
        "event_type": "process_start",
        "severity": "info",
        "metadata_": {k: v for k, v in raw.items() if k not in known_keys and not k.startswith("_")},
        "raw_event": raw,
    }


def normalize_generic_network(raw: dict) -> dict:
    """Expects raw fields: time, host, dst_ip, dst_port, [src_port], [protocol], [direction]."""
    try:
        timestamp = _parse_timestamp(raw["time"])
        hostname = raw["host"]
        destination_ip = raw["dst_ip"]
        destination_port = raw["dst_port"]
    except KeyError as exc:
        raise NormalizationError(f"generic_network event missing field {exc}") from exc

    known_keys = {"time", "host", "dst_ip", "dst_port", "src_port", "protocol", "direction"}

    return {
        "timestamp": timestamp,
        "source": raw.get("_source_name", "generic_network"),
        "source_type": "network",
        "hostname": hostname,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "source_port": raw.get("src_port"),
        "protocol": raw.get("protocol", "tcp"),
        "event_type": "network_connection",
        "action": raw.get("direction", "outbound"),
        "severity": "info",
        "metadata_": {k: v for k, v in raw.items() if k not in known_keys and not k.startswith("_")},
        "raw_event": raw,
    }


def normalize_generic_cloud_audit(raw: dict) -> dict:
    """Expects raw fields: time, actor, action, [resource]."""
    try:
        timestamp = _parse_timestamp(raw["time"])
        username = raw["actor"]
        action = raw["action"]
    except KeyError as exc:
        raise NormalizationError(f"generic_cloud_audit event missing field {exc}") from exc

    known_keys = {"time", "actor", "action", "resource"}

    return {
        "timestamp": timestamp,
        "source": raw.get("_source_name", "generic_cloud_audit"),
        "source_type": "cloud",
        "username": username,
        "event_type": "cloud_audit",
        "action": action,
        "severity": "info",
        "metadata_": {
            **{k: v for k, v in raw.items() if k not in known_keys and not k.startswith("_")},
            "resource": raw.get("resource"),
        },
        "raw_event": raw,
    }


def normalize_generic_application(raw: dict) -> dict:
    """Expects raw fields: time, src_ip, status, [path], [method]."""
    try:
        timestamp = _parse_timestamp(raw["time"])
        source_ip = raw["src_ip"]
        status = raw["status"]
    except KeyError as exc:
        raise NormalizationError(f"generic_application event missing field {exc}") from exc

    known_keys = {"time", "src_ip", "status", "path", "method"}

    return {
        "timestamp": timestamp,
        "source": raw.get("_source_name", "generic_application"),
        "source_type": "application",
        "source_ip": source_ip,
        "event_type": "application_request",
        "status": status,
        "url": raw.get("path"),
        "severity": "info",
        "metadata_": {k: v for k, v in raw.items() if k not in known_keys and not k.startswith("_")},
        "raw_event": raw,
    }


_NORMALIZERS: dict[str, Callable[[dict], dict]] = {
    "generic_auth": normalize_generic_authentication,
    "generic_endpoint": normalize_generic_endpoint,
    "generic_network": normalize_generic_network,
    "generic_cloud_audit": normalize_generic_cloud_audit,
    "generic_application": normalize_generic_application,
}


def normalize(source_format: str, raw: dict) -> dict:
    """Dispatches to the right normalizer by declared source_format
    (supplied by the ingestion API caller / simulator, not guessed from
    content — guessing log formats is a reliability and security footgun).
    """
    normalizer = _NORMALIZERS.get(source_format)
    if normalizer is None:
        raise NormalizationError(
            f"Unknown source_format {source_format!r}. Known formats: {sorted(_NORMALIZERS)}"
        )
    normalized = normalizer(raw)

    missing = [f for f in REQUIRED_OUTPUT_FIELDS if f not in normalized]
    if missing:  # pragma: no cover — defensive; indicates a bug in a normalizer above
        raise NormalizationError(f"Normalizer for {source_format!r} produced incomplete event: missing {missing}")

    return normalized
