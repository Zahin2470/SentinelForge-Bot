"""IOC matching (docs — §14 "Create lookup functionality"). Pure function
over plain dicts — no DB — matching normalized events against a list of
known IOCs by the field(s) each IOC type is relevant to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Which normalized-event field(s) each IOC type is checked against.
# 'domain' IOCs match either the event's own domain field OR as a substring
# of its url field, since our normalized schema doesn't always separate
# them — documented simplification, not a silent gap.
_IOC_TYPE_TO_EVENT_FIELDS: dict[str, list[str]] = {
    "ipv4": ["source_ip", "destination_ip"],
    "ipv6": ["source_ip", "destination_ip"],
    "domain": ["domain"],  # + substring-of-url handled specially below
    "url": ["url"],
    "sha256": ["file_hash"],
    "sha1": ["file_hash"],
    "md5": ["file_hash"],
}


@dataclass
class IOCMatch:
    event_id: Any
    ioc_id: Any
    ioc_type: str
    ioc_value: str
    matched_field: str
    confidence: float
    threat_level: str


def find_ioc_matches(events: list[dict], iocs: list[dict]) -> list[IOCMatch]:
    """events: normalized event dicts (id, source_ip, destination_ip,
    domain, url, file_hash, ...). iocs: IOC dicts (id, type, value,
    confidence, threat_level, ...). Every IOC value is compared
    case-insensitively for domain/url (DNS/URLs are conventionally
    case-insensitive) and exactly for IPs/hashes."""
    if not events or not iocs:
        return []

    by_type: dict[str, list[dict]] = {}
    for ioc in iocs:
        by_type.setdefault(ioc["type"], []).append(ioc)

    matches: list[IOCMatch] = []
    for event in events:
        for ioc_type, ioc_list in by_type.items():
            fields = _IOC_TYPE_TO_EVENT_FIELDS.get(ioc_type, [])
            for ioc in ioc_list:
                ioc_value = ioc["value"]
                for field_name in fields:
                    event_value = event.get(field_name)
                    if event_value and _values_match(ioc_type, event_value, ioc_value):
                        matches.append(
                            IOCMatch(
                                event_id=event["id"],
                                ioc_id=ioc["id"],
                                ioc_type=ioc_type,
                                ioc_value=ioc_value,
                                matched_field=field_name,
                                confidence=ioc.get("confidence", 0.5),
                                threat_level=ioc.get("threat_level", "unknown"),
                            )
                        )
                # domain IOCs additionally match as a substring of the URL field
                if ioc_type == "domain":
                    url_value = event.get("url")
                    if url_value and ioc_value.lower() in url_value.lower():
                        matches.append(
                            IOCMatch(
                                event_id=event["id"],
                                ioc_id=ioc["id"],
                                ioc_type=ioc_type,
                                ioc_value=ioc_value,
                                matched_field="url",
                                confidence=ioc.get("confidence", 0.5),
                                threat_level=ioc.get("threat_level", "unknown"),
                            )
                        )
    return matches


def _values_match(ioc_type: str, event_value: str, ioc_value: str) -> bool:
    if ioc_type in ("domain",):
        return event_value.lower() == ioc_value.lower()
    return event_value == ioc_value
