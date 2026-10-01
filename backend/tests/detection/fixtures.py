"""Small helper for building synthetic normalized-event dicts in detection
engine tests, so each test file stays focused on the scenario it's checking
rather than repeating event-construction boilerplate.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timezone

_id_counter = itertools.count(1)


def make_event(timestamp: datetime, **fields) -> dict:
    """Build a normalized event dict. `timestamp` is required and
    positional; everything else (event_type, status, username, ...) is
    passed as keyword fields matching SecurityEvent column names."""
    event = {"id": f"evt-{next(_id_counter)}", "timestamp": timestamp}
    event.update(fields)
    return event


def at(minute: int, *, base: datetime | None = None) -> datetime:
    """Returns a UTC datetime `minute` minutes after a fixed base time —
    lets tests express '5 minutes into the scenario' instead of hand-typing
    timestamps."""
    base = base or datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    from datetime import timedelta

    return base + timedelta(minutes=minute)
