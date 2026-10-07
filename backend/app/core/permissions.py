"""Canonical RBAC definition (docs/security/threat-model.md — "every tool
and API route declares required permissions; checked centrally"). This is
the single source of truth for ROLE_PERMISSIONS — scripts/seed_demo_data.py
imports it rather than defining its own copy, and app/agents/tools.py's
per-tool authorization checks import it too, so a role's actual
permissions can never silently drift between what seeds the demo DB and
what the agent actually enforces.

Deliberately uses plain role-name strings, not app.models.user.RoleName —
importing that enum would pull in the whole SQLAlchemy models package
(app/models/__init__.py imports every model) just for four string
constants, which would make this module (and everything that needs pure,
offline-testable authorization logic, like app/agents/tools.py) require
sqlalchemy to even import. ROLE_NAMES below is the parallel plain-string
set; app/models/user.py's RoleName enum values match it exactly by
convention — not by a shared import, so keep them in sync by hand if this
list ever changes.
"""

from __future__ import annotations

ROLE_NAMES = ("ADMIN", "SOC_ANALYST", "SECURITY_MANAGER", "VIEWER")

PERMISSIONS: list[tuple[str, str]] = [
    ("incidents:read", "View incidents"),
    ("incidents:write", "Update/resolve incidents"),
    ("detection_rules:read", "View detection rules"),
    ("detection_rules:write", "Enable/disable/edit detection rules"),
    ("threat_intel:write", "Manage IOCs and threat intelligence"),
    ("ai_copilot:use", "Trigger AI SOC Analyst investigations"),
    ("admin:settings", "Manage users, roles, and system settings"),
]

_ALL_PERMISSION_NAMES = [p[0] for p in PERMISSIONS]

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "ADMIN": list(_ALL_PERMISSION_NAMES),  # everything
    "SECURITY_MANAGER": [
        "incidents:read",
        "incidents:write",
        "detection_rules:read",
        "detection_rules:write",
        "threat_intel:write",
        "ai_copilot:use",
    ],
    "SOC_ANALYST": [
        "incidents:read",
        "incidents:write",
        "detection_rules:read",
        "ai_copilot:use",
    ],
    "VIEWER": [
        "incidents:read",
        "detection_rules:read",
    ],
}


def is_authorized(role: str, permission: str) -> bool:
    """The one function every tool call and API route should route
    through (docs/ai/ai-agent.md §4 — "every tool call re-checks the
    acting user's permissions; the LLM's 'intent' is never itself
    authorization"). Pure, no DB — the caller is responsible for knowing
    the acting user's actual role. Accepts a plain role-name string (or
    an app.models.user.RoleName, which IS a str subclass and compares
    equal to its own value) so callers on either side of the
    pure/DB-touching boundary can use it without extra conversion."""
    return permission in ROLE_PERMISSIONS.get(str(role), [])
