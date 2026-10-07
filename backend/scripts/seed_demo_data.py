#!/usr/bin/env python3
"""Seeds baseline reference data for local development/demo:
permissions, the four fixed roles, one admin user per role for login
testing, and a handful of sample assets with varying criticality (so
risk-scoring has something meaningful to weight against once it's built).

Idempotent — safe to re-run; existing rows are matched by their natural key
(permission name, role name, user email, asset hostname) and left alone.

Usage: python scripts/seed_demo_data.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from passlib.context import CryptContext  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal  # noqa: E402
from app.core.logging import configure_logging, get_logger  # noqa: E402
from app.core.permissions import PERMISSIONS, ROLE_PERMISSIONS  # noqa: E402
from app.models.asset import Asset, AssetCriticality  # noqa: E402
from app.models.user import Permission, Role, RoleName, User  # noqa: E402

configure_logging()
logger = get_logger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Demo-only credentials — never used outside local/dev seeding. Every seeded
# user's password is intentionally simple and identical; this script must
# never run against anything but a local dev database.
DEMO_PASSWORD = "sentinelforge-demo-2026"

# PERMISSIONS and ROLE_PERMISSIONS come from app.core.permissions — the
# single source of truth (also used by app/agents/tools.py's authorization
# checks), so what gets seeded here and what the agent actually enforces
# can never silently drift apart. ROLE_PERMISSIONS there is keyed by plain
# role-name strings; RoleName[key] below converts to the enum this script
# needs for the DB row.

DEMO_USERS = [
    (RoleName.ADMIN, "admin@sentinelforge.local", "Demo Admin"),
    (RoleName.SECURITY_MANAGER, "manager@sentinelforge.local", "Demo Security Manager"),
    (RoleName.SOC_ANALYST, "analyst@sentinelforge.local", "Demo SOC Analyst"),
    (RoleName.VIEWER, "viewer@sentinelforge.local", "Demo Viewer"),
]

DEMO_ASSETS = [
    ("corp-dc-01", "server", AssetCriticality.CRITICAL, 0.95, "production"),
    ("corp-vpn-gw", "server", AssetCriticality.HIGH, 0.8, "production"),
    ("aws-cloudtrail-main", "cloud_resource", AssetCriticality.HIGH, 0.85, "production"),
    ("win-desktop-01", "workstation", AssetCriticality.MEDIUM, 0.4, "production"),
    ("test-vm-03", "workstation", AssetCriticality.LOW, 0.1, "staging"),
]


def seed_permissions(db) -> dict[str, Permission]:
    existing = {p.name: p for p in db.execute(select(Permission)).scalars().all()}
    for name, description in PERMISSIONS:
        if name not in existing:
            perm = Permission(name=name, description=description)
            db.add(perm)
            db.flush()
            existing[name] = perm
            logger.info("seeded_permission", name=name)
    return existing


def seed_roles(db, permissions: dict[str, Permission]) -> dict[RoleName, Role]:
    existing = {r.name: r for r in db.execute(select(Role)).scalars().all()}
    for role_name in RoleName:
        if role_name not in existing:
            role = Role(name=role_name, description=f"{role_name.value} role")
            role.permissions = [permissions[p] for p in ROLE_PERMISSIONS[role_name]]
            db.add(role)
            db.flush()
            existing[role_name] = role
            logger.info("seeded_role", name=role_name.value)
        else:
            existing[role_name].permissions = [permissions[p] for p in ROLE_PERMISSIONS[role_name]]
    return existing


def seed_users(db, roles: dict[RoleName, Role]) -> None:
    existing_emails = {u.email for u in db.execute(select(User)).scalars().all()}
    hashed = pwd_context.hash(DEMO_PASSWORD)
    for role_name, email, full_name in DEMO_USERS:
        if email in existing_emails:
            continue
        user = User(email=email, full_name=full_name, hashed_password=hashed, role_id=roles[role_name].id)
        db.add(user)
        logger.info("seeded_user", email=email, role=role_name.value)
    db.flush()


def seed_assets(db) -> None:
    existing_hostnames = {a.hostname for a in db.execute(select(Asset)).scalars().all()}
    for hostname, asset_type, criticality, criticality_score, environment in DEMO_ASSETS:
        if hostname in existing_hostnames:
            continue
        asset = Asset(
            hostname=hostname,
            asset_type=asset_type,
            criticality=criticality,
            criticality_score=criticality_score,
            environment=environment,
        )
        db.add(asset)
        logger.info("seeded_asset", hostname=hostname, criticality=criticality.value)
    db.flush()


def main() -> int:
    db = SessionLocal()
    try:
        permissions = seed_permissions(db)
        roles = seed_roles(db, permissions)
        seed_users(db, roles)
        seed_assets(db)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print("Demo data seeded.")
    print(f"Demo login password for all seeded users: {DEMO_PASSWORD}")
    print("Users: " + ", ".join(email for _, email, _ in DEMO_USERS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
