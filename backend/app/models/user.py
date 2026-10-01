"""RBAC: users, roles, permissions.

Roles are fixed (docs/architecture — Auth section): ADMIN, SOC_ANALYST,
SECURITY_MANAGER, VIEWER. Permissions are a many-to-many join so specific
capabilities (incident access, rule management, threat-intel management, AI
copilot access, admin settings) can be composed per role without a schema
change — but the four roles above ship with sane defaults seeded in
scripts/seed_demo_data.py.

Authorization is enforced in app/core/security.py (dependency-injected into
every route and every agent tool) — never only in the frontend.
"""

import enum
import uuid

from sqlalchemy import Boolean, Column, Enum, ForeignKey, String, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class RoleName(str, enum.Enum):
    ADMIN = "ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    VIEWER = "VIEWER"


role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id",
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Permission(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="", nullable=False)


class Role(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "roles"

    name: Mapped[RoleName] = mapped_column(Enum(RoleName), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="", nullable=False)

    permissions: Mapped[list[Permission]] = relationship(
        secondary=role_permissions, lazy="selectin"
    )


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id"), nullable=False)
    role: Mapped[Role] = relationship(lazy="joined")
