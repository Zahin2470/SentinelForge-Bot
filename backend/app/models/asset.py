"""Assets are the hosts/systems SentinelForge has context on. asset
criticality feeds directly into risk scoring
(docs/architecture/architecture.md §7) — an anomaly on a domain controller
should never score the same as one on a test VM.
"""

import enum

from sqlalchemy import Float, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class AssetCriticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)  # server, workstation, cloud_resource, ...
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str] = mapped_column(String(50), default="production", nullable=False)
    criticality: Mapped[AssetCriticality] = mapped_column(
        default=AssetCriticality.MEDIUM, nullable=False
    )
    # Precomputed 0-1 value used directly as the asset_criticality risk
    # component; kept in sync with `criticality` by a service-layer setter,
    # not edited independently.
    criticality_score: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
