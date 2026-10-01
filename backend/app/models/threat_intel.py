"""IOC subsystem (docs/architecture — §14) and imported threat intelligence
(STIX/TAXII, §13 — advanced module, not an MVP blocker). Kept as separate
tables: an IOC is "a value we watch for", ThreatIntelligence is "a
structured report/bundle we imported it from" — one report can reference
many IOCs.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import ARRAY, DateTime, Enum, Float, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class IOCType(str, enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"


class IOC(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "iocs"
    __table_args__ = ()

    type: Mapped[IOCType] = mapped_column(Enum(IOCType), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    threat_level: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    related_campaign: Mapped[str | None] = mapped_column(String(255), nullable=True)
    related_techniques: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)


class ThreatIntelligence(UUIDPrimaryKeyMixin, Base):
    """A normalized STIX bundle / TAXII collection entry, or a manually
    curated sample intelligence record for the local demo. Core
    functionality never depends on a single external commercial API being
    reachable (docs/architecture — §13)."""

    __tablename__ = "threat_intelligence"

    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "sample-taxii-feed", "manual"
    stix_type: Mapped[str | None] = mapped_column(String(100), nullable=True)  # indicator, attack-pattern, malware, ...
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    raw_stix: Mapped[dict] = mapped_column(JSONB, nullable=False)
