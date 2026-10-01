"""MITRE ATT&CK reference data (docs/architecture — §12). Populated from
the machine-readable ATT&CK STIX bundle where possible
(scripts/import_attack_data.py) rather than manually duplicated — this
table is a local cache/index for fast lookup and coverage visualization,
not a hand-maintained copy of MITRE's data.
"""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class AttackTactic(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_tactics"

    tactic_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # e.g. TA0006
    name: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "Credential Access"
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class AttackTechnique(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "attack_techniques"

    technique_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # e.g. T1110 or T1110.001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tactic_id: Mapped[str] = mapped_column(String(20), nullable=False)  # FK-by-value to attack_tactics.tactic_id
    is_subtechnique: Mapped[bool] = mapped_column(default=False, nullable=False)
    parent_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
