from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset


class AssetRepository:
    def get_by_hostname(self, db: Session, hostname: str) -> Asset | None:
        stmt = select(Asset).where(Asset.hostname == hostname)
        return db.execute(stmt).scalar_one_or_none()
