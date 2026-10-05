from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_intel import IOC


class IOCRepository:
    def get_by_type_and_value(self, db: Session, ioc_type: str, value: str) -> IOC | None:
        stmt = select(IOC).where(IOC.type == ioc_type, IOC.value == value)
        return db.execute(stmt).scalar_one_or_none()

    def upsert(self, db: Session, ioc_data: dict) -> IOC:
        existing = self.get_by_type_and_value(db, ioc_data["type"], ioc_data["value"])
        if existing:
            for key, value in ioc_data.items():
                setattr(existing, key, value)
            db.flush()
            return existing
        ioc = IOC(**ioc_data)
        db.add(ioc)
        db.flush()
        return ioc

    def list_all(self, db: Session) -> list[IOC]:
        return list(db.execute(select(IOC)).scalars().all())

    def to_dict(self, ioc: IOC) -> dict:
        """Converts an ORM row to the plain dict shape
        app.threat_intel.matcher.find_ioc_matches expects."""
        return {
            "id": ioc.id,
            "type": ioc.type.value if hasattr(ioc.type, "value") else ioc.type,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "threat_level": ioc.threat_level,
        }
