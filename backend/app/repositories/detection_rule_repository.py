from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule


class DetectionRuleRepository:
    def get_by_key(self, db: Session, rule_key: str) -> DetectionRule | None:
        stmt = select(DetectionRule).where(DetectionRule.rule_key == rule_key)
        return db.execute(stmt).scalar_one_or_none()

    def list_enabled(self, db: Session, category: str | None = None) -> list[DetectionRule]:
        stmt = select(DetectionRule).where(DetectionRule.enabled.is_(True))
        if category:
            stmt = stmt.where(DetectionRule.category == category)
        return list(db.execute(stmt).scalars().all())

    def list_all(self, db: Session) -> list[DetectionRule]:
        return list(db.execute(select(DetectionRule)).scalars().all())

    def upsert_from_definition(self, db: Session, rule: dict, source_path: str) -> DetectionRule:
        """Used by scripts/sync_detection_rules.py to keep the DB index in
        step with the YAML files under detection-rules/ (the YAML remains
        the source of truth for detection logic — see docs/detection-engine.md)."""
        existing = self.get_by_key(db, rule["id"])
        fields = {
            "rule_key": rule["id"],
            "title": rule["title"],
            "category": rule["logsource"]["category"],
            "severity": rule["severity"],
            "tags": rule.get("tags", []),
            "attack_technique_id": rule.get("attack", {}).get("technique_id"),
            "enabled": rule.get("status") == "enabled",
            "source_path": source_path,
            "definition": rule,
        }
        if existing:
            for key, value in fields.items():
                setattr(existing, key, value)
            db.flush()
            return existing

        db_rule = DetectionRule(**fields)
        db.add(db_rule)
        db.flush()
        return db_rule

    def set_enabled(self, db: Session, rule_id: uuid.UUID, enabled: bool) -> DetectionRule | None:
        rule = db.get(DetectionRule, rule_id)
        if rule is None:
            return None
        rule.enabled = enabled
        db.flush()
        return rule
