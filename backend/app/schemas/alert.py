from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DetectionRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_key: str
    title: str
    category: str
    severity: str
    tags: list[str]
    attack_technique_id: str | None = None
    enabled: bool


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    source: str
    detection_rule_id: uuid.UUID | None = None
    title: str
    severity: str
    matched_event_ids: list[uuid.UUID]
    entity_username: str | None = None
    entity_hostname: str | None = None
    incident_id: uuid.UUID | None = None
