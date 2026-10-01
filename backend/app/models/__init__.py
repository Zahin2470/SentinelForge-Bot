"""Importing this package registers every model on Base.metadata. Alembic's
env.py imports `app.models` (not individual model modules) for exactly this
reason — forgetting to import a new model module here is the #1 cause of
"my migration didn't pick up my new table."
"""

from app.models.agent import AgentRun, AgentStep, AgentToolCall  # noqa: F401
from app.models.asset import Asset  # noqa: F401
from app.models.attack import AttackTactic, AttackTechnique  # noqa: F401
from app.models.audit import AuditLog  # noqa: F401
from app.models.detection_rule import Alert, DetectionRule  # noqa: F401
from app.models.incident import Incident, IncidentEvent, IncidentIOC  # noqa: F401
from app.models.knowledge import KnowledgeChunk, KnowledgeDocument  # noqa: F401
from app.models.model_run import ModelRun  # noqa: F401
from app.models.notification import Notification  # noqa: F401
from app.models.security_event import SecurityEvent  # noqa: F401
from app.models.threat_intel import IOC, ThreatIntelligence  # noqa: F401
from app.models.user import Permission, Role, User  # noqa: F401

__all__ = [
    "AgentRun",
    "AgentStep",
    "AgentToolCall",
    "Asset",
    "AttackTactic",
    "AttackTechnique",
    "AuditLog",
    "Alert",
    "DetectionRule",
    "Incident",
    "IncidentEvent",
    "IncidentIOC",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "ModelRun",
    "Notification",
    "SecurityEvent",
    "IOC",
    "ThreatIntelligence",
    "Permission",
    "Role",
    "User",
]
