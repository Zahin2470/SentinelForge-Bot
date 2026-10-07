"""Aggregates all API routers into one place to include in app.main.

New routers (incidents, alerts, events, detection_rules, agent, auth, ...)
get added here as each phase in docs/architecture/architecture.md lands —
keeping this file as the single source of truth for "what routes exist"
makes it easy to audit the API surface.
"""

from fastapi import APIRouter

from app.api import agent, alerts, attack, detection_rules, events, health, incidents, ml, rag, threat_intel

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(detection_rules.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(ml.router)
api_router.include_router(threat_intel.router)
api_router.include_router(attack.router)
api_router.include_router(rag.router)
api_router.include_router(agent.router)
