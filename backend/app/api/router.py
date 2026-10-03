"""Aggregates all API routers into one place to include in app.main.

New routers (incidents, alerts, events, detection_rules, agent, auth, ...)
get added here as each phase in docs/architecture/architecture.md lands —
keeping this file as the single source of truth for "what routes exist"
makes it easy to audit the API surface.
"""

from fastapi import APIRouter

from app.api import alerts, detection_rules, events, health

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(detection_rules.router)
api_router.include_router(alerts.router)

# Phase 4+: api_router.include_router(incidents.router, prefix="/api/v1/incidents", ...)
# Phase 8+: api_router.include_router(agent.router, prefix="/api/v1/agent", ...)
