"""Liveness/readiness endpoints.

/health        — process is up (liveness)
/health/ready  — process can actually serve traffic: DB + Redis reachable
                 (readiness). Used by docker-compose healthchecks and by
                 `docs/setup.md`'s "start the stack" verification step.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    settings = get_settings()

    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 — intentionally broad for a health probe
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"database unreachable: {exc}",
        ) from exc

    try:
        Redis.from_url(settings.redis_url, socket_connect_timeout=2).ping()
    except RedisError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"redis unreachable: {exc}",
        ) from exc

    return {"status": "ready"}
