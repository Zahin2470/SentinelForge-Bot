"""SentinelForge AI backend entrypoint.

Deliberately thin: this file wires up the FastAPI app, middleware, and the
aggregated router. Business logic lives in app/services, data access in
app/repositories, and domain-specific engines in app/detection,
app/correlation, app/ml, app/agents, app/rag, app/threat_intel, app/attack.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="SentinelForge AI",
    description="Defensive SOC platform — detection, correlation, ML anomaly "
    "scoring, and an evidence-grounded AI SOC analyst.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.on_event("startup")
async def on_startup() -> None:
    logger.info(
        "sentinelforge_backend_starting",
        environment=settings.environment,
        llm_provider=settings.llm_provider,
    )
