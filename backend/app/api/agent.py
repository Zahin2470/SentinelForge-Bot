"""Manual "run an investigation now" endpoint, mirroring every other
phase's manual-trigger pattern (/detection-rules/run, /incidents/correlate,
/ml/score, /threat-intel/match). In a real deployment this would be
triggered automatically when an incident reaches a severity threshold, or
on analyst request from the UI — this endpoint is that "on analyst
request" path.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.agents.llm_provider import AnthropicProvider, LLMProvider, LocalProvider, OpenAIProvider, ProviderUnavailable
from app.agents.orchestrator import run_agent
from app.agents.schemas import AgentLimits
from app.agents.tools import build_default_registry
from app.core.config import get_settings
from app.core.db import get_db

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


class InvestigateResponse(BaseModel):
    run_id: str
    incident_id: str
    status: str
    report: dict | None = None
    failure_reason: str | None = None


def _build_configured_provider() -> LLMProvider:
    """Selects the real provider from settings.llm_provider
    (docs/ai/ai-agent.md §2 — never hard-coded to one vendor). Raises
    ProviderUnavailable if unconfigured or set to something unrecognized;
    the route below turns that into the degraded-mode response rather
    than a 500."""
    settings = get_settings()
    provider_name = settings.llm_provider.lower()

    if provider_name == "anthropic":
        return AnthropicProvider(settings.llm_model, settings.llm_api_key)
    if provider_name == "openai":
        return OpenAIProvider(settings.llm_model, settings.llm_api_key)
    if provider_name == "local":
        return LocalProvider(settings.llm_model, settings.llm_model)
    raise ProviderUnavailable(
        f"No real LLM provider configured (LLM_PROVIDER={settings.llm_provider!r}). "
        "Set LLM_PROVIDER to 'anthropic', 'openai', or 'local' with credentials to enable investigations."
    )


@router.post("/investigate/{incident_id}", response_model=InvestigateResponse)
def investigate_incident(
    incident_id: uuid.UUID, actor_role: str = "SOC_ANALYST", db: Session = Depends(get_db)
) -> InvestigateResponse:
    try:
        provider = _build_configured_provider()
    except ProviderUnavailable as exc:
        # Degraded mode (docs/ai/ai-agent.md §9): a clear response, not a
        # 500 — rules/ML/correlation/threat-intel are entirely unaffected
        # by the AI agent being unavailable.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AI analysis unavailable: {exc}",
        ) from exc

    registry = build_default_registry(db)
    settings = get_settings()
    result = run_agent(
        incident_id=str(incident_id),
        tool_registry=registry,
        llm_provider=provider,
        actor_role=actor_role,
        limits=AgentLimits(
            max_steps=settings.agent_max_steps,
            max_tool_calls=settings.agent_max_tool_calls,
            max_retries=settings.agent_max_retries,
            max_investigation_seconds=settings.agent_max_investigation_seconds,
        ),
    )
    db.commit()

    report_dict = None
    if result.report:
        report_dict = {
            "classification": result.report.classification,
            "severity": result.report.severity,
            "confidence": result.report.confidence,
            "summary": result.report.summary,
            "evidence": result.report.evidence,
            "attack_mapping": [
                {"technique_id": m.technique_id, "technique_name": m.technique_name}
                for m in result.report.attack_mapping
            ],
            "recommended_next_steps": result.report.recommended_next_steps,
            "evidence_sources": result.report.evidence_sources,
            "human_approval_statement": result.report.human_approval_statement,
        }

    return InvestigateResponse(
        run_id=result.run_id,
        incident_id=result.incident_id,
        status=result.final_state.value,
        report=report_dict,
        failure_reason=result.failure_reason,
    )
