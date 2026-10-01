"""Persisted agent execution state (docs/ai/ai-agent.md §3). One AgentRun
per investigation; AgentStep per state-machine transition; AgentToolCall per
tool invocation within a step. This is what makes the agent auditable and
debuggable after the fact — "what did the AI actually do for INC-0012" is
always answerable from these three tables, not from re-reading logs.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class AgentRunStatus(str, enum.Enum):
    RECEIVED = "RECEIVED"
    UNDERSTANDING = "UNDERSTANDING"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    CORRELATING = "CORRELATING"
    THREAT_INTELLIGENCE_LOOKUP = "THREAT_INTELLIGENCE_LOOKUP"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    HYPOTHESIS_VALIDATION = "HYPOTHESIS_VALIDATION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    REPORT_GENERATION = "REPORT_GENERATION"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AgentRun(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "agent_runs"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False
    )
    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    status: Mapped[AgentRunStatus] = mapped_column(default=AgentRunStatus.RECEIVED, nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_tool_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_steps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class AgentStep(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "agent_steps"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[AgentRunStatus] = mapped_column(nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Summary only — never the raw prompt if it would contain unnecessary
    # sensitive data (docs/ai/ai-agent.md §3).
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AgentToolCall(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "agent_tool_calls"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    step_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_steps.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    input_summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    result_summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    authorized: Mapped[bool] = mapped_column(nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    called_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
