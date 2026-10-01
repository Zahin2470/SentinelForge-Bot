"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-17

Hand-authored to match app/models/* exactly (rather than generated via
`alembic revision --autogenerate`, which requires a live database
connection this environment doesn't have). Before relying on this in a real
run: bring up the stack (`docker compose up`), then verify it with
`alembic check` / a throwaway `alembic revision --autogenerate` diffed
against this file — see docs/setup.md.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMBEDDING_DIM = 1536


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
    )

    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "name",
            sa.Enum("ADMIN", "SOC_ANALYST", "SECURITY_MANAGER", "VIEWER", name="rolename"),
            nullable=False,
            unique=True,
        ),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
    )

    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "permission_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("permissions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("roles.id"), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("hostname", sa.String(255), nullable=False, unique=True),
        sa.Column("asset_type", sa.String(50), nullable=False),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("environment", sa.String(50), nullable=False, server_default="production"),
        sa.Column(
            "criticality",
            sa.Enum("low", "medium", "high", "critical", name="assetcriticality"),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("criticality_score", sa.Float, nullable=False, server_default="0.5"),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])

    op.create_table(
        "security_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer, nullable=True),
        sa.Column("destination_port", sa.Integer, nullable=True),
        sa.Column("protocol", sa.String(20), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("process_id", sa.Integer, nullable=True),
        sa.Column("command_line", sa.String, nullable=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("action", sa.String(100), nullable=True),
        sa.Column("status", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("user_agent", sa.String, nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("file_hash", sa.String(128), nullable=True),
        sa.Column("url", sa.String, nullable=True),
        sa.Column("country", sa.String(2), nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("raw_event", postgresql.JSONB, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=True),
    )
    for col in ["timestamp", "username", "hostname", "source_ip", "destination_ip", "event_type", "severity"]:
        op.create_index(f"ix_security_events_{col}", "security_events", [col])

    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("rule_key", sa.String(100), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("attack_technique_id", sa.String(20), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("source_path", sa.String(500), nullable=False),
        sa.Column("definition", postgresql.JSONB, nullable=False),
    )

    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("display_id", sa.String(20), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "OPEN", "TRIAGED", "INVESTIGATING", "CONTAINMENT_RECOMMENDED",
                "AWAITING_REVIEW", "RESOLVED", "FALSE_POSITIVE", "CLOSED",
                name="incidentstatus",
            ),
            nullable=False,
            server_default="OPEN",
        ),
        sa.Column("rule_score", sa.Float, nullable=True),
        sa.Column("anomaly_score", sa.Float, nullable=True),
        sa.Column("correlation_score", sa.Float, nullable=True),
        sa.Column("threat_intelligence_score", sa.Float, nullable=True),
        sa.Column("asset_criticality_score", sa.Float, nullable=True),
        sa.Column("identity_context_score", sa.Float, nullable=True),
        sa.Column("final_risk_score", sa.Float, nullable=True),
        sa.Column("assigned_to_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("primary_host", sa.String(255), nullable=True),
        sa.Column("primary_user", sa.String(255), nullable=True),
        sa.Column("attack_techniques", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("ai_summary", postgresql.JSONB, nullable=True),
        sa.Column("analyst_notes", sa.Text, nullable=False, server_default=""),
        sa.Column("resolution", sa.Text, nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column(
            "detection_rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detection_rules.id"),
            nullable=True,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("matched_event_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False),
        sa.Column("anomaly_score", sa.Float, nullable=True),
        sa.Column("model_version", sa.String(50), nullable=True),
        sa.Column("entity_username", sa.String(255), nullable=True),
        sa.Column("entity_hostname", sa.String(255), nullable=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id"), nullable=True),
    )

    op.create_table(
        "incident_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "security_event_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("security_events.id"),
            nullable=False,
        ),
        sa.Column(
            "linked_via_alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id"), nullable=True
        ),
    )

    op.create_table(
        "iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "type",
            sa.Enum("ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", name="ioctype"),
            nullable=False,
        ),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("threat_level", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("related_campaign", sa.String(255), nullable=True),
        sa.Column("related_techniques", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
    )
    op.create_index("ix_iocs_value", "iocs", ["value"])

    op.create_table(
        "incident_iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ioc_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("iocs.id"), nullable=False),
    )

    op.create_table(
        "threat_intelligence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("stix_type", sa.String(100), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("raw_stix", postgresql.JSONB, nullable=False),
    )

    op.create_table(
        "attack_tactics",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tactic_id", sa.String(20), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
    )

    op.create_table(
        "attack_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("technique_id", sa.String(20), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("tactic_id", sa.String(20), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("parent_technique_id", sa.String(20), nullable=True),
    )

    op.create_table(
        "agent_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("requested_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "RECEIVED", "UNDERSTANDING", "COLLECTING_EVIDENCE", "CORRELATING",
                "THREAT_INTELLIGENCE_LOOKUP", "HYPOTHESIS_GENERATION", "HYPOTHESIS_VALIDATION",
                "RISK_ASSESSMENT", "REPORT_GENERATION", "HUMAN_REVIEW", "COMPLETED", "FAILED",
                name="agentrunstatus",
            ),
            nullable=False,
            server_default="RECEIVED",
        ),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_tool_calls", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_steps", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_tokens", sa.Integer, nullable=True),
        sa.Column("failure_reason", sa.Text, nullable=True),
    )

    op.create_table(
        "agent_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("step_index", sa.Integer, nullable=False),
        sa.Column(
            "state",
            postgresql.ENUM(
                "RECEIVED", "UNDERSTANDING", "COLLECTING_EVIDENCE", "CORRELATING",
                "THREAT_INTELLIGENCE_LOOKUP", "HYPOTHESIS_GENERATION", "HYPOTHESIS_VALIDATION",
                "RISK_ASSESSMENT", "REPORT_GENERATION", "HUMAN_REVIEW", "COMPLETED", "FAILED",
                name="agentrunstatus",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("summary", sa.Text, nullable=False, server_default=""),
        sa.Column("error", sa.Text, nullable=True),
    )

    op.create_table(
        "agent_tool_calls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "step_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agent_steps.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("input_summary", postgresql.JSONB, nullable=False),
        sa.Column("result_summary", postgresql.JSONB, nullable=False),
        sa.Column("authorized", sa.Boolean, nullable=False),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("called_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "knowledge_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("version", sa.String(50), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "knowledge_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "document_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("knowledge_documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("chunk_index", sa.Integer, nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("embedding", Vector(EMBEDDING_DIM), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    # IVFFlat index for approximate nearest-neighbor search. `lists` is a
    # starting point (rule of thumb ~ sqrt(row_count)); revisit once the
    # knowledge base has real volume (docs/ai/ai-agent.md — RAG section).
    op.execute(
        "CREATE INDEX ix_knowledge_chunks_embedding ON knowledge_chunks "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
    )

    op.create_table(
        "model_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("model_version", sa.String(50), nullable=False, unique=True),
        sa.Column("model_type", sa.String(50), nullable=False),
        sa.Column("trained_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("training_sample_count", sa.Integer, nullable=False),
        sa.Column("feature_schema", postgresql.JSONB, nullable=False),
        sa.Column("hyperparameters", postgresql.JSONB, nullable=False),
        sa.Column("precision", sa.Float, nullable=True),
        sa.Column("recall", sa.Float, nullable=True),
        sa.Column("pr_auc", sa.Float, nullable=True),
        sa.Column("artifact_path", sa.String(500), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_type", sa.String(20), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_label", sa.String(255), nullable=False),
        sa.Column("session_id", sa.String(255), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("object_type", sa.String(100), nullable=False),
        sa.Column("object_id", sa.String(255), nullable=False),
        sa.Column("details", postgresql.JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])

    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("read", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("body", sa.String(1000), nullable=False, server_default=""),
        sa.Column("related_object_type", sa.String(100), nullable=True),
        sa.Column("related_object_id", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("notifications")
    op.drop_table("audit_logs")
    op.drop_table("model_runs")
    op.execute("DROP INDEX IF EXISTS ix_knowledge_chunks_embedding")
    op.drop_table("knowledge_chunks")
    op.drop_table("knowledge_documents")
    op.drop_table("agent_tool_calls")
    op.drop_table("agent_steps")
    op.drop_table("agent_runs")
    op.drop_table("attack_techniques")
    op.drop_table("attack_tactics")
    op.drop_table("threat_intelligence")
    op.drop_table("incident_iocs")
    op.drop_table("iocs")
    op.drop_table("incident_events")
    op.drop_table("alerts")
    op.drop_table("incidents")
    op.drop_table("detection_rules")
    op.drop_table("security_events")
    op.drop_table("assets")
    op.drop_table("users")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("permissions")
    op.execute("DROP TYPE IF EXISTS agentrunstatus")
    op.execute("DROP TYPE IF EXISTS incidentstatus")
    op.execute("DROP TYPE IF EXISTS assetcriticality")
    op.execute("DROP TYPE IF EXISTS ioctype")
    op.execute("DROP TYPE IF EXISTS rolename")
