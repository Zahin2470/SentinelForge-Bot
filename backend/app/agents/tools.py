"""Tool registry (docs/ai/ai-agent.md §4). Every tool call is authorized
here, not trusted from the LLM's stated intent — `ToolRegistry.call` is
the single choke point every tool invocation passes through, matching the
architecture note "LLM → Agent tool → Authorized service → Database".

Two ways to build a registry:
- `build_default_registry(db)` — the real, DB-wired tools, calling into
  the same repositories/services every other part of this app uses. Not
  executable in this offline environment (needs sqlalchemy), reviewed not
  run, same as every other DB-touching module here.
- `build_test_registry(fixtures)` — a fully in-memory registry over plain
  dicts, used by backend/tests/agents/ to run the ENTIRE orchestration
  loop end-to-end without a database. This isn't a lesser stand-in; it
  implements the exact same Tool/ToolRegistry contract the real registry
  does, so a test that passes against it is testing real orchestrator
  behavior, just with fixture data standing in for Postgres.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from app.agents.schemas import ToolCall, ToolResult
from app.core.permissions import is_authorized

# Every tool not explicitly given a required_permission defaults to
# "ai_copilot:use" — the baseline permission to run the AI SOC Analyst at
# all (docs/ai/ai-agent.md §4: "almost all tools are read-only"). Only the
# SIMULATE_* write tools require anything beyond that.
DEFAULT_PERMISSION = "ai_copilot:use"


@dataclass
class Tool:
    name: str
    description: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]  # returns {"output": {...}, "evidence_ids": [...]}
    required_permission: str = DEFAULT_PERMISSION
    read_only: bool = True


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool {tool.name!r} already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def call(self, tool_call: ToolCall, *, actor_role: str) -> ToolResult:
        """The single choke point every tool invocation passes through.
        Never raises — every failure mode (unknown tool, unauthorized,
        handler exception) becomes a ToolResult the orchestrator can react
        to, exactly like a real tool-use API response would."""
        start = time.time()
        tool = self.get(tool_call.tool_name)

        if tool is None:
            return ToolResult(
                call_id=tool_call.call_id,
                tool_name=tool_call.tool_name,
                authorized=False,
                success=False,
                error=f"Unknown tool: {tool_call.tool_name!r}. Available: {self.names()}",
            )

        if not is_authorized(actor_role, tool.required_permission):
            return ToolResult(
                call_id=tool_call.call_id,
                tool_name=tool_call.tool_name,
                authorized=False,
                success=False,
                error=f"Role {actor_role!r} lacks required permission {tool.required_permission!r}",
            )

        try:
            result = tool.handler(tool_call.input)
        except Exception as exc:  # noqa: BLE001 — a tool handler's own bug must not crash the whole run
            return ToolResult(
                call_id=tool_call.call_id,
                tool_name=tool_call.tool_name,
                authorized=True,
                success=False,
                error=str(exc),
                latency_ms=(time.time() - start) * 1000,
            )

        return ToolResult(
            call_id=tool_call.call_id,
            tool_name=tool_call.tool_name,
            authorized=True,
            success=True,
            output=result.get("output", {}),
            evidence_ids=result.get("evidence_ids", []),
            latency_ms=(time.time() - start) * 1000,
        )


# ---------------------------------------------------------------------------
# SIMULATE_* actions — the only "write" tools, and even these only ever
# write to simulation state pending human approval
# (docs/ai/ai-agent.md §7). Shared by both registries since the behavior
# is identical either way: record the proposed action, never execute it.
# ---------------------------------------------------------------------------


def _make_simulate_handler(action_name: str) -> Callable[[dict], dict]:
    def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "output": {
                "action": action_name,
                "target": input_data.get("target"),
                "status": "AWAITING_HUMAN_APPROVAL",
                "note": "No automatic containment action was executed. Human analyst approval is required.",
            },
            "evidence_ids": [],
        }

    return handler


def register_simulate_tools(registry: ToolRegistry) -> None:
    for action in ("SIMULATE_DISABLE_ACCOUNT", "SIMULATE_ISOLATE_HOST", "SIMULATE_BLOCK_IP"):
        registry.register(
            Tool(
                name=action,
                description=f"Propose {action.replace('_', ' ').title()} — writes simulation state only, "
                f"never executes for real; remains AWAITING_HUMAN_APPROVAL until an analyst confirms.",
                handler=_make_simulate_handler(action),
                required_permission="incidents:write",
                read_only=False,
            )
        )


def build_default_registry(db: Any) -> ToolRegistry:
    """The real, DB-wired tool registry — calls into the same
    repositories/services every other part of this app uses
    (SecurityEventRepository, AlertRepository, ThreatIntelService's
    IOCRepository, RAGService, app.attack.reference_data). `db` is a
    sqlalchemy Session; typed as Any here so this module stays importable
    without sqlalchemy installed (only build_default_registry itself
    needs it, and only when actually called).

    Reviewed, not executed in this offline dev environment — same caveat
    as every other DB-touching constructor in this repo (correlation
    service, ml scoring service, threat intel service, rag service).
    """
    from app.attack.reference_data import map_technique
    from app.repositories.alert_repository import AlertRepository
    from app.repositories.ioc_repository import IOCRepository
    from app.repositories.security_event_repository import SecurityEventRepository
    from app.services.rag_service import KnowledgeBaseNotIngested, RAGService

    event_repo = SecurityEventRepository()
    alert_repo = AlertRepository()
    ioc_repo = IOCRepository()
    rag_service = RAGService()

    registry = ToolRegistry()

    def search_security_events(input_data: dict) -> dict:
        events = event_repo.search(
            db,
            username=input_data.get("username"),
            hostname=input_data.get("hostname"),
            source_ip=input_data.get("source_ip"),
            event_type=input_data.get("event_type"),
            limit=input_data.get("limit", 50),
        )
        return {
            "output": {"events": [{"id": str(e.id), "event_type": e.event_type} for e in events]},
            "evidence_ids": [str(e.id) for e in events],
        }

    def get_event_by_id(input_data: dict) -> dict:
        import uuid as _uuid

        event = event_repo.get_by_id(db, _uuid.UUID(str(input_data["event_id"])))
        if event is None:
            return {"output": {"found": False}, "evidence_ids": []}
        return {"output": {"found": True, "event": {"id": str(event.id)}}, "evidence_ids": [str(event.id)]}

    def get_alert_context(input_data: dict) -> dict:
        import uuid as _uuid

        incident_id = input_data.get("incident_id")
        alerts = alert_repo.list_for_incident(db, _uuid.UUID(str(incident_id))) if incident_id else []
        evidence: list[str] = []
        for a in alerts:
            evidence.extend(str(eid) for eid in a.matched_event_ids)
        return {
            "output": {"alerts": [{"id": str(a.id), "severity": a.severity} for a in alerts]},
            "evidence_ids": evidence,
        }

    def search_threat_intelligence(input_data: dict) -> dict:
        iocs = ioc_repo.list_all(db)
        value = input_data.get("value")
        matched = [i for i in iocs if not value or i.value == value]
        return {
            "output": {"iocs": [{"id": str(i.id), "threat_level": i.threat_level} for i in matched]},
            "evidence_ids": [str(i.id) for i in matched],
        }

    def search_security_knowledge(input_data: dict) -> dict:
        try:
            results = rag_service.retrieve(db, input_data.get("query", ""), k=input_data.get("k", 5))
        except KnowledgeBaseNotIngested:
            return {"output": {"results": [], "evidence_sources": []}, "evidence_ids": []}
        sources = [f"{r.document_title} ({r.source})" for r in results]
        return {
            "output": {"results": [{"content": r.content} for r in results], "evidence_sources": sources},
            "evidence_ids": [],
        }

    def lookup_attack_technique(input_data: dict) -> dict:
        mapping = map_technique(input_data.get("technique_id", ""))
        if mapping is None:
            return {"output": {"found": False}, "evidence_ids": []}
        return {"output": {"found": True, **mapping}, "evidence_ids": []}

    registry.register(
        Tool("search_security_events", "Search normalized security events by filter.", search_security_events)
    )
    registry.register(Tool("get_event_by_id", "Fetch one security event by ID.", get_event_by_id))
    registry.register(Tool("get_alert_context", "Get all alerts tied to an incident.", get_alert_context))
    registry.register(Tool("search_threat_intelligence", "Look up known IOCs.", search_threat_intelligence))
    registry.register(
        Tool("search_security_knowledge", "Semantic search over the SOC knowledge base.", search_security_knowledge)
    )
    registry.register(
        Tool("lookup_attack_technique", "Look up a MITRE ATT&CK technique by ID.", lookup_attack_technique)
    )
    register_simulate_tools(registry)

    return registry


def build_test_registry(fixtures: dict[str, Any]) -> ToolRegistry:
    """In-memory registry for tests. `fixtures` provides:
    events (list[dict]), alerts (list[dict]), iocs (list[dict]),
    rag_chunks (list[dict] with 'content','document_title','source'),
    attack_techniques (dict[str, dict]).
    """
    registry = ToolRegistry()
    events = fixtures.get("events", [])
    alerts = fixtures.get("alerts", [])
    iocs = fixtures.get("iocs", [])
    rag_chunks = fixtures.get("rag_chunks", [])
    events_by_id = {str(e["id"]): e for e in events}
    _rag_cache: dict[str, Any] = {}

    def search_security_events(input_data: dict) -> dict:
        username = input_data.get("username")
        hostname = input_data.get("hostname")
        matched = [
            e
            for e in events
            if (username is None or e.get("username") == username)
            and (hostname is None or e.get("hostname") == hostname)
        ]
        return {
            "output": {"events": [{"id": str(e["id"]), "event_type": e.get("event_type")} for e in matched]},
            "evidence_ids": [str(e["id"]) for e in matched],
        }

    def get_event_by_id(input_data: dict) -> dict:
        event_id = str(input_data.get("event_id"))
        event = events_by_id.get(event_id)
        if event is None:
            return {"output": {"found": False}, "evidence_ids": []}
        return {"output": {"found": True, "event": {"id": event_id}}, "evidence_ids": [event_id]}

    def get_alert_context(_input_data: dict) -> dict:
        evidence = []
        for a in alerts:
            evidence.extend(str(eid) for eid in a.get("matched_event_ids", []))
        return {
            "output": {"alerts": [{"id": str(a["id"]), "severity": a["severity"]} for a in alerts]},
            "evidence_ids": evidence,
        }

    def search_threat_intelligence(input_data: dict) -> dict:
        value = input_data.get("value")
        matched = [i for i in iocs if i.get("value") == value] if value else iocs
        return {
            "output": {"iocs": [{"id": str(i["id"]), "threat_level": i.get("threat_level")} for i in matched]},
            "evidence_ids": [str(i["id"]) for i in matched],
        }

    def search_security_knowledge(input_data: dict) -> dict:
        """Uses the REAL retrieval stack (app.rag.embeddings +
        app.rag.retrieval), not a naive stand-in — a fixture that faked
        relevance ranking with substring matching would prove nothing
        about whether the real RAG pipeline plugs into the agent
        correctly. The TF-IDF vectorizer is fit lazily on first call and
        cached on the closure, mirroring how the real tool would use an
        already-fitted provider rather than refitting per query.
        """
        query = input_data.get("query", "")
        if not rag_chunks:
            return {"output": {"results": [], "evidence_sources": []}, "evidence_ids": []}

        if "_provider" not in _rag_cache:
            from app.rag.embeddings import TfidfEmbeddingProvider

            provider = TfidfEmbeddingProvider(max_features=512)
            provider.fit([c["content"] for c in rag_chunks])
            _rag_cache["_provider"] = provider
            _rag_cache["_vectors"] = provider.embed([c["content"] for c in rag_chunks])

        from app.rag.retrieval import retrieve_top_k

        provider = _rag_cache["_provider"]
        vectors = _rag_cache["_vectors"]
        chunk_dicts = [
            {"id": str(i), "content": c["content"], "document_title": c["document_title"], "source": c["source"]}
            for i, c in enumerate(rag_chunks)
        ]
        query_vector = provider.embed([query])[0]
        results = retrieve_top_k(query_vector, chunk_dicts, vectors, k=5)

        sources = [f"{r.document_title} ({r.source})" for r in results]
        return {
            "output": {
                "results": [{"content": r.content, "document_title": r.document_title} for r in results],
                "evidence_sources": sources,
            },
            "evidence_ids": [],
        }

    def lookup_attack_technique(input_data: dict) -> dict:
        technique_id = input_data.get("technique_id")
        technique = fixtures.get("attack_techniques", {}).get(technique_id)
        if not technique:
            return {"output": {"found": False}, "evidence_ids": []}
        return {"output": {"found": True, **technique}, "evidence_ids": []}

    registry.register(Tool("search_security_events", "Search normalized security events by filter.", search_security_events))
    registry.register(Tool("get_event_by_id", "Fetch one security event by ID.", get_event_by_id))
    registry.register(Tool("get_alert_context", "Get all alerts tied to the current incident.", get_alert_context))
    registry.register(Tool("search_threat_intelligence", "Look up known IOCs.", search_threat_intelligence))
    registry.register(
        Tool("search_security_knowledge", "Semantic search over the SOC knowledge base.", search_security_knowledge)
    )
    registry.register(
        Tool("lookup_attack_technique", "Look up a MITRE ATT&CK technique by ID.", lookup_attack_technique)
    )
    register_simulate_tools(registry)

    return registry
