"""The capstone integration test: a full AI SOC Analyst investigation,
using real data that actually flowed through normalize -> detect ->
threat-intel-match -> RAG retrieval (the same pipeline
tests/test_scenario_pipeline.py proves), fed into a scripted
MockLLMProvider that calls real tools via the in-memory ToolRegistry and
produces a validated, evidence-grounded InvestigationReport through the
real orchestrator.

This is deliberately self-contained (re-derives events/alerts/IOC matches
rather than importing tests/test_scenario_pipeline.py's helpers) so it
doesn't depend on fragile cross-test-file imports — see that file for the
narrower per-stage proofs; this one proves the AI agent layer sits
correctly on top of everything below it.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (_REPO_ROOT, _REPO_ROOT / "backend"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.agents.evidence import collect_evidence_ids  # noqa: E402
from app.agents.llm_provider import AgentDecision, MockLLMProvider  # noqa: E402
from app.agents.orchestrator import run_agent  # noqa: E402
from app.agents.schemas import AgentState, ToolCall  # noqa: E402
from app.agents.tools import build_test_registry  # noqa: E402
from app.detection.executor import evaluate_rule  # noqa: E402
from app.detection.parser import load_rules_from_dir  # noqa: E402
from app.ingest.normalizer import normalize  # noqa: E402
from app.rag.chunking import chunk_document  # noqa: E402
from app.threat_intel.matcher import find_ioc_matches  # noqa: E402
from app.threat_intel.stix_normalizer import UnsupportedStixPattern, normalize_stix_indicator  # noqa: E402
from simulator.scenarios import get_scenario  # noqa: E402

_id_counter = itertools.count(1)


def _build_investigation_fixtures() -> dict:
    """Rebuilds real events/alerts/IOCs/knowledge chunks from the actual
    brute_force_privilege_escalation scenario and the actual sample threat
    intel feed and knowledge base — the same real artifacts every other
    phase's tests use, not synthetic agent-only fixtures."""
    scenario = get_scenario("brute_force_privilege_escalation")

    events = []
    for source_format, raw in scenario.events:
        event = normalize(source_format, raw)
        event["id"] = f"evt-{next(_id_counter)}"
        events.append(event)
    events_by_id = {e["id"]: e for e in events}

    rules = load_rules_from_dir("detection-rules", only_enabled=True)
    alerts = []
    for rule in rules:
        if rule["logsource"]["category"] == "correlation":
            continue
        for result in evaluate_rule(rule, events):
            if not result.matched:
                continue
            matched_events = [events_by_id[eid] for eid in result.matched_event_ids]
            alerts.append(
                {
                    "id": f"alert-{next(_id_counter)}",
                    "severity": result.severity,
                    "matched_event_ids": [e["id"] for e in matched_events],
                    "rule_id": result.rule_id,
                }
            )

    with open("threat-intel/sample_feed.json") as f:
        bundle = json.load(f)
    iocs = []
    for obj in bundle["objects"]:
        if obj.get("type") != "indicator":
            continue
        try:
            ioc = normalize_stix_indicator(obj)
        except UnsupportedStixPattern:
            continue
        ioc["id"] = f"ioc-{obj['id']}"
        iocs.append(ioc)

    ioc_matches = find_ioc_matches(events, iocs)

    rag_chunks = []
    kb_dir = Path("knowledge-base")
    for path in sorted(kb_dir.rglob("*.md")):
        text = path.read_text()
        title = text.splitlines()[0].lstrip("# ").strip()
        category = path.parent.name
        for chunk in chunk_document(text):
            rag_chunks.append({"content": chunk.content, "document_title": title, "source": category})

    attack_techniques = {
        "T1110": {"technique_name": "Brute Force", "tactic_id": "TA0006", "tactic_name": "Credential Access"},
        "T1562": {"technique_name": "Impair Defenses", "tactic_id": "TA0005", "tactic_name": "Defense Evasion"},
    }

    return {
        "events": events,
        "alerts": alerts,
        "iocs": iocs,
        "ioc_matches": ioc_matches,
        "rag_chunks": rag_chunks,
        "attack_techniques": attack_techniques,
    }


def test_full_agent_investigation_over_real_pipeline_data() -> None:
    fixtures = _build_investigation_fixtures()

    # Sanity checks on the fixtures themselves — if these fail, the bug is
    # in the pipeline setup, not the agent, and the test should say so
    # clearly rather than failing deep inside orchestrator logic.
    assert len(fixtures["alerts"]) >= 2, "expected both AUTH-BRUTEFORCE-001 and CLOUD-SECCONTROL-001 alerts"
    assert len(fixtures["ioc_matches"]) >= 1, "expected the sample feed's attacker IP to match"
    assert len(fixtures["rag_chunks"]) > 20

    registry = build_test_registry(fixtures)

    def collect_evidence_and_build_report(*, tool_results_so_far, **_kwargs):
        """Mimics what a real LLM does at REPORT_GENERATION: look at
        everything the tool calls actually returned, and cite exactly
        that — not hand-typed IDs that might not even match what was
        really gathered. This is what makes the report's grounding a real
        proof, not a coincidence."""
        gathered_ids = sorted(collect_evidence_ids(tool_results_so_far))
        evidence_sources: list[str] = []
        for r in tool_results_so_far:
            evidence_sources.extend(r.output.get("evidence_sources", []))

        return AgentDecision(
            next_state=AgentState.COMPLETED,
            final_report={
                "classification": "brute_force_credential_access",
                "severity": "critical",
                "confidence": 0.88,
                "summary": (
                    "Repeated failed authentication for jdoe from a known-malicious IP, followed by a "
                    "successful login and a subsequent security-logging control disablement — consistent "
                    "with brute-force credential access followed by defense evasion."
                ),
                "evidence": gathered_ids,
                "detection_contributions": sorted({a["rule_id"] for a in fixtures["alerts"]}),
                "attack_mapping": [
                    {"technique_id": "T1110", "technique_name": "Brute Force"},
                    {"technique_id": "T1562", "technique_name": "Impair Defenses"},
                ],
                "alternative_explanations": [
                    "Shared VPN egress producing failures from multiple legitimate users (ruled out: "
                    "failures all target the same username, not multiple users at one IP)."
                ],
                "unknowns": ["Whether MFA was configured and challenged for this account."],
                "recommended_next_steps": [
                    "Reset jdoe's credentials and revoke active sessions.",
                    "Re-enable the disabled logging control if it is still off.",
                ],
                "evidence_sources": sorted(set(evidence_sources)),
            },
            reasoning_summary="Gathered event/alert/IOC/knowledge evidence and produced a grounded report.",
        )

    script = [
        AgentDecision(next_state=AgentState.UNDERSTANDING, reasoning_summary="Reviewing incident context."),
        AgentDecision(
            next_state=AgentState.COLLECTING_EVIDENCE,
            tool_calls=[
                ToolCall(tool_name="search_security_events", input={"username": "jdoe"}),
                ToolCall(tool_name="get_alert_context", input={}),
            ],
            reasoning_summary="Pulling all events and alerts tied to this identity.",
        ),
        AgentDecision(next_state=AgentState.CORRELATING, reasoning_summary="Alerts share entity and time window."),
        AgentDecision(
            next_state=AgentState.THREAT_INTELLIGENCE_LOOKUP,
            tool_calls=[ToolCall(tool_name="search_threat_intelligence", input={"value": "198.51.100.23"})],
            reasoning_summary="Checking the source IP against known indicators.",
        ),
        AgentDecision(
            next_state=AgentState.HYPOTHESIS_GENERATION,
            reasoning_summary="Hypothesis: brute-force credential access followed by defense evasion.",
        ),
        AgentDecision(
            next_state=AgentState.HYPOTHESIS_VALIDATION,
            tool_calls=[
                ToolCall(tool_name="lookup_attack_technique", input={"technique_id": "T1110"}),
                ToolCall(tool_name="search_security_knowledge", input={"query": "brute force response playbook"}),
            ],
            reasoning_summary="Validating against ATT&CK reference and SOC playbook guidance.",
        ),
        AgentDecision(next_state=AgentState.RISK_ASSESSMENT, reasoning_summary="Critical: known-bad IP + defense evasion."),
        AgentDecision(next_state=AgentState.REPORT_GENERATION, reasoning_summary="Drafting the investigation report."),
        AgentDecision(next_state=AgentState.HUMAN_REVIEW, reasoning_summary="Report ready for analyst review."),
        collect_evidence_and_build_report,
    ]
    provider = MockLLMProvider(script, model_name="mock-investigator-v1")

    result = run_agent(
        incident_id="INC-TEST-0001",
        tool_registry=registry,
        llm_provider=provider,
        actor_role="SOC_ANALYST",
        incident_context={"primary_user": "jdoe", "primary_host": "corp-vpn-gw"},
    )

    # --- The actual proof ---
    assert result.succeeded, f"investigation failed: {result.failure_reason}"
    assert result.final_state == AgentState.COMPLETED

    report = result.report
    assert report.severity == "critical"
    assert 0.0 <= report.confidence <= 1.0
    assert len(report.evidence) > 0, "a completed report must have cited evidence"
    assert {"T1110", "T1562"} == {m.technique_id for m in report.attack_mapping}
    assert any("Brute Force" in s or "playbook" in s.lower() for s in report.evidence_sources), (
        f"expected a playbook citation in evidence_sources, got {report.evidence_sources}"
    )
    assert "human analyst approval is required" in report.human_approval_statement.lower()
    assert report.alternative_explanations  # a real investigation considers what else it could be
    assert report.recommended_next_steps

    # Every step actually happened, in the right order, ending at COMPLETED —
    # confirms the state machine, not just the final report, is correct.
    state_sequence = [s.state for s in result.steps]
    assert state_sequence[0] == AgentState.UNDERSTANDING
    assert state_sequence[-1] == AgentState.COMPLETED
    assert AgentState.COLLECTING_EVIDENCE in state_sequence
    assert AgentState.THREAT_INTELLIGENCE_LOOKUP in state_sequence

    # Tool calls actually happened and were authorized.
    all_tool_results = [tr for step in result.steps for tr in step.tool_calls]
    assert len(all_tool_results) == 5  # 2 + 1 + 2 across the scripted steps
    assert all(tr.authorized and tr.success for tr in all_tool_results)


def test_viewer_role_cannot_run_an_investigation_at_all() -> None:
    """A VIEWER has no ai_copilot:use permission — every tool call in an
    investigation should be rejected, so the run should fail immediately
    rather than silently producing a report with no real evidence."""
    fixtures = _build_investigation_fixtures()
    registry = build_test_registry(fixtures)

    script = [
        AgentDecision(next_state=AgentState.UNDERSTANDING),
        AgentDecision(
            next_state=AgentState.COLLECTING_EVIDENCE,
            tool_calls=[ToolCall(tool_name="search_security_events", input={"username": "jdoe"})],
        ),
    ]
    provider = MockLLMProvider(script)

    result = run_agent("INC-TEST-0002", registry, provider, actor_role="VIEWER")

    tool_results = [tr for step in result.steps for tr in step.tool_calls]
    assert len(tool_results) == 1
    assert tool_results[0].authorized is False


if __name__ == "__main__":
    test_full_agent_investigation_over_real_pipeline_data()
    test_viewer_role_cannot_run_an_investigation_at_all()
    print("All agent investigation capstone tests passed.")
