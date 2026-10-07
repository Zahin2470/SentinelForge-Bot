"""Tests for app.agents.tools — pure, no DB needed. Uses build_test_registry,
the same in-memory registry the big orchestrator integration test uses.
"""

from app.agents.schemas import ToolCall
from app.agents.tools import Tool, ToolRegistry, build_test_registry


def test_registering_duplicate_tool_name_raises() -> None:
    registry = ToolRegistry()
    registry.register(Tool("t1", "desc", lambda _: {"output": {}, "evidence_ids": []}))
    try:
        registry.register(Tool("t1", "desc2", lambda _: {"output": {}, "evidence_ids": []}))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_unknown_tool_call_returns_unauthorized_error_not_raise() -> None:
    registry = build_test_registry({})
    result = registry.call(ToolCall(tool_name="not_a_real_tool", input={}), actor_role="ADMIN")

    assert result.success is False
    assert result.authorized is False
    assert "Unknown tool" in result.error


def test_authorized_role_can_call_read_only_tool() -> None:
    registry = build_test_registry({"events": [{"id": "evt-1", "username": "jdoe", "event_type": "authentication"}]})
    result = registry.call(
        ToolCall(tool_name="search_security_events", input={"username": "jdoe"}), actor_role="SOC_ANALYST"
    )

    assert result.success is True
    assert result.authorized is True
    assert result.evidence_ids == ["evt-1"]


def test_viewer_role_cannot_call_ai_copilot_tools() -> None:
    """VIEWER lacks ai_copilot:use — every default-permission tool must
    reject it, not just the write tools."""
    registry = build_test_registry({"events": []})
    result = registry.call(ToolCall(tool_name="search_security_events", input={}), actor_role="VIEWER")

    assert result.success is False
    assert result.authorized is False
    assert "lacks required permission" in result.error


def test_simulate_tools_require_incidents_write_not_just_ai_copilot_use() -> None:
    """SOC_ANALYST has ai_copilot:use AND incidents:write, so it CAN
    propose a simulated action — but the action must never actually
    execute, only propose."""
    registry = build_test_registry({})
    result = registry.call(
        ToolCall(tool_name="SIMULATE_ISOLATE_HOST", input={"target": "corp-dc-01"}), actor_role="SOC_ANALYST"
    )

    assert result.success is True
    assert result.output["status"] == "AWAITING_HUMAN_APPROVAL"
    assert "no automatic containment action was executed" in result.output["note"].lower()


def test_viewer_cannot_propose_simulate_actions() -> None:
    """VIEWER has neither ai_copilot:use nor incidents:write."""
    registry = build_test_registry({})
    result = registry.call(ToolCall(tool_name="SIMULATE_BLOCK_IP", input={"target": "1.2.3.4"}), actor_role="VIEWER")

    assert result.authorized is False


def test_tool_handler_exception_becomes_failed_result_not_raised() -> None:
    def broken_handler(_input):
        raise RuntimeError("boom")

    registry = ToolRegistry()
    registry.register(Tool("broken", "desc", broken_handler))

    result = registry.call(ToolCall(tool_name="broken", input={}), actor_role="ADMIN")

    assert result.success is False
    assert result.authorized is True  # got past authorization; the handler itself failed
    assert "boom" in result.error


def test_get_event_by_id_returns_correct_evidence_id() -> None:
    registry = build_test_registry({"events": [{"id": "evt-42", "username": "alice"}]})
    result = registry.call(ToolCall(tool_name="get_event_by_id", input={"event_id": "evt-42"}), actor_role="ADMIN")

    assert result.success is True
    assert result.evidence_ids == ["evt-42"]
    assert result.output["found"] is True


def test_get_event_by_id_not_found() -> None:
    registry = build_test_registry({"events": []})
    result = registry.call(ToolCall(tool_name="get_event_by_id", input={"event_id": "nope"}), actor_role="ADMIN")

    assert result.success is True  # the call itself succeeded — it just found nothing
    assert result.output["found"] is False
    assert result.evidence_ids == []


if __name__ == "__main__":
    test_registering_duplicate_tool_name_raises()
    test_unknown_tool_call_returns_unauthorized_error_not_raise()
    test_authorized_role_can_call_read_only_tool()
    test_viewer_role_cannot_call_ai_copilot_tools()
    test_simulate_tools_require_incidents_write_not_just_ai_copilot_use()
    test_viewer_cannot_propose_simulate_actions()
    test_tool_handler_exception_becomes_failed_result_not_raised()
    test_get_event_by_id_returns_correct_evidence_id()
    test_get_event_by_id_not_found()
    print("All tool registry tests passed.")
