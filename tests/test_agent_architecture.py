import asyncio

import pytest

from aisshbot.agent.orchestrator import Orchestrator
from aisshbot.agent.planner import PlanFormatError, legacy_intent_to_plan, tool_plan_from_payload
from aisshbot.agent.schemas import ExecutionContext, ObjectRef, PlannedStep, ToolResult
from aisshbot.agent.evidence import EvidenceEvaluator
from aisshbot.agent.runtime import AgentRuntime
from aisshbot.audit.recorder import AuditEvent, InMemoryAuditRecorder, digest
from aisshbot.compatibility.legacy_tools import LegacyToolAdapter
from aisshbot.conversation.session_store import SessionKey, SessionStore
from aisshbot.intent import OperationIntent
from aisshbot.security.policy_engine import PolicyEngine, PolicyViolation
from aisshbot.tools.registry import ToolDefinition, ToolRegistry, build_default_registry


def context(**overrides):
    values = dict(
        request_id="req-1",
        principal_id="alice",
        channel="openclaw-weixin",
        conversation_id="conv-1",
        server_id="server1",
        roles=frozenset({"viewer"}),
        path_scopes=("/home/uav",),
        allowed_server_ids=frozenset({"server1"}),
    )
    values.update(overrides)
    return ExecutionContext(**values)


def test_training_pid_becomes_a_multi_step_structured_plan():
    plan = legacy_intent_to_plan(
        OperationIntent("process_training", "server1", target="258292", target_type="pid"),
        "alice",
        goal="查看 PID 258292 的训练效果",
    )
    assert [step.tool for step in plan.steps] == [
        "process.inspect",
        "training.resolve_by_process",
        "training.inspect",
        "training.list_artifacts",
    ]
    assert plan.steps[2].args["run_ref"] == "$training.resolve.run_ref"
    assert plan.object_ref == ObjectRef("pid", "258292", "server1", owner_id="alice")


def test_policy_rejects_unknown_tool_sudo_and_path_escape():
    registry = build_default_registry()
    policy = PolicyEngine(registry)
    with pytest.raises(PolicyViolation):
        policy.check_step(
            # A registered tool must still reject a sudo-like parameter.
            PlannedStep("shell.readonly", {"command": "sudo cat /etc/shadow"}),
            context(),
        )
    with pytest.raises(PolicyViolation):
        policy.check_path("/home/uav/../etc/shadow", context(), "project_read_roots")
    with pytest.raises(PolicyViolation):
        policy.check_step(
            PlannedStep("unknown.tool"),
            context(),
        )


def test_orchestrator_enforces_budget_and_resolves_step_references():
    registry = ToolRegistry()

    def resolve(call, _context):
        return ToolResult(call.tool, "SUCCESS", {"run_ref": "run-42"})

    def inspect(call, _context):
        return ToolResult(call.tool, "SUCCESS", {"received": call.args["run_ref"]})

    registry.register(ToolDefinition("training.resolve", handler=resolve))
    registry.register(ToolDefinition("training.inspect", handler=inspect))
    plan = legacy_intent_to_plan(
        OperationIntent("training_overview", "server1", target="/home/uav/run", target_type="path"),
        "alice",
    )
    # Replace the unbound names from the compatibility plan with test handlers.
    registry.register(ToolDefinition("training.resolve_by_path", handler=resolve))
    plan = plan.__class__(
        **{**plan.__dict__, "max_steps": 2},
    )
    results = asyncio.run(Orchestrator(registry).run(plan, context()))
    assert [result.status for result in results] == ["SUCCESS", "SUCCESS"]
    assert results[1].data["received"] == "run-42"


def test_session_store_isolated_by_principal_channel_and_conversation():
    store = SessionStore(ttl_seconds=60)
    first = SessionKey("alice", "openclaw-weixin", "conversation-a")
    second = SessionKey("bob", "openclaw-weixin", "conversation-a")
    state = store.get(first)
    state.active_server_id = "server1"
    state.active_training_run_ref = ObjectRef("training_run", "run-1", "server1", owner_id="alice")
    store.update(first, state)
    assert store.get(first).active_server_id == "server1"
    assert store.get(second).active_server_id is None


def test_audit_stores_hashes_not_raw_result():
    recorder = InMemoryAuditRecorder()
    raw = "token=secret-value"
    event = AuditEvent(
        "req-1", "alice", "server1", "tool_result", "SUCCESS",
        tool="system.health", result_hash=digest(raw),
    )
    recorder.record(event)
    stored = recorder.list("req-1")[0]
    assert stored.result_hash == digest(raw)
    assert raw not in str(stored)


def test_evidence_evaluator_requires_successful_requested_tools():
    evaluator = EvidenceEvaluator()
    results = (ToolResult("process.inspect", "SUCCESS", {"pid": "1"}),)
    assert evaluator.sufficient(results, ("process.inspect",)) is True
    assert evaluator.sufficient(results, ("training.inspect",)) is False


def test_agent_runtime_turns_policy_rejection_into_audited_answer():
    registry = build_default_registry()
    runtime = AgentRuntime(registry)
    plan = legacy_intent_to_plan(
        OperationIntent("health", "server2"),
        "alice",
        goal="查看未授权服务器",
    )
    result = asyncio.run(runtime.run(plan, context()))
    assert result.status == "DENIED"
    assert "服务器" in result.answer
    assert runtime.audit.list(result.plan.request_id)[-1].status == "DENIED"


def test_legacy_adapter_binds_only_proven_readonly_tools():
    registry = build_default_registry()
    LegacyToolAdapter().bind(registry)
    assert registry.require("system.health").handler is not None
    assert registry.require("file.read_text").handler is not None
    # Native multi-step training handlers must not be faked by the legacy bridge.
    assert registry.require("training.inspect").handler is None


def test_llm_tool_plan_payload_is_structured_but_still_requires_policy():
    plan = tool_plan_from_payload(
        {
            "server_id": "server1",
            "object": {"type": "process", "id": "258292"},
            "steps": [{"tool": "process.inspect", "args": {"pid": "258292"}}],
            "response_focus": ["status"],
            "confidence": 0.88,
        },
        "alice",
        {"server1"},
        "查看 PID 258292",
    )
    assert plan.source == "llm_proposal"
    assert plan.object_ref.owner_id == "alice"
    with pytest.raises(PlanFormatError):
        tool_plan_from_payload(
            {"server_id": "server2", "steps": [{"tool": "process.inspect"}]},
            "alice", {"server1"}, "越权服务器",
        )
