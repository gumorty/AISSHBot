import asyncio

from aisshbot.access_control import Principal
from aisshbot.compatibility.agent_runtime import (
    AGENT_BRIDGED_OPERATIONS,
    LangBotAgentBridge,
)
from aisshbot.intent import OperationIntent


def test_bridge_only_claims_operations_with_bound_handlers():
    bridge = LangBotAgentBridge()
    assert "health" in AGENT_BRIDGED_OPERATIONS
    assert "training_overview" not in AGENT_BRIDGED_OPERATIONS
    assert bridge.runtime.registry.require("system.health").handler is not None


def test_bridge_fails_closed_for_unmapped_training_operation():
    principal = Principal("alice", "Alice", {"server1": {"operations": ["training_overview"]}})
    result = asyncio.run(
        LangBotAgentBridge().run(
            OperationIntent("training_overview", "server1"),
            principal,
            ["server1"],
            channel="test",
            conversation_id="conv-1",
            goal="查看训练情况",
        )
    )
    assert result is None
