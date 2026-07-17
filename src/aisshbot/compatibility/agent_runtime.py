"""Bridge the LangBot handler to the structured Agent runtime.

The bridge deliberately covers only legacy operations whose structured tools
already have a proven read-only handler. Unsupported domain operations return
``None`` so the existing compatibility path can answer them without risking a
partial migration. No shell text or credentials cross this boundary.
"""

from __future__ import annotations

from uuid import uuid4

from ..access_control import Principal
from ..agent.runtime import AgentRun, AgentRuntime
from ..agent.schemas import ExecutionContext
from ..agent.planner import legacy_intent_to_plan
from ..intent import OperationIntent
from ..ops_gateway import _server_config
from ..tools.registry import build_default_registry
from .legacy_tools import LegacyToolAdapter


# These operations map one-to-one to an existing structured tool and retain
# the old gateway's bounded formatter. Training, Java and middleware domain
# queries stay on the compatibility path until native domain handlers exist.
AGENT_BRIDGED_OPERATIONS = frozenset(
    {
        "health",
        "processes",
        "process_detail",
        "gpu_overview",
        "gpu_processes",
        "service_status",
        "service_logs",
        "service_errors",
        "path_inspect",
        "file_list",
        "file_preview",
    }
)


class LangBotAgentBridge:
    """Run a validated structured plan for a single LangBot request."""

    def __init__(self) -> None:
        registry = build_default_registry()
        LegacyToolAdapter().bind(registry)
        self.runtime = AgentRuntime(registry)

    async def run(
        self,
        intent: OperationIntent,
        principal: Principal,
        visible_server_ids: list[str],
        *,
        channel: str,
        conversation_id: str,
        goal: str,
    ) -> AgentRun | None:
        if intent.operation not in AGENT_BRIDGED_OPERATIONS:
            return None
        if intent.server_id not in visible_server_ids:
            return None

        plan = legacy_intent_to_plan(
            intent,
            principal_id=principal.user_id,
            goal=goal,
            request_id=uuid4().hex,
        )
        # Fail closed during migration: a plan with a native tool that has no
        # handler must use the old known-good compatibility path instead.
        if any(self.runtime.registry.require(step.tool).handler is None for step in plan.steps):
            return None

        config = _server_config(intent.server_id)
        read_roots = tuple(str(root) for root in config.get("read_roots", ()))
        context = ExecutionContext(
            request_id=plan.request_id,
            principal_id=principal.user_id,
            channel=channel,
            conversation_id=conversation_id,
            server_id=intent.server_id,
            roles=frozenset({"viewer"}),
            path_scopes=read_roots,
            allowed_server_ids=frozenset(visible_server_ids),
        )
        return await self.runtime.run(plan, context)


_BRIDGE: LangBotAgentBridge | None = None


def get_langbot_agent_bridge() -> LangBotAgentBridge:
    global _BRIDGE
    if _BRIDGE is None:
        _BRIDGE = LangBotAgentBridge()
    return _BRIDGE


async def execute_with_agent(
    intent: OperationIntent,
    principal: Principal,
    visible_server_ids: list[str],
    *,
    channel: str,
    conversation_id: str,
    goal: str,
) -> AgentRun | None:
    """Return an Agent result, or ``None`` to request legacy fallback."""

    return await get_langbot_agent_bridge().run(
        intent,
        principal,
        visible_server_ids,
        channel=channel,
        conversation_id=conversation_id,
        goal=goal,
    )
