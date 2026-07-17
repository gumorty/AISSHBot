"""Application service wiring the new Agent layers together."""

from __future__ import annotations

from dataclasses import dataclass

from ..audit.recorder import AuditEvent, InMemoryAuditRecorder, digest
from ..response.composer import ResponseComposer
from ..security.policy_engine import PolicyEngine, PolicyViolation
from ..tools.registry import ToolRegistry, build_default_registry
from .evidence import EvidenceLedger
from .orchestrator import Orchestrator
from .schemas import ExecutionContext, ToolPlan, ToolResult


@dataclass(frozen=True)
class AgentRun:
    plan: ToolPlan
    results: tuple[ToolResult, ...]
    answer: str
    status: str


class AgentRuntime:
    """A safe composition root for a new LangBot/API adapter."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        policy: PolicyEngine | None = None,
        audit: InMemoryAuditRecorder | None = None,
        composer: ResponseComposer | None = None,
    ):
        self.registry = registry or build_default_registry()
        self.policy = policy or PolicyEngine(self.registry)
        self.orchestrator = Orchestrator(self.registry, self.policy)
        self.audit = audit or InMemoryAuditRecorder()
        self.composer = composer or ResponseComposer()

    async def run(self, plan: ToolPlan, context: ExecutionContext) -> AgentRun:
        self.audit.record(AuditEvent(
            plan.request_id,
            context.principal_id,
            context.server_id,
            "plan",
            "RECEIVED",
            metadata={"source": plan.source, "step_count": len(plan.steps)},
        ))
        try:
            results = await self.orchestrator.run(plan, context)
        except PolicyViolation as exc:
            self.audit.record(AuditEvent(
                plan.request_id,
                context.principal_id,
                context.server_id,
                "policy",
                "DENIED",
                metadata={"reason": str(exc)[:200]},
            ))
            result = ToolResult("policy", "DENIED", error=str(exc)[:300])
            return AgentRun(plan, (result,), self.composer.compose((result,), plan.response_focus), "DENIED")

        ledger = EvidenceLedger()
        for result in results:
            ledger.add(result)
            self.audit.record(AuditEvent(
                plan.request_id,
                context.principal_id,
                context.server_id,
                "tool_result",
                result.status,
                tool=result.tool_name,
                result_hash=digest(result.data),
                metadata={"exit_code": result.exit_code},
            ))
        status = "SUCCESS" if results and all(result.ok for result in results) else "PARTIAL"
        answer = self.composer.compose(results, plan.response_focus)
        return AgentRun(plan, results, answer, status)
