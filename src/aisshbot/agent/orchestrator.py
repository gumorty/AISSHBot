"""Budgeted structured tool orchestration with explicit context."""

from __future__ import annotations

import inspect
from typing import Any

from ..security.policy_engine import PolicyEngine, PolicyViolation
from ..tools.registry import ToolRegistry
from .budgets import BudgetExceeded, ExecutionBudget
from .evidence import EvidenceLedger
from .schemas import ExecutionContext, PlannedStep, ToolCall, ToolPlan, ToolResult


class Orchestrator:
    def __init__(self, registry: ToolRegistry, policy: PolicyEngine | None = None):
        self.registry = registry
        self.policy = policy or PolicyEngine(registry)

    async def run(self, plan: ToolPlan, context: ExecutionContext) -> tuple[ToolResult, ...]:
        decision = self.policy.check_plan(plan, context)
        if not decision.allowed:
            raise PolicyViolation(decision.reason)
        budget = ExecutionBudget(min(plan.max_steps, self.policy.max_steps), min(plan.max_tool_calls, self.policy.max_tool_calls))
        results: list[ToolResult] = []
        outputs: dict[str, dict[str, Any]] = {}
        for index, step in enumerate(plan.steps, 1):
            budget.consume()
            self.policy.check_step(step, context, plan.server_id)
            definition = self.registry.require(step.tool)
            if definition.handler is None:
                result = ToolResult(step.tool, "ERROR", error="工具尚未绑定执行处理器")
            else:
                args = _resolve_refs(step.args, outputs)
                call = ToolCall(plan.request_id, step.step_id or f"step-{index}", step.tool, args, plan.server_id)
                try:
                    result = definition.handler(call, context)
                    if inspect.isawaitable(result):
                        result = await result
                except Exception as exc:  # handlers are isolated at this boundary
                    result = ToolResult(step.tool, "ERROR", error=str(exc)[:300])
            results.append(result)
            outputs[step.step_id or f"step-{index}"] = result.data
            if not result.ok:
                break
        return tuple(results)


def _resolve_refs(value: Any, outputs: dict[str, dict[str, Any]]) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        expression = value[1:]
        # Step IDs use domain.action names, so split at the final separator:
        # ``$training.resolve.run_ref`` -> (``training.resolve``, ``run_ref``).
        step_id, _, key = expression.rpartition(".")
        return outputs.get(step_id, {}).get(key, value)
    if isinstance(value, dict):
        return {key: _resolve_refs(item, outputs) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_refs(item, outputs) for item in value]
    return value
