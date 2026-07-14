"""Safe, rule-first operation planner.

The fallback is dependency-injected so the gateway stays independent from a
specific LLM framework. A fallback may only return an operation and asset ID.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .intent import OperationIntent, SAFE_OPERATIONS, detect_intent


@dataclass(frozen=True)
class OperationPlan:
    intent: OperationIntent | None
    source: str
    confidence: float


async def plan_operation(
    message: str,
    visible_servers: list[str],
    fallback: Callable[[str, list[str]], OperationIntent | None | Awaitable[OperationIntent | None]] | None = None,
) -> OperationPlan:
    """Plan known requests locally; call an LLM fallback only for unknown ones."""
    rule = detect_intent(message)
    if rule is not None:
        return OperationPlan(rule, "rule", 0.95)
    if fallback is None:
        return OperationPlan(None, "unknown", 0.0)
    candidate = fallback(message, visible_servers)
    if inspect.isawaitable(candidate):
        candidate = await candidate
    if candidate is None or candidate.operation not in SAFE_OPERATIONS:
        return OperationPlan(None, "unknown", 0.0)
    if candidate.server_id not in visible_servers:
        return OperationPlan(None, "unknown", 0.0)
    return OperationPlan(candidate, "llm_fallback", 0.5)
