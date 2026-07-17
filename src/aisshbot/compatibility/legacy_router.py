"""Bridge existing OperationIntent routes into the new ToolPlan contract."""

from __future__ import annotations

from ..agent.planner import legacy_intent_to_plan
from ..intent import detect_intent


def legacy_plan(message: str, principal_id: str, default_server_id: str | None = None):
    intent = detect_intent(message, default_server_id=default_server_id)
    if intent is None:
        return None
    return legacy_intent_to_plan(intent, principal_id, goal=message)
