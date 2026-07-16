"""Rule-first planner with a tightly constrained LLM fallback."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable

from .intent import OperationIntent, detect_intent, llm_planner_prompt
from .memory import SessionContext


@dataclass(frozen=True)
class OperationPlan:
    intent: OperationIntent | None
    source: str
    confidence: float


def _parse_json(content: str) -> dict | None:
    match = re.search(r"\{.*\}", content or "", re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _context_summary(context: SessionContext | None) -> str:
    if context is None:
        return ""
    parts = []
    if context.last_server_id:
        parts.append(f"上次服务器={context.last_server_id}")
    if context.last_operation:
        parts.append(f"上次操作={context.last_operation}")
    if context.last_target:
        parts.append(f"上次目标={context.last_target}")
    if context.last_pid:
        parts.append(f"上次PID={context.last_pid}")
    if context.last_path:
        parts.append(f"上次路径={context.last_path}")
    if context.last_training_run:
        parts.append(f"上次训练实验={context.last_training_run}")
    if context.last_artifact:
        parts.append(f"上次文件={context.last_artifact}")
    if context.last_service:
        parts.append(f"上次服务={context.last_service}")
    for turn in context.turns[-2:]:
        question = re.sub(r"\s+", " ", turn.question).strip()[:96]
        if question:
            parts.append(f"最近请求={question}（{turn.operation}@{turn.server_id}）")
    return "；".join(parts)


async def _llm_plan(
    ap,
    query,
    message: str,
    allowed_servers: Iterable[str],
    context: SessionContext | None,
) -> OperationPlan | None:
    if ap is None or query is None or not getattr(query, "use_llm_model_uuid", None):
        return None

    from langbot_plugin.api.entities.builtin.provider import message as provider_message

    allowed = list(allowed_servers)
    model = await ap.model_mgr.get_model_by_uuid(query.use_llm_model_uuid)
    if model is None:
        return None
    prompt = llm_planner_prompt(message, allowed, _context_summary(context))
    extra_args = dict(model.model_entity.extra_args or {})
    extra_args.update({"temperature": 0.0, "max_tokens": 180, "enable_thinking": False})
    response = await model.requester.invoke_llm(
        query,
        model,
        [
            provider_message.Message(role="system", content="只返回合法 JSON，不解释。"),
            provider_message.Message(role="user", content=prompt),
        ],
        [],
        extra_args=extra_args,
        remove_think=True,
    )
    payload = _parse_json(response.content if isinstance(response.content, str) else "")
    if not payload:
        return None

    operation = str(payload.get("operation", "unknown"))
    server_id = str(payload.get("server_id", "unknown"))
    target = payload.get("target")
    detail = str(payload.get("detail", "summary"))
    try:
        confidence = float(payload.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    fallback_operations = {
        "inventory", "select_server", "health", "processes", "gpu_overview",
        "training_overview", "java_status", "middleware_overview",
    }
    if operation not in fallback_operations or server_id not in allowed or confidence < 0.6:
        return None
    if target is not None:
        return None
    if detail not in ("count", "summary", "detail"):
        detail = "summary"
    return OperationPlan(
        OperationIntent(operation, server_id, False, target=target, detail=detail),
        "llm_fallback",
        confidence,
    )


async def plan_operation(
    ap,
    query,
    message: str,
    allowed_servers: Iterable[str],
    context: SessionContext | None = None,
) -> OperationPlan:
    """Route known requests locally; use the LLM only when rules cannot decide."""
    allowed = list(allowed_servers)
    default_server = context.last_server_id if context else None
    rule = detect_intent(message, default_server_id=default_server)
    if rule is not None:
        return OperationPlan(rule, "rule", 0.95)
    try:
        fallback = await _llm_plan(ap, query, message, allowed, context)
        if fallback is not None:
            return fallback
    except Exception:
        pass
    return OperationPlan(None, "unknown", 0.0)
