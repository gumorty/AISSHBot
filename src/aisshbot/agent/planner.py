"""Translate legacy intents into validated, multi-step ToolPlans."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from ..intent import OperationIntent, detect_intent
from .schemas import ObjectRef, PlannedStep, ToolPlan


class PlanFormatError(ValueError):
    pass


LEGACY_TO_TOOL = {
    "health": "system.health",
    "processes": "process.list",
    "process_detail": "process.inspect",
    "gpu_overview": "gpu.overview",
    "gpu_processes": "gpu.processes",
    "java_status": "process.list",
    "java_log_sources": "service.logs",
    "middleware_overview": "service.status",
    "service_status": "service.status",
    "service_logs": "service.logs",
    "service_errors": "service.errors",
    "file_list": "file.list",
    "file_preview": "file.read_text",
    "path_inspect": "file.inspect_path",
}


def _object_ref(intent: OperationIntent, principal_id: str) -> ObjectRef | None:
    if not intent.target:
        return None
    object_type = intent.target_type or "target"
    return ObjectRef(object_type, intent.target, intent.server_id, owner_id=principal_id)


def legacy_intent_to_plan(
    intent: OperationIntent,
    principal_id: str,
    goal: str = "服务器只读查询",
    request_id: str | None = None,
) -> ToolPlan:
    """Compatibility adapter; legacy routes become normal structured plans."""
    request_id = request_id or uuid4().hex
    target = intent.target
    steps: list[PlannedStep] = []
    focus: tuple[str, ...] = (intent.detail,)

    if intent.operation == "process_training" and target:
        steps = [
            PlannedStep("process.inspect", {"pid": target}, "process.inspect"),
            PlannedStep("training.resolve_by_process", {"pid": target}, "training.resolve", ("process.inspect",)),
            PlannedStep("training.inspect", {"run_ref": "$training.resolve.run_ref"}, "training.inspect", ("training.resolve",)),
            PlannedStep("training.list_artifacts", {"run_ref": "$training.resolve.run_ref"}, "training.artifacts", ("training.resolve",)),
        ]
        focus = ("status", "progress", "latest_metrics", "best_metrics", "artifacts")
    elif intent.operation == "training_overview":
        if target:
            steps = [
                PlannedStep("training.resolve_by_path", {"path": target}, "training.resolve"),
                PlannedStep("training.inspect", {"run_ref": "$training.resolve.run_ref"}, "training.inspect", ("training.resolve",)),
            ]
        else:
            steps = [
                PlannedStep("training.resolve_by_process", {"scope": "active_gpu"}, "training.resolve"),
                PlannedStep("training.inspect", {"run_ref": "$training.resolve.run_ref"}, "training.inspect", ("training.resolve",)),
            ]
        focus = (intent.detail, "status", "progress", "latest_metrics", "trend")
    else:
        tool = LEGACY_TO_TOOL.get(intent.operation)
        if tool is None:
            raise ValueError(f"没有结构化工具映射：{intent.operation}")
        args = {}
        if target:
            key = "pid" if intent.target_type == "pid" else "path" if intent.target_type == "path" else "service"
            args[key] = target
        steps = [PlannedStep(tool, args, intent.operation)]

    return ToolPlan(
        request_id=request_id,
        principal_id=principal_id,
        server_id=intent.server_id,
        goal=goal,
        object_ref=_object_ref(intent, principal_id),
        steps=tuple(steps),
        response_focus=focus,
        confidence=0.95,
        source="legacy_adapter",
    )


def tool_plan_from_payload(
    payload: dict,
    principal_id: str,
    allowed_server_ids: set[str],
    goal: str,
    request_id: str | None = None,
) -> ToolPlan:
    """Parse an LLM proposal without trusting it as an execution decision."""
    if not isinstance(payload, dict):
        raise PlanFormatError("ToolPlan 必须是 JSON 对象")
    server_id = str(payload.get("server_id", ""))
    if not server_id or server_id not in allowed_server_ids:
        raise PlanFormatError("ToolPlan 服务器不在授权范围内")
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise PlanFormatError("ToolPlan 缺少 steps")
    steps: list[PlannedStep] = []
    for index, raw_step in enumerate(raw_steps, 1):
        if not isinstance(raw_step, dict) or not isinstance(raw_step.get("tool"), str):
            raise PlanFormatError("ToolPlan 步骤格式非法")
        args = raw_step.get("args", {})
        if not isinstance(args, dict):
            raise PlanFormatError("工具参数必须是对象")
        depends_on = raw_step.get("depends_on", ())
        if isinstance(depends_on, str):
            depends_on = (depends_on,)
        if not isinstance(depends_on, (list, tuple)):
            raise PlanFormatError("依赖步骤格式非法")
        steps.append(PlannedStep(
            raw_step["tool"],
            args,
            str(raw_step.get("step_id") or f"step-{index}"),
            tuple(str(item) for item in depends_on),
        ))
    object_payload = payload.get("object")
    object_ref = None
    if object_payload is not None:
        if not isinstance(object_payload, dict) or not object_payload.get("type") or not object_payload.get("id"):
            raise PlanFormatError("对象引用格式非法")
        object_ref = ObjectRef(
            str(object_payload["type"]),
            str(object_payload["id"]),
            server_id,
            owner_id=principal_id,
            source="llm_proposal",
        )
    focus = payload.get("response_focus", ())
    if isinstance(focus, str):
        focus = (focus,)
    if not isinstance(focus, (list, tuple)):
        raise PlanFormatError("response_focus 格式非法")
    return ToolPlan(
        request_id=request_id or uuid4().hex,
        principal_id=principal_id,
        server_id=server_id,
        goal=goal,
        object_ref=object_ref,
        steps=tuple(steps),
        response_focus=tuple(str(item) for item in focus),
        max_steps=int(payload.get("max_steps", 6)),
        max_tool_calls=int(payload.get("max_tool_calls", 12)),
        confidence=float(payload.get("confidence", 0.0)),
        source="llm_proposal",
    )


@dataclass
class StructuredPlanner:
    """Rule-first planner facade; an LLM planner can be injected later."""

    def plan(self, message: str, principal_id: str, default_server_id: str | None = None) -> ToolPlan | None:
        intent = detect_intent(message, default_server_id=default_server_id)
        if intent is None or intent.operation in {"inventory", "select_server"}:
            return None
        return legacy_intent_to_plan(intent, principal_id, goal=message)
