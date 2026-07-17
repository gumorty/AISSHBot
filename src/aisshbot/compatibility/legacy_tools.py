"""Optional bridge from structured tools to the existing read-only gateway.

This adapter is intentionally narrow. It lets the new planner reuse proven
read-only operations during migration, while native domain tools are built.
It never exposes the old free-form command interface to the Agent.
"""

from __future__ import annotations

from ..agent.schemas import ExecutionContext, ToolCall, ToolResult
from ..intent import OperationIntent
from ..ops_gateway import execute_readonly
from ..tools.registry import ToolRegistry


LEGACY_TOOL_OPERATIONS = {
    "system.health": "health",
    "process.list": "processes",
    "process.inspect": "process_detail",
    "gpu.overview": "gpu_overview",
    "gpu.processes": "gpu_processes",
    "service.status": "service_status",
    "service.logs": "service_logs",
    "service.errors": "service_errors",
    "file.inspect_path": "path_inspect",
    "file.list": "file_list",
    "file.read_text": "file_preview",
}


class LegacyToolAdapter:
    """Bind only existing safe operations to the new registry."""

    def bind(self, registry: ToolRegistry) -> None:
        for tool_name in LEGACY_TOOL_OPERATIONS:
            if registry.get(tool_name) is not None:
                registry.with_handler(tool_name, self.handle)

    async def handle(self, call: ToolCall, context: ExecutionContext) -> ToolResult:
        operation = LEGACY_TOOL_OPERATIONS[call.tool]
        args = call.args
        target = args.get("pid") or args.get("path") or args.get("service")
        target_type = "pid" if "pid" in args else "path" if "path" in args else "service" if "service" in args else None
        intent = OperationIntent(
            operation=operation,
            server_id=call.server_id,
            assumed_server=False,
            target=str(target) if target is not None else None,
            detail=str(args.get("detail", "summary")),
            target_type=target_type,
        )
        try:
            text = await execute_readonly(
                intent,
                actor_id=context.principal_id,
                visible_server_ids=sorted(context.allowed_server_ids or {context.server_id}),
            )
        except Exception as exc:
            return ToolResult(call.tool, "ERROR", error=str(exc)[:300])
        return ToolResult(
            call.tool,
            "SUCCESS",
            data={"text": text},
            evidence=(f"legacy:{operation}",),
        )
