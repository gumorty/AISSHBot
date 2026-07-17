"""Tool registry: the model can only see tools registered here."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable

from ..agent.schemas import ExecutionContext, ToolCall, ToolResult


ToolHandler = Callable[[ToolCall, ExecutionContext], ToolResult]


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    version: int = 1
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    risk: str = "R0_READ_ONLY"
    read_only: bool = True
    allowed_roles: frozenset[str] = frozenset({"viewer", "operator", "admin"})
    path_policy: str | None = None
    timeout_seconds: int = 8
    max_output_bytes: int = 262_144
    audit_level: str = "FULL"
    requires_confirmation: bool = False
    handler: ToolHandler | None = None

    def visible_to(self, roles: Iterable[str]) -> bool:
        return bool(self.allowed_roles.intersection(set(roles)))


class ToolRegistry:
    def __init__(self, definitions: Iterable[ToolDefinition] = ()):
        self._tools: dict[str, ToolDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ToolDefinition) -> None:
        if not definition.name or "." not in definition.name:
            raise ValueError("工具名称必须使用 domain.action 格式")
        if definition.name in self._tools:
            raise ValueError(f"工具已注册：{definition.name}")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def require(self, name: str) -> ToolDefinition:
        definition = self.get(name)
        if definition is None:
            raise KeyError(f"未注册工具：{name}")
        return definition

    def visible(self, roles: Iterable[str]) -> tuple[ToolDefinition, ...]:
        return tuple(tool for tool in self._tools.values() if tool.visible_to(roles))

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def with_handler(self, name: str, handler: ToolHandler) -> None:
        self._tools[name] = replace(self.require(name), handler=handler)


_READ_ONLY_TOOLS = (
    ("system.health", "R0_READ_ONLY", None, 8),
    ("system.disk_usage", "R0_READ_ONLY", None, 8),
    ("system.network_summary", "R0_READ_ONLY", None, 8),
    ("gpu.overview", "R0_READ_ONLY", None, 8),
    ("gpu.processes", "R0_READ_ONLY", None, 8),
    ("process.list", "R0_READ_ONLY", None, 8),
    ("process.inspect", "R0_READ_ONLY", None, 8),
    ("process.tree", "R0_READ_ONLY", None, 8),
    ("training.resolve_by_process", "R0_READ_ONLY", "project_read_roots", 15),
    ("training.resolve_by_path", "R0_READ_ONLY", "project_read_roots", 15),
    ("training.inspect", "R0_READ_ONLY", "project_read_roots", 15),
    ("training.metrics", "R0_READ_ONLY", "project_read_roots", 15),
    ("training.trend", "R0_READ_ONLY", "project_read_roots", 15),
    ("training.list_artifacts", "R1_READ_ONLY_SENSITIVE", "project_read_roots", 15),
    ("training.render_curve", "R1_READ_ONLY_SENSITIVE", "project_read_roots", 20),
    ("service.status", "R0_READ_ONLY", None, 8),
    ("service.logs", "R1_READ_ONLY_SENSITIVE", "service_log_roots", 12),
    ("service.errors", "R1_READ_ONLY_SENSITIVE", "service_log_roots", 12),
    ("file.inspect_path", "R0_READ_ONLY", "project_read_roots", 8),
    ("file.list", "R0_READ_ONLY", "project_read_roots", 8),
    ("file.read_text", "R1_READ_ONLY_SENSITIVE", "project_read_roots", 8),
    ("file.download", "R1_READ_ONLY_SENSITIVE", "download_roots", 20),
    ("shell.readonly", "R1_READ_ONLY_SENSITIVE", "project_read_roots", 8),
)


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for name, risk, path_policy, timeout in _READ_ONLY_TOOLS:
        registry.register(
            ToolDefinition(
                name=name,
                risk=risk,
                path_policy=path_policy,
                timeout_seconds=timeout,
                read_only=True,
                requires_confirmation=False,
            )
        )
    return registry
