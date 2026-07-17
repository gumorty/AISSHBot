"""Plan and call validation; this is the execution safety boundary."""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from ..agent.schemas import ExecutionContext, PlannedStep, ToolCall, ToolPlan
from ..tools.registry import ToolDefinition, ToolRegistry


class PolicyViolation(ValueError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str = "allowed"
    requires_confirmation: bool = False
    risk: str = "R0_READ_ONLY"


_DENIED_TOKENS = re.compile(r"(?i)(?:^|[^a-z])(sudo|su|doas|pkexec)(?:$|[^a-z])")
_PID_RE = re.compile(r"^[1-9]\d{0,8}$")
_DENIED_PATH_PARTS = {
    ".ssh", ".env", ".env.local", "id_rsa", "id_ed25519", "authorized_keys",
}
_DENIED_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/etc/shadow")


class PolicyEngine:
    def __init__(self, registry: ToolRegistry, max_steps: int = 6, max_tool_calls: int = 12):
        self.registry = registry
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls

    def check_plan(self, plan: ToolPlan, context: ExecutionContext) -> PolicyDecision:
        if plan.principal_id != context.principal_id:
            return PolicyDecision(False, "计划主体与当前会话不一致")
        if plan.server_id != context.server_id:
            return PolicyDecision(False, "计划服务器与当前会话不一致")
        if context.allowed_server_ids and plan.server_id not in context.allowed_server_ids:
            return PolicyDecision(False, "服务器不在主体授权范围内")
        if not plan.steps:
            return PolicyDecision(False, "计划没有工具步骤")
        if len(plan.steps) > min(plan.max_steps, self.max_steps):
            return PolicyDecision(False, "计划步骤超过预算")
        if len(plan.steps) > self.max_tool_calls:
            return PolicyDecision(False, "工具调用超过预算")
        for step in plan.steps:
            self.check_step(step, context, plan.server_id)
        return PolicyDecision(True)

    def check_step(self, step: PlannedStep, context: ExecutionContext, server_id: str | None = None) -> PolicyDecision:
        definition = self.registry.get(step.tool)
        if definition is None:
            raise PolicyViolation(f"拒绝未注册工具：{step.tool}")
        if not definition.visible_to(context.roles):
            raise PolicyViolation(f"角色不能使用工具：{step.tool}")
        if server_id and server_id != context.server_id:
            raise PolicyViolation("工具调用服务器越权")
        if not definition.read_only:
            raise PolicyViolation("当前版本只允许注册为只读的 Agent 工具")
        serialized = json.dumps(step.args, ensure_ascii=False)
        if _DENIED_TOKENS.search(serialized):
            raise PolicyViolation("工具参数包含禁止的提权指令")
        self._check_args(step.args, context, definition)
        return PolicyDecision(True, risk=definition.risk)

    def _check_args(self, args: dict[str, Any], context: ExecutionContext, definition: ToolDefinition) -> None:
        for key, value in args.items():
            if key.lower() in {"pid", "process_id"} and value is not None:
                if not _PID_RE.fullmatch(str(value)):
                    raise PolicyViolation("PID 参数非法")
            if isinstance(value, str) and ("path" in key.lower() or key.lower() in {"run_dir", "work_dir", "cwd"}):
                self.check_path(value, context, definition.path_policy)

    def check_path(self, path: str, context: ExecutionContext, policy_name: str | None = None) -> str:
        if not path or "\x00" in path:
            raise PolicyViolation("路径为空或包含非法字符")
        # Server paths are POSIX paths even when the planner is tested or
        # hosted on Windows.
        normalized = posixpath.normpath(path)
        pure = PurePosixPath(normalized)
        if any(part in _DENIED_PATH_PARTS for part in pure.parts):
            raise PolicyViolation("敏感路径被拒绝")
        if any(normalized == prefix or normalized.startswith(prefix + "/") for prefix in _DENIED_PREFIXES):
            raise PolicyViolation("系统敏感目录被拒绝")
        if context.path_scopes:
            if not any(normalized == root or normalized.startswith(root.rstrip("/") + "/") for root in context.path_scopes):
                raise PolicyViolation("路径不在当前主体授权范围内")
        return normalized
