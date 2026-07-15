"""Rule-first intent detection for safe, structured server operations."""

from __future__ import annotations

import re
from dataclasses import dataclass


SAFE_OPERATIONS = (
    "inventory",
    "select_server",
    "health",
    "processes",
    "paper_progress",
    "java_status",
    "service_status",
    "service_logs",
)

SERVICE_ALIASES = {
    "nginx": "nginx",
    "docker": "docker",
    "docker服务": "docker",
}


@dataclass(frozen=True)
class OperationIntent:
    operation: str
    server_id: str
    assumed_server: bool = False
    target: str | None = None
    detail: str = "summary"


def _server_from_text(value: str, default_server_id: str | None) -> tuple[str, bool]:
    if any(word in value for word in ("阿里云", "服务器2", "云服务器2")):
        return "server2", False
    if any(word in value for word in ("ai服务器", "gpu服务器", "论文服务器", "服务器1")):
        return "server1", False
    return default_server_id or "server1", True


def _service_from_text(value: str) -> str | None:
    for alias, service in SERVICE_ALIASES.items():
        if alias in value:
            return service
    return None


def detect_intent(message: str, default_server_id: str | None = None) -> OperationIntent | None:
    value = re.sub(r"\s+", "", message or "").lower()
    if not value:
        return None

    server_id, assumed = _server_from_text(value, default_server_id)

    inventory_phrases = (
        "有哪些服务器", "有什么服务器", "哪些服务器", "服务器列表", "可用服务器",
        "我的服务器", "可访问服务器", "能操作的服务器", "可以操作的服务器",
        "服务器可以操作", "服务器能操作",
    )
    if any(phrase in value for phrase in inventory_phrases):
        return OperationIntent("inventory", server_id, assumed)

    if not assumed and any(word in value for word in ("切换", "选择", "连接", "使用", "设为默认")):
        return OperationIntent("select_server", server_id, False)

    if "java" in value and any(word in value for word in ("进程", "运行", "状态", "异常", "服务", "正常")):
        return OperationIntent("java_status", server_id, assumed, target="java")

    service = _service_from_text(value)
    if service and any(word in value for word in ("日志", "报错", "错误记录")):
        return OperationIntent("service_logs", server_id, assumed, target=service)
    if service and any(word in value for word in ("状态", "运行", "正常", "异常", "是否启动", "在不在")):
        return OperationIntent("service_status", server_id, assumed, target=service)

    if any(word in value for word in ("论文", "训练", "实验", "gpu", "显卡", "epoch", "loss", "step", "进展")):
        return OperationIntent("paper_progress", server_id, assumed)

    if any(word in value for word in ("进程", "任务", "运行什么", "运行哪些")):
        if any(word in value for word in ("几个", "多少", "数量", "总数")):
            detail = "count"
        elif any(word in value for word in ("详细", "列表", "哪些", "什么")):
            detail = "detail"
        else:
            detail = "summary"
        return OperationIntent("processes", server_id, assumed, detail=detail)

    if any(word in value for word in ("cpu", "内存", "负载", "磁盘", "健康", "资源", "系统状态")):
        return OperationIntent("health", server_id, assumed)

    return None


def llm_planner_prompt(message: str, visible_servers: list[str], context_summary: str = "") -> str:
    """Fallback contract; excludes credentials, command strings and command output."""
    return (
        "你是 AISSHBot 的受限意图规划器。只能选择 operation、server_id、target 和 detail，"
        "绝不输出 shell 命令、路径、账号、密码或执行步骤。\n"
        f"允许操作：{list(SAFE_OPERATIONS)}；允许服务器：{visible_servers}。\n"
        "target 只允许 nginx、docker 或 null；detail 只允许 count、summary、detail。\n"
        f"本地会话上下文：{context_summary or '无'}。\n"
        "只输出 JSON：{\"operation\":\"...\",\"server_id\":\"...\","
        "\"target\":null,\"detail\":\"summary\",\"confidence\":0.0}。\n"
        f"用户消息：{message!r}"
    )
