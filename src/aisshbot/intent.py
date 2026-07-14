"""Rule-first intent detection; an LLM may only select this fixed operation set."""

from __future__ import annotations

import re
from dataclasses import dataclass


SAFE_OPERATIONS = ("inventory", "health", "processes", "paper_progress", "java_status")


@dataclass(frozen=True)
class OperationIntent:
    operation: str
    server_id: str
    assumed_server: bool = False


def detect_intent(message: str) -> OperationIntent | None:
    value = re.sub(r"\s+", "", message or "").lower()
    if not value:
        return None
    if any(word in value for word in ("阿里云", "服务器2", "云服务器2")):
        server_id, assumed = "server2", False
    elif any(word in value for word in ("ai服务器", "gpu服务器", "论文服务器", "服务器1")):
        server_id, assumed = "server1", False
    else:
        server_id, assumed = "server1", True
    if any(word in value for word in ("服务器列表", "有哪些服务器", "我的服务器", "可用服务器")):
        return OperationIntent("inventory", server_id, assumed)
    if "java" in value and any(word in value for word in ("进程", "运行", "状态", "异常", "服务")):
        return OperationIntent("java_status", server_id, assumed)
    if any(word in value for word in ("论文", "训练", "实验", "gpu", "显卡", "epoch", "loss", "step", "进展")):
        return OperationIntent("paper_progress", server_id, assumed)
    if any(word in value for word in ("进程", "任务", "运行什么", "运行哪些")):
        return OperationIntent("processes", server_id, assumed)
    if any(word in value for word in ("cpu", "内存", "负载", "磁盘", "健康", "资源", "状态")):
        return OperationIntent("health", server_id, assumed)
    return None


def llm_planner_prompt(message: str, visible_servers: list[str]) -> str:
    """Prompt contract for a fallback planner; it deliberately excludes shell and credentials."""
    return (
        "你是 AISSHBot 的受限意图规划器。只能选择 operation 与 server_id，绝不输出 shell 命令、"
        "路径、账号、密码或执行步骤。"
        f"允许操作：{list(SAFE_OPERATIONS)}；允许服务器：{visible_servers}。"
        "只输出 JSON：{\"operation\":\"...\",\"server_id\":\"...\",\"confidence\":0.0}。"
        f"用户消息：{message!r}"
    )
