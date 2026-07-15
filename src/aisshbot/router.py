"""Fast first-response routing for AISSHBot messages."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .intent import detect_intent


PROCESSING_ACK = "正在处理，请稍候。"

_SERVER_MARKERS = (
    "服务器", "主机", "ssh", "sftp", "命令", "文件", "上传", "下载", "目录", "路径",
    "部署", "发布", "回滚", "日志", "进程", "服务", "nginx", "docker", "容器",
    "重启", "端口", "cpu", "内存", "磁盘", "负载", "连接", "数据库", "gpu", "显卡",
    "训练", "论文", "实验", "java",
)
_GREETING_MARKERS = ("你好", "您好", "嗨", "hello", "hi", "在吗")
_IDENTITY_MARKERS = ("你是谁", "你能做什么", "有什么功能", "怎么使用", "帮助", "help")


@dataclass(frozen=True)
class RouteDecision:
    kind: str
    requires_processing_ack: bool = False


def extract_text(message_chain) -> str:
    parts: list[str] = []
    for component in message_chain or []:
        text = getattr(component, "text", None)
        if text:
            parts.append(str(text))
    return " ".join(parts).strip()


def classify(text: str) -> RouteDecision:
    normalized = re.sub(r"\s+", "", (text or "").lower())
    if detect_intent(normalized) is not None:
        # Whitelisted read-only queries normally finish within one second.
        return RouteDecision("server_operation", False)
    if any(marker in normalized for marker in _SERVER_MARKERS):
        # Unknown or potentially complex server requests may need an LLM fallback.
        return RouteDecision("server_operation", True)
    return RouteDecision("quick_reply", False)


def quick_reply(text: str) -> str:
    normalized = re.sub(r"\s+", "", (text or "").lower())
    if any(marker in normalized for marker in _GREETING_MARKERS):
        return "你好，我是 AISSHBot。你可以问我服务器状态、进程、GPU、Java、Nginx 或 Docker。"
    if any(marker in normalized for marker in _IDENTITY_MARKERS):
        return "我是 AISSHBot，只对已授权服务器执行受控运维查询。发送“我能操作哪些服务器”即可开始。"
    return "请描述服务器运维需求，例如“查看阿里云服务器 Java 状态”。"
