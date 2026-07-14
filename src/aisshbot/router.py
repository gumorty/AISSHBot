"""Fast local routing for AISSHBot chat messages."""

from __future__ import annotations

from dataclasses import dataclass


PROCESSING_ACK = "正在处理，请稍候。"

_SERVER_WORDS = (
    "服务器", "ssh", "cpu", "内存", "磁盘", "进程", "日志", "java", "docker",
    "nginx", "gpu", "显卡", "训练", "论文", "实验", "部署", "文件", "上传", "下载",
)
_GREETING_WORDS = ("你好", "您好", "在吗", "你是谁", "帮助", "help")


@dataclass(frozen=True)
class Route:
    kind: str
    requires_processing_ack: bool


def classify(message: str) -> Route:
    value = (message or "").lower()
    if any(word in value for word in _SERVER_WORDS):
        return Route("server_request", True)
    return Route("quick_reply", False)


def quick_reply(message: str) -> str:
    value = (message or "").lower()
    if any(word in value for word in _GREETING_WORDS):
        return "我是 AISSHBot，只处理已授权服务器的状态查询和受控运维操作。可发送“查看服务器列表”。"
    return "我是 AISSHBot。请描述需要查询的已授权服务器状态，例如“查看 AI服务器1 CPU和内存”。"
