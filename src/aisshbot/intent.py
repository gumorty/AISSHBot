"""Rule-first intent detection for safe, structured server diagnostics."""

from __future__ import annotations

import re
from dataclasses import dataclass


SAFE_OPERATIONS = (
    "inventory",
    "select_server",
    "health",
    "processes",
    "process_detail",
    "process_training",
    "gpu_overview",
    "gpu_processes",
    "training_overview",
    "java_status",
    "java_log_sources",
    "middleware_overview",
    "service_status",
    "service_logs",
    "service_errors",
    "path_inspect",
    "file_list",
    "file_preview",
)

SERVICE_ALIASES = {
    "nginx": "nginx",
    "docker": "docker",
    "docker服务": "docker",
    "mysql": "mysql",
    "mysqld": "mysql",
    "mariadb": "mysql",
    "mqtt": "mqtt",
    "mosquitto": "mqtt",
    "emqx": "mqtt",
    "redis": "redis",
    "redis-server": "redis",
}

# Keep Chinese sentence text after a path out of the target, e.g.
# `/home/uav/a.py内容` should resolve to `/home/uav/a.py`.
_PATH_RE = re.compile(r"(?P<path>/[A-Za-z0-9._~:/@%+\-]+)")
_PID_RE = re.compile(r"(?:pid\s*[=:：#-]?\s*)?(?<!\d)([1-9]\d{1,8})(?!\d)", re.I)


@dataclass(frozen=True)
class OperationIntent:
    operation: str
    server_id: str
    assumed_server: bool = False
    target: str | None = None
    detail: str = "summary"
    target_type: str | None = None
    output_mode: str = "text"


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


def _path_from_text(message: str) -> str | None:
    match = _PATH_RE.search(message or "")
    if not match:
        return None
    return match.group("path").rstrip("/，。；、！？?：:,.!") or "/"


def _pid_from_text(message: str) -> str | None:
    match = _PID_RE.search(message or "")
    return match.group(1) if match else None


def _training_words(value: str) -> bool:
    return any(word in value for word in (
        "论文", "训练", "实验", "epoch", "loss", "step", "训练进度", "训练情况",
        "模型", "指标", "map50", "map50-95", "最佳", "权重", "曲线",
    ))


def _training_detail(value: str) -> str:
    """Choose the smallest useful answer for the user's training question."""
    if any(word in value for word in (
        "趋势", "走势", "最近几轮", "最近十轮", "效果", "提升", "下降", "平台期", "是否变好",
    )):
        return "trend"
    if any(word in value for word in (
        "第几轮", "到哪一轮", "进度", "完成多少", "跑到哪里", "还要多久",
    )):
        return "progress"
    if any(word in value for word in (
        "指标", "loss", "map", "精度", "准确率", "召回率", "precision", "recall",
    )):
        return "metrics"
    if any(word in value for word in (
        "详细", "完整", "产物", "模型文件", "best.pt", "last.pt", "曲线", "混淆矩阵",
    )):
        return "detail"
    return "summary"


def detect_intent(message: str, default_server_id: str | None = None) -> OperationIntent | None:
    raw_message = message or ""
    value = re.sub(r"\s+", "", raw_message).lower()
    if not value:
        return None

    server_id, assumed = _server_from_text(value, default_server_id)
    path = _path_from_text(raw_message)
    pid = _pid_from_text(raw_message)

    inventory_phrases = (
        "有哪些服务器", "有什么服务器", "哪些服务器", "服务器列表", "可用服务器",
        "我的服务器", "可访问服务器", "能操作的服务器", "可以操作的服务器",
        "服务器可以操作", "服务器能操作",
    )
    if any(phrase in value for phrase in inventory_phrases):
        return OperationIntent("inventory", server_id, assumed)

    if not assumed and any(word in value for word in ("切换", "选择", "连接", "使用", "设为默认")):
        return OperationIntent("select_server", server_id, False)

    # A PID plus training language is a domain query, not a generic process
    # detail query.  Resolve it before path/file rules so a script path in the
    # same sentence cannot hide the training request.
    if pid and _training_words(value):
        return OperationIntent(
            "process_training", server_id, assumed, target=pid, target_type="pid",
            detail=_training_detail(value),
        )

    if path and _training_words(value):
        return OperationIntent(
            "training_overview", server_id, assumed, target=path, target_type="path",
            detail=_training_detail(value),
        )

    if path and any(word in value for word in ("列出", "目录", "文件夹", "有哪些文件", "文件列表")):
        return OperationIntent("file_list", server_id, assumed, target=path, target_type="path")
    if path and any(word in value for word in ("查看", "读取", "内容", "最后", "tail", "日志")):
        return OperationIntent("file_preview", server_id, assumed, target=path, target_type="path")
    if path:
        return OperationIntent("path_inspect", server_id, assumed, target=path, target_type="path")

    service = _service_from_text(value)
    if service and any(word in value for word in ("报错", "错误", "异常", "error", "exception", "失败")):
        return OperationIntent("service_errors", server_id, assumed, target=service, target_type="service")
    if service and any(word in value for word in ("日志", "log", "记录")):
        return OperationIntent("service_logs", server_id, assumed, target=service, target_type="service")
    if service and any(word in value for word in ("状态", "运行", "正常", "是否启动", "在不在")):
        return OperationIntent("service_status", server_id, assumed, target=service, target_type="service")

    if "java" in value and any(word in value for word in ("日志", "log", "文件")):
        return OperationIntent(
            "java_log_sources", server_id, assumed, target=pid or "all",
            target_type="pid" if pid else "process_group",
        )
    if "java" in value and any(word in value for word in ("进程", "运行", "状态", "异常", "服务", "正常")):
        return OperationIntent("java_status", server_id, assumed, target="java", target_type="process_group")

    if any(word in value for word in ("中间件", "运行的服务", "服务列表", "mysql", "mqtt", "nginx", "redis")):
        return OperationIntent("middleware_overview", server_id, assumed)

    if any(word in value for word in ("gpu进程", "显卡进程", "占用gpu的进程", "gpu上的进程")):
        return OperationIntent("gpu_processes", server_id, assumed)
    if _training_words(value):
        return OperationIntent(
            "training_overview", server_id, assumed,
            target_type="current_run", detail=_training_detail(value),
        )
    if any(word in value for word in ("gpu", "显卡", "nvidia-smi")):
        return OperationIntent("gpu_overview", server_id, assumed)

    if pid and any(word in value for word in ("进程", "pid", "详情", "状态", "在干什么")):
        return OperationIntent("process_detail", server_id, assumed, target=pid, target_type="pid")
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
    """Fallback contract; it excludes credentials, paths and command output."""
    fallback_operations = [
        "inventory", "select_server", "health", "processes", "gpu_overview",
        "training_overview", "java_status", "middleware_overview",
    ]
    return (
        "你是 AISSHBot 的受限意图规划器。只能选择 operation、server_id 和 detail；"
        "绝不输出 shell 命令、路径、账号、密码或执行步骤。\n"
        f"允许操作：{fallback_operations}；允许服务器：{visible_servers}。\n"
        "detail 只允许 count、summary、progress、trend、metrics、detail。\n"
        f"本地会话上下文：{context_summary or '无'}。\n"
        "只输出 JSON：{\"operation\":\"...\",\"server_id\":\"...\","
        "\"detail\":\"summary\",\"confidence\":0.0}。\n"
        f"用户消息：{message!r}"
    )
