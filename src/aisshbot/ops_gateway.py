"""Whitelist-only read operations and concise response formatting."""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from .intent import OperationIntent, detect_intent


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVERS_FILE = PROJECT_ROOT / "data" / "servers.json"
CREDENTIALS_FILE = PROJECT_ROOT / "secrets" / "server_credentials.json"
AUDIT_FILE = PROJECT_ROOT / "data" / "ops_audit.jsonl"


class GatewayError(RuntimeError):
    pass


READONLY_COMMANDS = {
    "health": (
        "printf 'hostname='; hostname; "
        "printf 'cpu_cores='; nproc; "
        "printf 'load1='; awk '{print $1}' /proc/loadavg; "
        "printf 'uptime='; (uptime -p 2>/dev/null || uptime); "
        "awk '/MemTotal:/{print \"mem_total_kb=\"$2} /MemAvailable:/{print \"mem_available_kb=\"$2}' /proc/meminfo; "
        "df -Pk / | awk 'NR==2 {print \"disk_total_kb=\"$2; print \"disk_used_kb=\"$3; print \"disk_pct=\"$5}'"
    ),
    "processes": (
        "printf 'total='; ps -e --no-headers | wc -l; "
        "printf 'account='; ps -u \"$(id -u)\" --no-headers | wc -l; "
        "printf 'abnormal='; ps -e -o stat= | awk '/^[DZ]/{c++} END{print c+0}'; "
        "echo '__ROWS__'; "
        "ps -eo user=,pid=,stat=,etime=,%cpu=,%mem=,comm= --sort=-%cpu | head -n 7"
    ),
    "java_status": (
        "printf 'java_count='; ps -e -o comm= | awk '$1==\"java\"{c++} END{print c+0}'; "
        "echo '__ROWS__'; "
        "ps -eo pid=,user=,stat=,etime=,%cpu=,%mem=,comm= --sort=-%cpu | awk '$7==\"java\"{print}' | head -n 6"
    ),
    "paper_progress": (
        "if command -v nvidia-smi >/dev/null 2>&1; then "
        "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits; "
        "echo '__APPS__'; "
        "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits; "
        "else echo 'nvidia-smi=unavailable'; fi"
    ),
}

SERVICE_STATUS_COMMANDS = {
    "nginx": (
        "printf 'service=nginx\\n'; "
        "printf 'active=%s\\n' \"$(systemctl is-active nginx 2>/dev/null || true)\"; "
        "printf 'enabled=%s\\n' \"$(systemctl is-enabled nginx 2>/dev/null || true)\"; "
        "printf 'main_pid=%s\\n' \"$(systemctl show nginx -p MainPID --value 2>/dev/null || echo 0)\""
    ),
    "docker": (
        "printf 'service=docker\\n'; "
        "printf 'active=%s\\n' \"$(systemctl is-active docker 2>/dev/null || true)\"; "
        "printf 'enabled=%s\\n' \"$(systemctl is-enabled docker 2>/dev/null || true)\"; "
        "printf 'containers=%s\\n' \"$(docker ps -q 2>/dev/null | wc -l)\""
    ),
}

SERVICE_LOG_COMMANDS = {
    "nginx": "journalctl -u nginx --no-pager -n 20 -o short-iso 2>&1 | tail -n 20",
    "docker": "journalctl -u docker --no-pager -n 20 -o short-iso 2>&1 | tail -n 20",
}


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GatewayError(f"配置读取失败：{path.name}") from exc


def _server_config(server_id: str) -> dict:
    try:
        return _load_json(SERVERS_FILE)[server_id]
    except KeyError as exc:
        raise GatewayError("未找到该服务器资产") from exc


def _credentials(ref: str) -> dict:
    try:
        return _load_json(CREDENTIALS_FILE)[ref]
    except KeyError as exc:
        raise GatewayError("服务器凭据未配置") from exc


def _run_local(command: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["/bin/bash", "-c", command],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=15,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    output = (completed.stdout + ("\n" + completed.stderr if completed.stderr else "")).strip()
    return completed.returncode, output


def _run_ssh(config: dict, command: str) -> tuple[int, str]:
    known_hosts = PROJECT_ROOT / config["known_hosts"]
    if not known_hosts.exists():
        raise GatewayError("目标服务器缺少可信 SSH 主机公钥，已拒绝连接。")
    credential = _credentials(config["credential_ref"])
    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=config["host"],
            port=int(config.get("port", 22)),
            username=config["username"],
            password=credential["password"],
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        _, stdout, stderr = client.exec_command(command, timeout=15)
        output = stdout.read().decode("utf-8", errors="replace").strip()
        error = stderr.read().decode("utf-8", errors="replace").strip()
        if error:
            output = (output + "\n" + error).strip()
        return stdout.channel.recv_exit_status(), output
    finally:
        client.close()


def _write_audit(intent: OperationIntent, actor_id: str, status: str, exit_code: int | None = None) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_id": actor_id,
        "server_id": intent.server_id,
        "operation": intent.operation,
        "target": intent.target,
        "status": status,
        "exit_code": exit_code,
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_denied_audit(intent: OperationIntent, actor_id: str) -> None:
    _write_audit(intent, actor_id, "denied")


def _as_int(value: str | None, default: int = 0) -> int:
    try:
        return int(float(str(value).replace("%", "")))
    except (TypeError, ValueError):
        return default


def _as_float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _kv_and_rows(raw: str, marker: str = "__ROWS__") -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    rows: list[str] = []
    in_rows = False
    for line in raw.splitlines():
        line = line.strip()
        if line == marker:
            in_rows = True
            continue
        if not line:
            continue
        if in_rows:
            rows.append(line)
        elif "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values, rows


def _mobile_items(items: list[str]) -> str:
    """Format narrow, readable WeChat messages without pseudo-tables."""
    return "\n".join(f"• {item}" for item in items)


def _format_health(name: str, raw: str) -> str:
    values, _ = _kv_and_rows(raw, marker="__NEVER__")
    cores = _as_int(values.get("cpu_cores"))
    load = _as_float(values.get("load1"))
    total_kb = _as_int(values.get("mem_total_kb"))
    available_kb = _as_int(values.get("mem_available_kb"))
    used_kb = max(total_kb - available_kb, 0)
    mem_pct = round(used_kb / total_kb * 100) if total_kb else 0
    disk_total = _as_int(values.get("disk_total_kb"))
    disk_used = _as_int(values.get("disk_used_kb"))
    disk_pct = _as_int(values.get("disk_pct"))
    warnings = []
    if cores and load > cores:
        warnings.append("系统负载偏高")
    if mem_pct >= 90:
        warnings.append("内存使用率偏高")
    if disk_pct >= 90:
        warnings.append("根分区空间不足")
    conclusion = "；".join(warnings) if warnings else "资源状态正常"
    return "【%s · 资源概览】\n%s\n结论：%s。" % (
        name,
        _mobile_items([
            f"CPU：{cores} 核，1 分钟负载 {load:g}",
            f"内存：{used_kb / 1048576:.1f} / {total_kb / 1048576:.1f} GB（{mem_pct}%）",
            f"磁盘：{disk_used / 1048576:.1f} / {disk_total / 1048576:.1f} GB（{disk_pct}%）",
            f"运行时间：{values.get('uptime', '未知')}",
        ]),
        conclusion,
    )


def _format_processes(name: str, raw: str, detail: str) -> str:
    values, raw_rows = _kv_and_rows(raw)
    total = _as_int(values.get("total"))
    account = _as_int(values.get("account"))
    abnormal = _as_int(values.get("abnormal"))
    summary = (
        f"【{name} · 进程概览】\n"
        + _mobile_items([
            f"系统进程：{total:,} 个",
            f"当前账号：{account:,} 个",
            f"异常状态（D/Z）：{abnormal} 个",
        ])
    )
    if detail == "count":
        return summary
    limit = 5 if detail == "detail" else 3
    rows = []
    for line in raw_rows[:limit]:
        fields = line.split(maxsplit=6)
        if len(fields) == 7:
            user, pid, state, elapsed, cpu, memory, command = fields
            rows.append(
                f"{command}（PID {pid}）\n"
                f"  CPU {cpu}% · 内存 {memory}% · 已运行 {elapsed}"
            )
    if not rows:
        return summary
    return summary + "\n\n高占用进程\n" + _mobile_items(rows)


def _format_java(name: str, raw: str) -> str:
    values, raw_rows = _kv_and_rows(raw)
    count = _as_int(values.get("java_count"))
    if count == 0:
        return f"【{name} · Java】未发现 Java 进程。"
    abnormal = 0
    rows = []
    for line in raw_rows[:5]:
        fields = line.split(maxsplit=6)
        if len(fields) == 7:
            pid, user, state, elapsed, cpu, memory, command = fields
            if state.startswith(("D", "Z")):
                abnormal += 1
            rows.append(
                f"PID {pid}：{state} 状态\n"
                f"  CPU {cpu}% · 内存 {memory}% · 已运行 {elapsed}"
            )
    conclusion = "发现异常状态，请进一步排查" if abnormal else "未发现 D/Z 异常状态"
    text = f"【{name} · Java】共 {count} 个进程；{conclusion}。"
    if rows:
        text += "\n\n进程详情\n" + _mobile_items(rows)
    return text


def _format_gpu(name: str, raw: str) -> str:
    if "nvidia-smi=unavailable" in raw:
        return f"【{name} · GPU】未安装或无法访问 nvidia-smi。"
    gpu_part, _, app_part = raw.partition("__APPS__")
    gpu_rows = []
    gpu_utils = []
    high_count = 0
    for line in gpu_part.splitlines():
        fields = [item.strip() for item in line.split(",")]
        if len(fields) != 5:
            continue
        index, model, util_s, used_s, total_s = fields
        util, used, total = _as_int(util_s), _as_int(used_s), _as_int(total_s)
        status = "高负载" if util >= 80 else "运行中" if util >= 20 else "空闲"
        if util >= 80:
            high_count += 1
        gpu_utils.append(util)
        gpu_rows.append(
            f"GPU {index}：{status}\n"
            f"  利用率 {util}% · 显存 {used / 1024:.1f} / {total / 1024:.1f} GB"
        )
    app_lines = [line for line in app_part.splitlines() if line.strip()]
    app_names = []
    for line in app_lines:
        fields = [item.strip() for item in line.split(",")]
        if len(fields) >= 2:
            app_names.append(os.path.basename(fields[1]))
    app_summary = "、".join(sorted(set(app_names))) or "无"
    if not gpu_rows:
        return f"【{name} · GPU】没有采集到显卡数据。"
    max_util = max(gpu_utils)
    if high_count:
        conclusion = f"{high_count}/{len(gpu_rows)} 张 GPU 处于高负载，训练/计算任务正在运行"
    elif max_util >= 20 or app_lines:
        conclusion = "GPU 正在运行计算任务，当前负载中等"
    else:
        conclusion = "GPU 当前基本空闲"
    return (
        f"【{name} · GPU】\n"
        + _mobile_items(gpu_rows)
        + f"\n\n计算任务：{len(app_lines)} 个（{app_summary}）\n结论：{conclusion}。"
    )


def _format_service_status(name: str, target: str, raw: str) -> str:
    values, _ = _kv_and_rows(raw, marker="__NEVER__")
    active = values.get("active") or "unknown"
    enabled = values.get("enabled") or "unknown"
    extra = ""
    if target == "nginx":
        extra = f"，主进程 PID {values.get('main_pid', '0')}"
    elif target == "docker":
        extra = f"，运行容器 {values.get('containers', '0')} 个"
    if active == "active":
        conclusion = "运行正常"
    elif active in ("unknown", "not-found", ""):
        conclusion = "未运行或未安装"
    else:
        conclusion = f"当前状态为 {active}"
    enabled_text = "未配置" if enabled in ("unknown", "not-found", "") else enabled
    return f"【{name} · {target}】{conclusion}；开机启动 {enabled_text}{extra}。"


_SECRET_PATTERN = re.compile(r"(?i)(password|passwd|token|secret|authorization)(\s*[=:]\s*)\S+")


def _format_logs(name: str, target: str, raw: str) -> str:
    lines = []
    for line in raw.splitlines()[-10:]:
        clean = _SECRET_PATTERN.sub(r"\1\2<redacted>", line.strip())[:180]
        if clean:
            lines.append(clean)
    if not lines:
        return f"【{name} · {target}日志】最近没有可读取的日志。"
    return f"【{name} · {target}最近日志】\n" + "\n".join(f"- {line}" for line in lines)


def _format_inventory(visible_server_ids: list[str]) -> str:
    servers = _load_json(SERVERS_FILE)
    rows = []
    for server_id in visible_server_ids:
        config = servers.get(server_id)
        if config:
            transport = "本机" if config.get("transport") == "local" else "SSH"
            rows.append(f"{config['name']}（{server_id}）\n  {transport} · 只读")
    if not rows:
        return "当前没有可访问的服务器。"
    return (
        "【可操作服务器】\n"
        + "\n".join(f"{index + 1}. {row}" for index, row in enumerate(rows))
        + "\n\n回复“切换到服务器1”或“切换到阿里云服务器”可设为默认服务器。"
    )


def _command_for(intent: OperationIntent) -> str:
    if intent.operation in READONLY_COMMANDS:
        return READONLY_COMMANDS[intent.operation]
    if intent.operation == "service_status" and intent.target in SERVICE_STATUS_COMMANDS:
        return SERVICE_STATUS_COMMANDS[intent.target]
    if intent.operation == "service_logs" and intent.target in SERVICE_LOG_COMMANDS:
        return SERVICE_LOG_COMMANDS[intent.target]
    raise GatewayError("该操作或目标不在只读白名单中")


def _format_result(intent: OperationIntent, config: dict, code: int, raw: str) -> str:
    name = config["name"]
    if code != 0 and not raw:
        return f"【{name}】查询失败（退出码 {code}）。"
    if intent.operation == "health":
        return _format_health(name, raw)
    if intent.operation == "processes":
        return _format_processes(name, raw, intent.detail)
    if intent.operation == "java_status":
        return _format_java(name, raw)
    if intent.operation == "paper_progress":
        return _format_gpu(name, raw)
    if intent.operation == "service_status" and intent.target:
        return _format_service_status(name, intent.target, raw)
    if intent.operation == "service_logs" and intent.target:
        return _format_logs(name, intent.target, raw)
    raise GatewayError("没有对应的结果格式化器")


async def execute_readonly(
    intent: OperationIntent,
    actor_id: str,
    visible_server_ids: list[str],
) -> str:
    if intent.server_id not in visible_server_ids:
        write_denied_audit(intent, actor_id)
        raise GatewayError("服务器不在当前用户的授权范围内")
    if intent.operation == "inventory":
        _write_audit(intent, actor_id, "success", 0)
        return _format_inventory(visible_server_ids)
    if intent.operation == "select_server":
        config = _server_config(intent.server_id)
        _write_audit(intent, actor_id, "success", 0)
        return f"已切换到【{config['name']}】。后续未指定服务器时默认查询它。"

    command = _command_for(intent)
    config = _server_config(intent.server_id)
    try:
        if config["transport"] == "local":
            code, raw = await asyncio.to_thread(_run_local, command)
        elif config["transport"] == "ssh":
            code, raw = await asyncio.to_thread(_run_ssh, config, command)
        else:
            raise GatewayError("不支持的服务器连接类型")
    except Exception:
        _write_audit(intent, actor_id, "failed")
        raise
    _write_audit(intent, actor_id, "success" if code == 0 else "command_error", code)
    return _format_result(intent, config, code, raw)
