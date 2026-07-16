"""Whitelist-only read operations and concise response formatting."""

from __future__ import annotations

import asyncio
import csv
import fnmatch
import io
import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from .intent import OperationIntent, detect_intent
from .training import analyze_results_csv, summarize_status, total_epochs_from_text


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
    "gpu_overview": (
        "if command -v nvidia-smi >/dev/null 2>&1; then "
        "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits; "
        "echo '__APPS__'; "
        "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits; "
        "else echo 'nvidia-smi=unavailable'; fi"
    ),
    "gpu_processes": (
        "if command -v nvidia-smi >/dev/null 2>&1; then "
        "echo '__GPU_PROCESSES__'; "
        "nvidia-smi --query-compute-apps=pid,process_name,used_memory "
        "--format=csv,noheader,nounits 2>/dev/null | "
        "while IFS=, read -r pid pname gpu_mem; do "
        "case \"$pid\" in ''|*[!0-9]*) continue;; esac; "
        "ps -p \"$pid\" -o user=,pid=,ppid=,stat=,etime=,%cpu=,%mem=,comm= 2>/dev/null | "
        "awk -v gpu_mem=\"$gpu_mem\" '{print gpu_mem \"|\" $0}'; "
        "done; "
        "else echo 'nvidia-smi=unavailable'; fi"
    ),
    "middleware_overview": (
        "echo '__UNITS__'; "
        "for unit in nginx mysql mysqld mariadb mosquitto emqx redis redis-server docker; do "
        "active=$(systemctl is-active \"$unit\" 2>/dev/null || true); "
        "enabled=$(systemctl is-enabled \"$unit\" 2>/dev/null || true); "
        "pid=$(systemctl show \"$unit\" -p MainPID --value 2>/dev/null || true); "
        "[ -n \"$active$enabled$pid\" ] && printf '%s|%s|%s|%s\\n' \"$unit\" \"$active\" \"$enabled\" \"${pid:-0}\"; "
        "done; "
        "echo '__PROCESSES__'; "
        "ps -eo pid=,user=,stat=,etime=,%cpu=,%mem=,comm= --sort=-%cpu | "
        "awk '$7 ~ /^(java|nginx|mysqld|mariadbd|mosquitto|emqx|redis-server)$/ {print}' | head -n 15"
    ),
}

SERVICE_UNITS = {
    "nginx": ("nginx",),
    "docker": ("docker",),
    "mysql": ("mysql", "mysqld", "mariadb"),
    "mqtt": ("mosquitto", "emqx"),
    "redis": ("redis", "redis-server"),
}

HARD_DENIED_PATHS = (
    "/proc", "/proc/*", "/sys", "/sys/*", "/dev", "/dev/*", "/run", "/run/*",
    "/etc/shadow", "/etc/gshadow", "/etc/ssh", "/etc/ssh/*", "/etc/ssl/private", "/etc/ssl/private/*",
    "*/.ssh", "*/.ssh/*", "*/.gnupg", "*/.gnupg/*", "*/.aws", "*/.aws/*",
    "*/.kube/config", "*.pem", "*.key", "*/.env", "*/.env.*",
)


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


def _is_under_root(path: str, root: str) -> bool:
    return root == "/" or path == root or path.startswith(root.rstrip("/") + "/")


def _validate_read_path(path: str | None, config: dict) -> str:
    if not path or not path.startswith("/"):
        raise GatewayError("请提供以 / 开头的绝对路径。")
    if "\x00" in path or any(part in (".", "..") for part in path.split("/")):
        raise GatewayError("路径不能包含 .、.. 或空字节。")
    read_roots = config.get("read_roots", [])
    if not any(_is_under_root(path, root.rstrip("/")) for root in read_roots):
        raise GatewayError("该路径不在当前服务器允许读取的范围内。")
    denied = tuple(config.get("denied_read_patterns", [])) + HARD_DENIED_PATHS
    if any(fnmatch.fnmatch(path, pattern) for pattern in denied):
        raise GatewayError("该路径属于敏感来源，AISSHBot 不会读取。")
    return path


def _path_guard_command(path: str, config: dict) -> str:
    """Resolve remote symlinks and re-check roots before any file operation."""
    quoted_path = shlex.quote(path)
    roots = [root.rstrip("/") or "/" for root in config.get("read_roots", [])]
    if "/" in roots:
        root_check = ":"
    else:
        patterns = []
        for root in roots:
            patterns.extend((root, root + "/*"))
        root_check = f"case \"$resolved\" in {'|'.join(patterns)}) ;; *) echo '__ERROR__|outside_read_root'; exit 2;; esac"
    return (
        f"resolved=$(readlink -f -- {quoted_path} 2>/dev/null) || {{ echo '__ERROR__|path_not_found'; exit 2; }}; "
        f"{root_check}; "
        "case \"$resolved\" in "
        "/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/etc/shadow|/etc/gshadow|"
        "/etc/ssh|/etc/ssh/*|/etc/ssl/private|/etc/ssl/private/*|*/.ssh|*/.ssh/*|*/.gnupg|*/.gnupg/*|"
        "*/.aws|*/.aws/*|*/.kube/config|*.pem|*.key|*/.env|*/.env.*) "
        "echo '__ERROR__|sensitive_path'; exit 2;; esac"
    )


def _pid_target(intent: OperationIntent) -> str:
    if not intent.target or not re.fullmatch(r"[1-9]\d{1,8}", intent.target):
        raise GatewayError("PID 必须是有效的纯数字。")
    return intent.target


def _process_detail_command(intent: OperationIntent) -> str:
    pid = _pid_target(intent)
    return (
        f"if ps -p {pid} >/dev/null 2>&1; then "
        "ps -p " + pid + " -o user=,pid=,ppid=,stat=,etime=,%cpu=,%mem=,comm=; "
        "else echo '__MISSING__'; fi"
    )


def _process_training_command(intent: OperationIntent) -> str:
    """Collect bounded metadata for one GPU process, never arbitrary proc data."""
    pid = _pid_target(intent)
    return (
        f"if ps -p {pid} >/dev/null 2>&1; then "
        "echo '__PROCESS__'; "
        "ps -p " + pid + " -o user=,pid=,ppid=,pgid=,stat=,etime=,%cpu=,%mem=,comm=; "
        "echo '__CWD__'; cwd=$(readlink -f /proc/" + pid + "/cwd 2>/dev/null || true); "
        "case \"$cwd\" in /home/uav|/home/uav/*) printf '%s\\n' \"$cwd\";; *) cwd='';; esac; "
        "echo '__CMDLINE__'; "
        "if [ -r /proc/" + pid + "/cmdline ]; then "
        "tr '\\0' ' ' < /proc/" + pid + "/cmdline | sed -E 's/((password|passwd|token|secret|api[_-]?key|authorization)[=: ]+)[^ ]+/\\1<redacted>/Ig' | cut -c1-360; "
        "fi; "
        "echo '__GPU__'; "
        "if command -v nvidia-smi >/dev/null 2>&1; then "
        "nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader,nounits 2>/dev/null | "
        "awk -F, -v wanted='" + pid + "' '{gsub(/^[ \\t]+|[ \\t]+$/, \"\", $1); if ($1==wanted) print $2}'; fi; "
        "echo '__RELATED_GPU_PIDS__'; "
        "if [ -n \"$cwd\" ] && command -v nvidia-smi >/dev/null 2>&1; then "
        "nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits 2>/dev/null | awk '{gsub(/ /, \"\"); if ($1 ~ /^[0-9]+$/) print $1}' | "
        "while read -r related; do rcwd=$(readlink -f /proc/\"$related\"/cwd 2>/dev/null || true); "
        "[ \"$rcwd\" = \"$cwd\" ] && printf '%s\\n' \"$related\"; done | sort -n -u; fi; "
        "echo '__ARTIFACTS__'; "
        "if [ -n \"$cwd\" ]; then "
        "find \"$cwd\" -xdev -maxdepth 5 -type f \\( -name 'results.csv' -o -name 'args.yaml' -o -name 'best.pt' -o -name 'last.pt' -o -name 'results.png' -o -name 'confusion_matrix*.png' -o -name 'PR_curve.png' -o -iname '*.log' \\) "
        "-size -200M -printf '%T@|%s|%p\\n' 2>/dev/null | sort -nr | head -n 40; "
        "csv=$(find \"$cwd\" -xdev -maxdepth 5 -type f -name 'results.csv' -size -4M -printf '%T@|%p\\n' 2>/dev/null | sort -nr | head -n 1 | cut -d'|' -f2); "
        "if [ -n \"$csv\" ]; then echo '__CSV_PATH__'; printf '%s\\n' \"$csv\"; echo '__CSV__'; head -c 4194304 \"$csv\"; "
        "cfg=$(find \"$(dirname \"$csv\")\" -maxdepth 2 -type f -name 'args.yaml' -size -256k -print -quit 2>/dev/null); "
        "else cfg=$(find \"$cwd\" -xdev -maxdepth 5 -type f -name 'args.yaml' -size -256k -print -quit 2>/dev/null); fi; "
        "if [ -n \"$cfg\" ]; then echo '__CONFIG__'; cat \"$cfg\"; fi; "
        "fi; "
        "else echo '__MISSING__'; fi"
    )


def _java_log_sources_command(intent: OperationIntent) -> str:
    if intent.target == "all":
        # Keep each ps format as a separate -o option.  This works on the
        # older procps version present on the Alibaba host as well.
        pid_selector = "ps -e -o pid= -o comm= | awk '$2==\"java\" {print $1}'"
    else:
        pid_selector = f"printf '%s\\n' '{_pid_target(intent)}'"
    return (
        "echo '__JAVA_LOG_SOURCES__'; "
        f"for pid in $({pid_selector}); do "
        "if ps -p \"$pid\" -o comm= 2>/dev/null | grep -qx 'java'; then "
        "printf '__PID__|%s\\n' \"$pid\"; "
        "ps -p \"$pid\" -o user=,pid=,ppid=,stat=,etime=,%cpu=,%mem=,comm=; "
        "for fd in /proc/\"$pid\"/fd/*; do p=$(readlink \"$fd\" 2>/dev/null || true); "
        "case \"$p\" in *.log|*/logs/*) printf '%s\\n' \"$p\";; esac; done | sort -u | head -n 12; "
        "fi; done"
    )


def _service_units(target: str | None) -> tuple[str, ...]:
    units = SERVICE_UNITS.get(target or "")
    if not units:
        raise GatewayError("该服务不在允许查询的中间件清单中。")
    return units


def _service_status_command(target: str | None) -> str:
    units = " ".join(shlex.quote(unit) for unit in _service_units(target))
    return (
        "echo '__SERVICES__'; "
        f"for unit in {units}; do "
        "active=$(systemctl is-active \"$unit\" 2>/dev/null || true); "
        "enabled=$(systemctl is-enabled \"$unit\" 2>/dev/null || true); "
        "pid=$(systemctl show \"$unit\" -p MainPID --value 2>/dev/null || true); "
        "printf '%s|%s|%s|%s\\n' \"$unit\" \"${active:-unknown}\" \"${enabled:-unknown}\" \"${pid:-0}\"; "
        "done"
    )


def _service_log_command(target: str | None, lines: int = 80) -> str:
    units = " ".join(f"-u {shlex.quote(unit)}" for unit in _service_units(target))
    return f"journalctl {units} --no-pager -n {lines} -o short-iso 2>&1 | tail -n {lines}"


def _training_overview_command(target: str | None = None, config: dict | None = None) -> str:
    if target:
        if config is None:
            raise GatewayError("训练查询缺少服务器配置。")
        safe_target = _validate_read_path(target, config)
        project_setup = (
            _path_guard_command(safe_target, config)
            + "; if [ -d \"$resolved\" ]; then scan_root=\"$resolved\"; else scan_root=$(dirname \"$resolved\"); fi; "
            + "project_rows() { printf 'path|%s\\n' \"$scan_root\"; "
            + "if command -v nvidia-smi >/dev/null 2>&1; then "
            + "nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits 2>/dev/null | awk '{gsub(/ /, \"\"); if ($1 ~ /^[0-9]+$/) print $1}' | "
            + "while read -r pid; do cwd=$(readlink -f /proc/\"$pid\"/cwd 2>/dev/null || true); "
            + "case \"$cwd\" in \"$scan_root\"|\"$scan_root\"/*) printf '%s|%s\\n' \"$pid\" \"$cwd\";; esac; done; fi; }; "
        )
    else:
        project_setup = (
            "gpu_pids() { nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits 2>/dev/null | "
            "awk '{gsub(/ /, \"\"); if ($1 ~ /^[0-9]+$/) print $1}'; }; "
            "project_rows() { gpu_pids | while read -r pid; do cwd=$(readlink -f \"/proc/$pid/cwd\" 2>/dev/null || true); "
            "case \"$cwd\" in /home/uav|/home/uav/*) printf '%s|%s\\n' \"$pid\" \"$cwd\";; esac; done | sort -u; }; "
        )
    return (
        project_setup
        +
        "training_files() { project_rows | while IFS='|' read -r pid cwd; do "
        "find \"$cwd\" -xdev -maxdepth 5 -type f \\( -iname '*.log' -o -name 'results.csv' -o -name 'metrics*.csv' -o -name 'args.yaml' -o -name 'best.pt' -o -name 'last.pt' -o -name 'results.png' -o -name 'confusion_matrix*.png' -o -name 'PR_curve.png' \\) "
        "! -path '*/.ssh/*' ! -name '.env' ! -name '.env.*' -size -200M -printf '%T@|%s|%p\\n' 2>/dev/null; done; }; "
        "echo '__GPU__'; "
        "if command -v nvidia-smi >/dev/null 2>&1; then "
        "nvidia-smi --query-gpu=index,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits; "
        "else echo 'unavailable'; fi; "
        "echo '__PROJECTS__'; project_rows; "
        "echo '__RECENT_LOGS__'; "
        "training_files | sort -nr | awk -F'|' '!seen[$3]++' | head -n 12; "
        "latest=$(training_files | sort -nr | awk -F'|' '$3 ~ /\\/results\\.csv$/ {print; exit}'); "
        "if [ -n \"$latest\" ]; then record=${latest#*|}; path=${record#*|}; echo '__LATEST_FILE__'; printf 'path=%s\\n' \"$path\"; "
        "printf 'modified='; stat -c '%y' \"$path\"; printf 'size='; stat -c '%s' \"$path\"; echo '__CSV__'; head -c 4194304 \"$path\"; "
        "cfg=$(training_files | awk -F'|' '$3 ~ /\\/args\\.yaml$/ {print $3; exit}'); "
        "if [ -n \"$cfg\" ]; then echo '__CONFIG__'; cat \"$cfg\"; fi; fi"
    )


def _file_list_command(path: str, config: dict) -> str:
    return (
        _path_guard_command(path, config)
        + "; [ -d \"$resolved\" ] || { echo '__ERROR__|not_a_directory'; exit 2; }; "
        "echo '__FILES__'; find \"$resolved\" -mindepth 1 -maxdepth 1 \\( -type f -o -type d \\) "
        "-printf '%y|%s|%TY-%Tm-%Td %TH:%TM|%f\\n' 2>/dev/null | sort | head -n 80"
    )


def _path_inspect_command(path: str, config: dict) -> str:
    """Inspect a path and return bounded metadata for the correct formatter."""
    return (
        _path_guard_command(path, config)
        + "; if [ -d \"$resolved\" ]; then "
        "echo '__TYPE__|directory'; printf '__PATH__|%s\\n' \"$resolved\"; "
        "echo '__ENTRIES__'; find \"$resolved\" -mindepth 1 -maxdepth 1 \\( -type f -o -type d \\) "
        "-printf '%y|%s|%TY-%Tm-%Td %TH:%TM|%f\\n' 2>/dev/null | sort | head -n 40; "
        "echo '__ACTIVE_PIDS__'; "
        "if command -v nvidia-smi >/dev/null 2>&1; then "
        "nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits 2>/dev/null | awk '{gsub(/ /, \"\"); if ($1 ~ /^[0-9]+$/) print $1}' | "
        "while read -r pid; do cwd=$(readlink -f /proc/\"$pid\"/cwd 2>/dev/null || true); case \"$cwd\" in \"$resolved\"|\"$resolved\"/*) printf '%s\\n' \"$pid\";; esac; done; fi; "
        "csv=$(find \"$resolved\" -xdev -maxdepth 5 -type f -name 'results.csv' -size -4M -printf '%T@|%p\\n' 2>/dev/null | sort -nr | head -n 1 | cut -d'|' -f2); "
        "if [ -n \"$csv\" ]; then echo '__TRAINING_CSV_PATH__'; printf '%s\\n' \"$csv\"; echo '__TRAINING_CSV__'; head -c 4194304 \"$csv\"; "
        "cfg=$(find \"$(dirname \"$csv\")\" -maxdepth 2 -type f -name 'args.yaml' -size -256k -print -quit 2>/dev/null); "
        "if [ -n \"$cfg\" ]; then echo '__CONFIG__'; cat \"$cfg\"; fi; fi; "
        "else echo '__TYPE__|file'; printf '__PATH__|%s\\n' \"$resolved\"; "
        "size=$(stat -c %s \"$resolved\" 2>/dev/null || echo 0); modified=$(stat -c %y \"$resolved\" 2>/dev/null || true); "
        "mime=$(file -b --mime-type \"$resolved\" 2>/dev/null || echo application/octet-stream); "
        "printf '__META__\\nsize=%s\\nmodified=%s\\nmime=%s\\n' \"$size\" \"$modified\" \"$mime\"; "
        "case \"$resolved\" in *.csv|*.tsv) echo '__TRAINING_CSV__'; head -c 4194304 \"$resolved\";; "
        "*.pt|*.pth|*.onnx|*.safetensors) echo '__ARTIFACT__|model';; "
        "*.png|*.jpg|*.jpeg|*.webp) echo '__ARTIFACT__|image';; "
        "*.log|*.out) echo '__LOG__'; tail -n 50 \"$resolved\";; "
        "*) echo '__TEXT__'; tail -n 50 \"$resolved\";; esac; fi"
    )


def _file_preview_command(path: str, config: dict) -> str:
    return (
        _path_guard_command(path, config)
        + "; [ -f \"$resolved\" ] && [ ! -L \"$resolved\" ] || { echo '__ERROR__|not_a_regular_file'; exit 2; }; "
        "size=$(stat -c %s \"$resolved\" 2>/dev/null || echo 0); [ \"$size\" -le 2097152 ] || { echo '__ERROR__|file_too_large'; exit 2; }; "
        "mime=$(file -b --mime-type \"$resolved\" 2>/dev/null || echo application/octet-stream); "
        "case \"$mime\" in text/*|application/json|application/xml|application/x-yaml) ;; "
        "*) case \"$resolved\" in *.py|*.pyw|*.sh|*.bash|*.conf|*.ini|*.yaml|*.yml|*.json|*.xml|*.properties|*.log|*.csv|*.tsv|*.txt|*.md) ;; "
        "*) echo '__ERROR__|non_text_file'; exit 2;; esac;; esac; "
        "echo '__META__'; printf 'path=%s\\nsize=%s\\nmime=%s\\n' \"$resolved\" \"$size\" \"$mime\"; "
        "echo '__CONTENT__'; tail -n 60 \"$resolved\""
    )


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


def _format_gpu_processes(name: str, raw: str) -> str:
    if "nvidia-smi=unavailable" in raw:
        return f"【{name} · GPU 进程】当前服务器未提供 nvidia-smi。"
    _, _, content = raw.partition("__GPU_PROCESSES__")
    rows = []
    for line in content.splitlines():
        fields = line.split("|", 1)
        if len(fields) != 2:
            continue
        gpu_memory, process = fields
        values = process.split(maxsplit=7)
        if len(values) != 8:
            continue
        user, pid, ppid, state, elapsed, cpu, memory, command = values
        rows.append(
            f"{command}（PID {pid}）\n"
            f"  GPU 显存 {gpu_memory.strip()} MiB · CPU {cpu}% · 内存 {memory}% · 已运行 {elapsed}"
        )
    if not rows:
        return f"【{name} · GPU 进程】当前没有检测到可见的计算进程。"
    return f"【{name} · GPU 进程】共 {len(rows)} 个\n" + _mobile_items(rows[:8])


def _format_process_detail(name: str, intent: OperationIntent, raw: str) -> str:
    if "__MISSING__" in raw:
        return f"【{name} · 进程】未找到 PID {intent.target}，它可能已经退出。"
    values = raw.strip().split(maxsplit=7)
    if len(values) != 8:
        return f"【{name} · 进程】无法读取 PID {intent.target} 的状态。"
    user, pid, ppid, state, elapsed, cpu, memory, command = values
    state_text = "异常" if state.startswith(("D", "Z")) else "运行中"
    return (
        f"【{name} · PID {pid}】{state_text}\n"
        + _mobile_items([
            f"程序：{command}",
            f"父进程：{ppid}",
            f"CPU：{cpu}% · 内存：{memory}%",
            f"运行时长：{elapsed}",
        ])
    )


def _format_middleware(name: str, raw: str) -> str:
    unit_part, _, process_part = raw.partition("__PROCESSES__")
    _, _, unit_content = unit_part.partition("__UNITS__")
    active = []
    for line in unit_content.splitlines():
        unit, *values = line.split("|")
        if len(values) != 3:
            continue
        state, enabled, pid = values
        if state == "active" or pid not in ("", "0"):
            active.append(f"{unit}：{state or 'unknown'}（PID {pid or '0'}）")
    processes = []
    for line in process_part.splitlines()[:8]:
        values = line.split(maxsplit=6)
        if len(values) == 7:
            pid, user, state, elapsed, cpu, memory, command = values
            processes.append(f"{command}（PID {pid}，CPU {cpu}%）")
    if not active and not processes:
        return f"【{name} · 中间件】未检测到 Nginx、MySQL、MQTT、Redis 或 Docker 服务。"
    blocks = []
    if active:
        blocks.append("服务状态\n" + _mobile_items(active[:8]))
    if processes:
        blocks.append("相关进程\n" + _mobile_items(processes))
    return f"【{name} · 中间件概览】\n" + "\n\n".join(blocks)


def _parse_service_records(raw: str) -> list[tuple[str, str, str, str]]:
    _, marker, content = raw.partition("__SERVICES__")
    source = content if marker else raw
    records = []
    for line in source.splitlines():
        values = line.split("|")
        if len(values) == 4:
            records.append(tuple(value.strip() for value in values))
    return records


def _format_service_status(name: str, target: str, raw: str) -> str:
    records = _parse_service_records(raw)
    if records:
        lines = []
        for unit, active, enabled, pid in records:
            if active == "active":
                status = "运行中"
            elif active in ("unknown", "not-found", ""):
                status = "未运行或未安装"
            else:
                status = active
            startup = "未配置" if enabled in ("unknown", "not-found", "") else enabled
            lines.append(f"{unit}：{status}\n  开机启动 {startup} · PID {pid or '0'}")
        return f"【{name} · {target}】\n" + _mobile_items(lines)
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


_ERROR_PATTERN = re.compile(r"(?i)(error|exception|fatal|oom|outofmemory|failed|timeout|拒绝|错误|异常)")


def _format_service_errors(name: str, target: str, raw: str) -> str:
    matches = []
    for line in raw.splitlines():
        clean = _SECRET_PATTERN.sub(r"\1\2<redacted>", line.strip())[:220]
        if clean and _ERROR_PATTERN.search(clean):
            matches.append(clean)
    if not matches:
        return f"【{name} · {target}错误摘要】最近采样日志中未发现 ERROR、Exception、OOM、Failed 或 Timeout。"
    recent = matches[-5:]
    return (
        f"【{name} · {target}错误摘要】发现 {len(matches)} 条可疑日志\n"
        + "\n".join(f"- {line}" for line in recent)
        + "\n\n说明：这是日志关键词诊断，不等同于服务已不可用。"
    )


def _section(raw: str, start: str, end: str | None = None) -> str:
    _, marker, content = raw.partition(start)
    if not marker:
        return ""
    if end:
        content, _, _ = content.partition(end)
    return content.strip()


def _metric_items(metrics: dict[str, str]) -> list[str]:
    labels = (
        ("box_loss", "Box Loss"),
        ("cls_loss", "Cls Loss"),
        ("map50", "mAP50"),
        ("map5095", "mAP50-95"),
        ("precision", "Precision"),
        ("recall", "Recall"),
    )
    return [f"{label}：{metrics[key]}" for key, label in labels if key in metrics]


def _training_summary(
    name: str,
    analysis,
    *,
    run_path: str | None = None,
    artifacts: list[str] | None = None,
    detail: str = "detail",
    prefix: str | None = None,
) -> str:
    items = [f"状态：{summarize_status(analysis)}"]
    if analysis.current_epoch is not None:
        progress = (
            f"{analysis.progress_percent:.0f}%"
            if analysis.progress_percent is not None
            else "总轮数未知"
        )
        total = analysis.total_epochs or "?"
        items.append(f"进度：第 {analysis.current_epoch} / {total} 轮（{progress}）")
    if analysis.last_update and detail in ("detail", "progress"):
        items.append(f"最近更新：{analysis.last_update}")
    if run_path and detail == "detail":
        items.append(f"实验目录：{run_path}")
    blocks = ["训练状态\n" + _mobile_items(items)]
    if detail == "progress":
        return (prefix or f"【{name} · 训练进度】") + "\n" + "\n\n".join(blocks)

    latest = _metric_items(analysis.latest_metrics)
    if detail in ("summary", "trend"):
        latest = [
            item for item in latest
            if item.startswith(("mAP50：", "mAP50-95："))
        ]
    if latest:
        blocks.append("最新指标\n" + _mobile_items(latest))
    best = _metric_items(analysis.best_metrics)
    if detail in ("trend", "metrics", "detail") and analysis.best_epoch is not None and best:
        if detail == "metrics":
            best = [item for item in best if item.startswith(("mAP50：", "mAP50-95：", "Precision：", "Recall："))]
        blocks.append(f"最佳结果：第 {analysis.best_epoch} 轮\n" + _mobile_items(best))
    trend_labels = {
        "improving": "最近 10 轮指标仍在改善",
        "plateau": "最近 10 轮提升较小，可能进入平台期",
        "declining": "最近 10 轮指标下降，建议检查数据或训练状态",
        "insufficient_data": "暂时没有足够历史数据判断趋势",
    }
    if detail in ("summary", "trend", "detail"):
        trend_text = trend_labels.get(analysis.trend, analysis.trend)
        if analysis.trend == "declining" and analysis.best_epoch is not None:
            trend_text += f"；当前指标低于第 {analysis.best_epoch} 轮最佳值，建议继续观察验证集指标，不直接判定训练失败"
        blocks.append("趋势判断\n• " + trend_text)
    if analysis.error_count and detail in ("trend", "detail"):
        blocks.append(f"风险提示\n• 最近采样日志匹配到 {analysis.error_count} 个错误关键词，建议查看具体日志。")
    if artifacts and detail == "detail":
        blocks.append("关键产物\n" + _mobile_items(artifacts[:8]))
    title = prefix or f"【{name} · 训练分析】"
    return title + "\n" + "\n\n".join(blocks)


def _parse_artifact_rows(raw: str) -> list[str]:
    rows = []
    for line in raw.splitlines():
        values = line.split("|", 2)
        if len(values) != 3 or not values[2].startswith("/"):
            continue
        _, size, path = values
        rows.append(f"{Path(path).name}（{_as_int(size) / 1024 / 1024:.1f} MB）")
    return rows


def _format_process_training(name: str, intent: OperationIntent, raw: str) -> str:
    if "__MISSING__" in raw:
        return f"【{name} · 训练进程】未找到 PID {intent.target}，它可能已经退出。"
    process = _section(raw, "__PROCESS__", "__CWD__").strip().splitlines()
    cwd = _section(raw, "__CWD__", "__CMDLINE__").strip()
    cmdline = _section(raw, "__CMDLINE__", "__GPU__").strip()
    gpu = _section(raw, "__GPU__", "__ARTIFACTS__").strip()
    related = [line.strip() for line in _section(raw, "__RELATED_GPU_PIDS__", "__ARTIFACTS__").splitlines() if line.strip().isdigit()]
    artifact_part = _section(raw, "__ARTIFACTS__", "__CSV_PATH__")
    csv_path = _section(raw, "__CSV_PATH__", "__CSV__").strip()
    csv_text = _section(raw, "__CSV__", "__CONFIG__")
    config_text = _section(raw, "__CONFIG__")
    if not process:
        return f"【{name} · 训练进程】无法读取 PID {intent.target} 的状态。"
    values = process[0].split(maxsplit=8)
    status_items = []
    if len(values) >= 9:
        _, pid, ppid, pgid, state, elapsed, cpu, memory, command = values
        state_text = "异常" if state.startswith(("D", "Z")) else "运行中"
        status_items = [
            f"PID：{pid} · {state_text} · 程序 {command}",
            f"父进程：{ppid} · 进程组：{pgid}",
            f"CPU：{cpu}% · 内存：{memory}% · 已运行 {elapsed}",
        ]
    if cwd and intent.detail == "detail":
        status_items.append(f"工作目录：{cwd}")
    if gpu:
        status_items.append(f"GPU 显存：{gpu.splitlines()[0].strip()} MiB")
    if len(related) > 1:
        status_items.append("同一工作目录的 GPU 进程：" + "、".join(f"PID {item}" for item in related))
    blocks = ["进程状态\n" + _mobile_items(status_items)]
    if cmdline and intent.detail == "detail":
        blocks.append("启动信息\n• " + cmdline[:360])
    if csv_text:
        errors = len(_ERROR_PATTERN.findall(csv_text))
        analysis = analyze_results_csv(
            csv_text,
            total_epochs=total_epochs_from_text(config_text),
            process_alive=True,
            error_count=errors,
        )
        analysis_text = _training_summary(
            name,
            analysis,
            run_path=csv_path or cwd or None,
            artifacts=_parse_artifact_rows(artifact_part),
            detail=intent.detail,
            prefix="训练结果",
        )
        blocks.append(analysis_text)
    elif artifact_part:
        blocks.append("发现的训练产物\n" + _mobile_items(_parse_artifact_rows(artifact_part)[:8]))
    return f"【{name} · PID {intent.target} · 训练详情】\n" + "\n\n".join(blocks)


def _format_path_inspect(name: str, intent: OperationIntent, raw: str) -> str:
    if "__ERROR__" in raw:
        return _format_file_error(name, intent.target, raw)
    path = _section(raw, "__PATH__", "__META__").splitlines()[0] if "__PATH__" in raw else intent.target
    type_line = _section(raw, "__TYPE__").splitlines()[0]
    if "directory" in type_line:
        entries = []
        for line in _section(raw, "__ENTRIES__", "__TRAINING_CSV_PATH__").splitlines()[:20]:
            values = line.split("|", 3)
            if len(values) == 4:
                kind, size, modified, filename = values
                entries.append(f"{'目录' if kind == 'd' else '文件'}：{filename}" + (f"（{_as_int(size) / 1024:.0f} KB）" if kind != "d" else ""))
        csv_text = _section(raw, "__TRAINING_CSV__", "__CONFIG__")
        if csv_text:
            active_pids = [line.strip() for line in _section(raw, "__ACTIVE_PIDS__", "__TRAINING_CSV_PATH__").splitlines() if line.strip().isdigit()]
            analysis = analyze_results_csv(
                csv_text,
                total_epochs=total_epochs_from_text(_section(raw, "__CONFIG__")),
                process_alive=bool(active_pids),
            )
            return _training_summary(
                name,
                analysis,
                run_path=_section(raw, "__TRAINING_CSV_PATH__", "__TRAINING_CSV__").strip() or path,
                artifacts=entries,
                detail=intent.detail,
                prefix=f"【{name} · 训练目录】",
            )
        title = f"【{name} · 目录检查】\n• 路径：{path}\n• 类型：目录"
        return title + ("\n\n目录内容\n" + _mobile_items(entries) if entries else "\n• 目录为空或没有可显示内容")

    meta = _kv_and_rows(_section(raw, "__META__", "__TRAINING_CSV__"), marker="__NEVER__")[0]
    base = [f"路径：{path}", f"大小：{_as_int(meta.get('size')) / 1024:.0f} KB", f"类型：{meta.get('mime', '未知')}"]
    csv_text = _section(raw, "__TRAINING_CSV__")
    if csv_text:
        analysis = analyze_results_csv(csv_text, last_update=meta.get("modified"))
        return _training_summary(name, analysis, run_path=path, detail=intent.detail, prefix=f"【{name} · 训练文件】")
    artifact = _section(raw, "__ARTIFACT__").strip()
    if artifact:
        base.append("用途：模型权重或训练图片（仅返回元数据，未读取二进制内容）")
    log_text = _section(raw, "__LOG__") or _section(raw, "__TEXT__")
    if log_text:
        lines = [_SECRET_PATTERN.sub(r"\1\2<redacted>", line.strip())[:220] for line in log_text.splitlines()[-20:] if line.strip()]
        base.append("最近内容\n" + _mobile_items(lines))
        errors = [line for line in lines if _ERROR_PATTERN.search(line)]
        if errors:
            base.append(f"异常提示：发现 {len(errors)} 条错误关键词日志")
    return f"【{name} · 路径检查】\n" + _mobile_items(base)


def _format_training_overview(name: str, raw: str, detail: str = "summary") -> str:
    csv_text = _section(raw, "__CSV__", "__CONFIG__")
    if csv_text:
        project_part = _section(raw, "__PROJECTS__", "__RECENT_LOGS__")
        recent = _parse_artifact_rows(_section(raw, "__RECENT_LOGS__", "__LATEST_FILE__"))
        latest = _section(raw, "__LATEST_FILE__", "__CSV__")
        path = ""
        modified = ""
        for line in latest.splitlines():
            if line.startswith("path="):
                path = line.split("=", 1)[1]
            elif line.startswith("modified="):
                modified = line.split("=", 1)[1]
        config_text = _section(raw, "__CONFIG__")
        analysis = analyze_results_csv(
            csv_text,
            total_epochs=total_epochs_from_text(config_text),
            process_alive=any(line.split("|", 1)[0].strip().isdigit() for line in project_part.splitlines()),
            error_count=len(_ERROR_PATTERN.findall(csv_text)),
            last_update=modified or None,
        )
        project_groups: dict[str, list[str]] = {}
        for line in project_part.splitlines():
            if "|" in line and line.split("|", 1)[0].strip().isdigit():
                pid, project = line.split("|", 1)
                project_groups.setdefault(project, []).append(pid.strip())
        project_items = [
            f"GPU 任务 PID {'、'.join(pids)}：{project}"
            for project, pids in project_groups.items()
        ]
        return _training_summary(
            name,
            analysis,
            run_path=path or (project_items[0].split("：", 1)[1] if project_items else None),
            artifacts=project_items + recent,
            detail=detail,
        )
    gpu_part, _, remainder = raw.partition("__PROJECTS__")
    project_part, _, remainder = remainder.partition("__RECENT_LOGS__")
    logs_part, _, latest_part = remainder.partition("__LATEST_LOG__")
    gpu_rows = []
    for line in gpu_part.splitlines():
        values = [value.strip() for value in line.split(",")]
        if len(values) == 4:
            index, util, used, total = values
            gpu_rows.append(f"GPU {index}：{util}% · {_as_float(used) / 1024:.1f} / {_as_float(total) / 1024:.1f} GB")
    candidates = []
    for line in logs_part.splitlines()[:5]:
        values = line.split("|", 2)
        if len(values) == 3:
            _, size, path = values
            candidates.append(f"{Path(path).name}（{_as_int(size) / 1024:.0f} KB）")

    projects = []
    for line in project_part.splitlines():
        values = line.split("|", 1)
        if len(values) == 2:
            pid, cwd = values
            projects.append(f"PID {pid}：{cwd}")

    metric_lines = latest_part.splitlines()
    metadata = {}
    content = []
    in_content = False
    for line in metric_lines:
        if line.startswith(("path=", "modified=", "size=")) and not in_content:
            key, value = line.split("=", 1)
            metadata[key] = value
        else:
            in_content = True
            content.append(line)
    joined = "\n".join(content)
    patterns = {
        "Epoch": r"(?i)epoch\s*[:=]?\s*(\d+)\s*(?:/|of)\s*(\d+)?",
        "Step": r"(?i)(?:global_)?step\s*[:=]?\s*(\d+)",
        "Loss": r"(?i)(?:train[_ ]?)?loss\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)",
        "Episode": r"(?i)episode\s*[:=]?\s*(\d+)",
        "Success": r"(?i)success[_ ]?rate\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)",
    }
    facts = []
    for label, pattern in patterns.items():
        found = re.findall(pattern, joined)
        if found:
            value = found[-1]
            facts.append(f"{label}：{' / '.join(value) if isinstance(value, tuple) else value}")
    csv_rows = []
    try:
        parsed_rows = list(csv.reader(io.StringIO(joined)))
        header_index = next(
            (index for index, row in enumerate(parsed_rows) if row and row[0].strip().lower() == "epoch"),
            None,
        )
        if header_index is not None:
            header = [column.strip() for column in parsed_rows[header_index]]
            data_rows = [row for row in parsed_rows[header_index + 1:] if row and row[0].strip().isdigit()]
            if data_rows:
                latest = data_rows[-1]
                values = dict(zip(header, latest))
                csv_rows.append(f"Epoch：{latest[0].strip()}")
                for column, label in (
                    ("train/box_loss", "Box Loss"),
                    ("train/cls_loss", "Cls Loss"),
                    ("metrics/mAP50(B)", "mAP50"),
                    ("metrics/mAP50-95(B)", "mAP50-95"),
                ):
                    if values.get(column, "").strip():
                        csv_rows.append(f"{label}：{values[column].strip()}")
    except (csv.Error, ValueError):
        csv_rows = []
    if csv_rows:
        facts = csv_rows
    errors = len(_ERROR_PATTERN.findall(joined))
    blocks = []
    if gpu_rows:
        blocks.append("GPU\n" + _mobile_items(gpu_rows))
    if projects:
        blocks.append("GPU 任务工作目录\n" + _mobile_items(projects[:4]))
    if facts:
        blocks.append("最新训练指标\n" + _mobile_items(facts))
    if metadata.get("path"):
        blocks.append(f"最近训练日志：{Path(metadata['path']).name}\n更新时间：{metadata.get('modified', '未知')}")
    elif candidates:
        blocks.append("最近发现的训练日志\n" + _mobile_items(candidates))
    if errors:
        blocks.append(f"风险提示：最近日志片段匹配到 {errors} 个错误关键词，建议进一步查看具体日志。")
    if not blocks:
        return f"【{name} · 训练概览】未发现 GPU 数据或可识别的训练日志。"
    return f"【{name} · 训练概览】\n" + "\n\n".join(blocks) + "\n\n说明：未登记项目规则时，只能识别通用 Epoch、Step、Loss，不能保证代表全部训练任务。"


def _format_file_list(name: str, intent: OperationIntent, raw: str) -> str:
    if "__ERROR__" in raw:
        return _format_file_error(name, intent.target, raw)
    _, _, content = raw.partition("__FILES__")
    rows = []
    for line in content.splitlines()[:40]:
        kind, size, modified, filename = (line.split("|", 3) + ["", "", "", ""])[:4]
        if not filename:
            continue
        kind_text = "目录" if kind == "d" else "文件"
        size_text = "" if kind == "d" else f" · {_as_int(size) / 1024:.0f} KB"
        rows.append(f"{kind_text}：{filename}{size_text}\n  修改时间 {modified}")
    if not rows:
        return f"【{name} · 文件目录】目录为空或没有可显示的普通文件。"
    suffix = "\n… 已限制显示前 40 项。" if len(content.splitlines()) > 40 else ""
    return f"【{name} · 文件目录】{intent.target}\n" + _mobile_items(rows) + suffix


def _format_file_error(name: str, path: str | None, raw: str) -> str:
    code = raw.rsplit("|", 1)[-1].strip()
    messages = {
        "path_not_found": "路径不存在。",
        "outside_read_root": "路径不在允许读取范围内。",
        "sensitive_path": "该路径包含敏感数据，已拒绝读取。",
        "not_a_directory": "目标不是目录。",
        "not_a_regular_file": "目标不是普通文件。",
        "file_too_large": "文件超过 2 MB 预览上限。",
        "non_text_file": "只支持文本、JSON、XML 或 YAML 文件预览。",
    }
    return f"【{name} · 文件查询】{messages.get(code, '该文件查询无法执行。')}"


def _format_file_preview(name: str, intent: OperationIntent, raw: str) -> str:
    if "__ERROR__" in raw:
        return _format_file_error(name, intent.target, raw)
    meta_part, _, content = raw.partition("__CONTENT__")
    metadata, _ = _kv_and_rows(meta_part, marker="__NEVER__")
    lines = []
    for line in content.splitlines()[-40:]:
        clean = _SECRET_PATTERN.sub(r"\1\2<redacted>", line.strip())[:220]
        if clean:
            lines.append(clean)
    header = (
        f"【{name} · 文件预览】{Path(metadata.get('path', intent.target or '')).name}\n"
        f"大小：{_as_int(metadata.get('size')) / 1024:.0f} KB · 类型：{metadata.get('mime', '未知')}"
    )
    return header + ("\n\n最后内容\n" + "\n".join(f"- {line}" for line in lines) if lines else "\n\n文件为空。")


def _format_java_log_sources(name: str, intent: OperationIntent, raw: str) -> str:
    if "__PID__|" not in raw:
        target = "Java 进程" if intent.target == "all" else f"Java PID {intent.target}"
        return f"【{name} · Java 日志】未找到正在运行的{target}。"
    lines = raw.splitlines()
    blocks: list[tuple[str, list[str]]] = []
    current_pid: str | None = None
    current_paths: list[str] = []
    for line in lines:
        if line.startswith("__PID__|"):
            if current_pid is not None:
                blocks.append((current_pid, current_paths))
            current_pid = line.split("|", 1)[1].strip()
            current_paths = []
        elif current_pid is not None:
            clean = line.strip()
            if clean and clean.startswith("/"):
                current_paths.append(clean)
    if current_pid is not None:
        blocks.append((current_pid, current_paths))
    sections = []
    for pid, paths in blocks:
        if paths:
            sections.append(f"• PID {pid}\n" + "\n".join(f"  - {path}" for path in paths[:12]))
        else:
            sections.append(f"• PID {pid}\n  - 未从已打开文件描述符发现日志路径")
    return f"【{name} · Java 日志来源】\n" + "\n\n".join(sections)


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


def _command_for(intent: OperationIntent, config: dict | None = None) -> str:
    if intent.operation in READONLY_COMMANDS:
        return READONLY_COMMANDS[intent.operation]
    if intent.operation == "process_detail":
        return _process_detail_command(intent)
    if intent.operation == "process_training":
        if intent.server_id != "server1":
            raise GatewayError("指定进程训练分析目前仅在 AI GPU服务器1 开放。")
        return _process_training_command(intent)
    if intent.operation == "java_log_sources":
        return _java_log_sources_command(intent)
    if intent.operation == "training_overview":
        if intent.server_id != "server1":
            raise GatewayError("训练概览目前仅在 AI GPU服务器1 开放。")
        return _training_overview_command(intent.target, config)
    if intent.operation == "service_status":
        return _service_status_command(intent.target)
    if intent.operation == "service_logs":
        return _service_log_command(intent.target, lines=30)
    if intent.operation == "service_errors":
        return _service_log_command(intent.target, lines=240)
    if intent.operation == "file_list":
        if config is None:
            raise GatewayError("文件查询缺少服务器配置。")
        return _file_list_command(_validate_read_path(intent.target, config), config)
    if intent.operation == "path_inspect":
        if config is None:
            raise GatewayError("路径查询缺少服务器配置。")
        return _path_inspect_command(_validate_read_path(intent.target, config), config)
    if intent.operation == "file_preview":
        if config is None:
            raise GatewayError("文件查询缺少服务器配置。")
        return _file_preview_command(_validate_read_path(intent.target, config), config)
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
    if intent.operation == "gpu_overview":
        return _format_gpu(name, raw)
    if intent.operation == "gpu_processes":
        return _format_gpu_processes(name, raw)
    if intent.operation == "process_detail":
        return _format_process_detail(name, intent, raw)
    if intent.operation == "process_training":
        return _format_process_training(name, intent, raw)
    if intent.operation == "training_overview":
        return _format_training_overview(name, raw, intent.detail)
    if intent.operation == "middleware_overview":
        return _format_middleware(name, raw)
    if intent.operation == "java_log_sources":
        return _format_java_log_sources(name, intent, raw)
    if intent.operation == "service_status" and intent.target:
        return _format_service_status(name, intent.target, raw)
    if intent.operation == "service_logs" and intent.target:
        return _format_logs(name, intent.target, raw)
    if intent.operation == "service_errors" and intent.target:
        return _format_service_errors(name, intent.target, raw)
    if intent.operation == "file_list":
        return _format_file_list(name, intent, raw)
    if intent.operation == "path_inspect":
        return _format_path_inspect(name, intent, raw)
    if intent.operation == "file_preview":
        return _format_file_preview(name, intent, raw)
    raise GatewayError("没有对应的结果格式化器")


async def execute_readonly(
    intent: OperationIntent,
    actor_id: str,
    visible_server_ids: list[str],
) -> str:
    if intent.operation == "inventory":
        _write_audit(intent, actor_id, "success", 0)
        return _format_inventory(visible_server_ids)
    if intent.server_id not in visible_server_ids:
        write_denied_audit(intent, actor_id)
        raise GatewayError("服务器不在当前用户的授权范围内")
    if intent.operation == "select_server":
        config = _server_config(intent.server_id)
        _write_audit(intent, actor_id, "success", 0)
        return f"已切换到【{config['name']}】。后续未指定服务器时默认查询它。"

    config = _server_config(intent.server_id)
    command = _command_for(intent, config)
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
