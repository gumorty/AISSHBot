"""Whitelist-only server inspection gateway.

This module intentionally has no arbitrary-shell, upload, delete, restart, or
write operation. Add any future change action as a separately reviewed template.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from .intent import OperationIntent


class GatewayError(RuntimeError):
    pass


READONLY_COMMANDS = {
    "health": "hostname; nproc; uptime; free -h; df -h -x tmpfs -x devtmpfs",
    "processes": "ps -eo user,pid,ppid,stat,etime,%cpu,%mem,comm --sort=-%cpu | head -n 31",
    "java_status": "ps -eo user,pid,ppid,stat,etime,%cpu,%mem,comm --sort=-%cpu | awk 'NR==1 || tolower($0) ~ /java/' | head -n 21",
    "paper_progress": "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader; ps -eo user,pid,stat,etime,%cpu,%mem,comm --sort=-%cpu | head -n 21",
}


class ReadonlyGateway:
    def __init__(self, root: Path):
        self.root = root
        self.servers_file = root / "data" / "servers.json"
        self.credentials_file = root / "secrets" / "server_credentials.json"
        self.audit_file = root / "data" / "ops_audit.jsonl"

    def _load(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise GatewayError("AISSHBot 运行配置不可用") from exc

    def _audit(self, actor_id: str, intent: OperationIntent, status: str, exit_code: int | None = None) -> None:
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "actor_id": actor_id,
                  "server_id": intent.server_id, "operation": intent.operation,
                  "status": status, "exit_code": exit_code}
        with self.audit_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    @staticmethod
    def _run_local(command: str) -> tuple[int, str]:
        completed = subprocess.run(["/bin/bash", "-c", command], capture_output=True, text=True,
                                   timeout=15, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
        return completed.returncode, (completed.stdout + ("\n" + completed.stderr if completed.stderr else "")).strip()

    def _run_ssh(self, server: dict, command: str) -> tuple[int, str]:
        known_hosts = self.root / server["known_hosts"]
        if not known_hosts.exists():
            raise GatewayError("目标服务器尚未配置可信 SSH 主机公钥；为防止中间人攻击，已拒绝连接。")
        credential = self._load(self.credentials_file)[server["credential_ref"]]
        client = paramiko.SSHClient()
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(hostname=server["host"], port=int(server.get("port", 22)), username=server["username"],
                           password=credential["password"], look_for_keys=False, allow_agent=False,
                           timeout=10, banner_timeout=10, auth_timeout=10)
            _, stdout, stderr = client.exec_command(command, timeout=15)
            output = stdout.read().decode("utf-8", errors="replace").strip()
            error = stderr.read().decode("utf-8", errors="replace").strip()
            return stdout.channel.recv_exit_status(), (output + ("\n" + error if error else "")).strip()
        finally:
            client.close()

    async def execute(self, actor_id: str, intent: OperationIntent, visible_servers: list[str]) -> str:
        if intent.server_id not in visible_servers:
            self._audit(actor_id, intent, "denied")
            raise GatewayError("服务器不在当前用户授权范围内")
        servers = self._load(self.servers_file)
        if intent.operation == "inventory":
            names = [f"- {servers[item]['name']}（{item}）" for item in visible_servers if item in servers]
            self._audit(actor_id, intent, "success", 0)
            return "当前你有权限访问的服务器：\n" + "\n".join(names)
        if intent.operation not in READONLY_COMMANDS:
            self._audit(actor_id, intent, "denied")
            raise GatewayError("操作不在只读白名单中")
        server = servers.get(intent.server_id)
        if not server:
            self._audit(actor_id, intent, "failed")
            raise GatewayError("服务器配置不存在")
        try:
            if server["transport"] == "local":
                code, output = await asyncio.to_thread(self._run_local, READONLY_COMMANDS[intent.operation])
            elif server["transport"] == "ssh":
                code, output = await asyncio.to_thread(self._run_ssh, server, READONLY_COMMANDS[intent.operation])
            else:
                raise GatewayError("不支持的连接类型")
        except Exception:
            self._audit(actor_id, intent, "failed")
            raise
        self._audit(actor_id, intent, "success" if code == 0 else "command_error", code)
        lines = [line.rstrip() for line in output.splitlines() if line.strip()][:24]
        return f"【{server['name']}】\n" + ("\n".join(lines) or "没有采集到数据。")
