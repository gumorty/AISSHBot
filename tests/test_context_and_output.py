import asyncio

import pytest

from aisshbot.intent import OperationIntent, detect_intent
from aisshbot.intent_planner import plan_operation
from aisshbot.memory import ShortTermMemory
from aisshbot.ops_gateway import (
    GatewayError,
    _command_for,
    _format_gpu,
    _format_health,
    _format_processes,
    _format_service_status,
)
from aisshbot.router import classify


def test_short_term_memory_inherits_server_and_isolates_users():
    memory = ShortTermMemory(ttl_seconds=1800, max_turns=3)
    memory.remember("alice", "查看阿里云CPU", "正常", OperationIntent("health", "server2"))
    alice = memory.get("alice")
    bob = memory.get("bob")
    assert alice.last_server_id == "server2"
    assert alice.last_operation == "health"
    assert bob.last_server_id is None

    inherited = memory.apply("alice", detect_intent("那它的GPU呢？"), "那它的GPU呢？")
    assert inherited.server_id == "server2"
    assert inherited.operation == "paper_progress"

    follow_up = memory.apply("alice", None, "有异常吗？")
    assert follow_up.server_id == "server2"
    assert follow_up.operation == "health"


def test_planner_uses_context_server_without_llm():
    memory = ShortTermMemory()
    memory.remember("u1", "查看阿里云", "正常", OperationIntent("health", "server2"))
    plan = asyncio.run(
        plan_operation(None, None, "那它的进程有多少？", ["server1", "server2"], memory.get("u1"))
    )
    assert plan.source == "rule"
    assert plan.intent.server_id == "server2"
    assert plan.intent.operation == "processes"
    assert plan.intent.detail == "count"


def test_fast_readonly_queries_do_not_emit_processing_ack():
    assert classify("查看服务器列表").requires_processing_ack is False
    assert classify("查看服务器1 GPU占用").requires_processing_ack is False
    assert classify("在服务器上做一个复杂部署").requires_processing_ack is True


def test_concise_process_and_gpu_output():
    process_raw = """total=321
account=210
abnormal=0
__ROWS__
uav 258292 Ssl 10:23:05 89.4 1.9 python
uav 258293 Ssl 10:23:05 76.7 1.4 python
uav 258636 Sl 10:22:59 3.7 0.9 pt_data_worker
"""
    count = _format_processes("AI GPU服务器1", process_raw, "count")
    assert "系统进程：321 个" in count
    assert "258292" not in count
    summary = _format_processes("AI GPU服务器1", process_raw, "summary")
    assert "python（PID 258292）" in summary
    assert "|" not in summary

    gpu_raw = """0, NVIDIA GeForce RTX 4090, 90, 19309, 46068
1, NVIDIA GeForce RTX 4090, 100, 19369, 49140
__APPS__
258292, /home/uav/env/bin/python, 19298
258293, /home/uav/env/bin/python, 19360
"""
    gpu = _format_gpu("AI GPU服务器1", gpu_raw)
    assert "GPU 0：高负载" in gpu
    assert "利用率 90% · 显存 18.9 / 45.0 GB" in gpu
    assert "计算任务：2 个（python）" in gpu
    assert "/home/uav" not in gpu
    assert "|" not in gpu

    medium_gpu = _format_gpu(
        "AI GPU服务器1",
        "0, NVIDIA GeForce RTX 4090, 53, 22000, 46068\n__APPS__\n1, /x/python, 21000",
    )
    assert "当前负载中等" in medium_gpu


def test_health_summary_and_service_target_allowlist():
    raw = """hostname=node1
cpu_cores=16
load1=1.25
uptime=up 3 days
mem_total_kb=33554432
mem_available_kb=16777216
disk_total_kb=104857600
disk_used_kb=52428800
disk_pct=50%
"""
    output = _format_health("node1", raw)
    assert "内存：16.0 / 32.0 GB（50%）" in output
    assert "结论：资源状态正常" in output

    assert "systemctl is-active nginx" in _command_for(
        OperationIntent("service_status", "server1", target="nginx")
    )
    service = _format_service_status(
        "阿里云服务器",
        "nginx",
        "service=nginx\nactive=inactive\nenabled=disabled\nmain_pid=0\n",
    )
    assert "当前状态为 inactive" in service
    assert "开机启动 disabled" in service
    with pytest.raises(GatewayError):
        _command_for(OperationIntent("service_status", "server1", target="nginx;id"))
