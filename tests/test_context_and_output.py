import asyncio

import pytest

from aisshbot.intent import OperationIntent, detect_intent
from aisshbot.intent_planner import plan_operation
from aisshbot.memory import ShortTermMemory
from aisshbot.ops_gateway import (
    GatewayError,
    _command_for,
    _format_file_preview,
    _format_gpu_processes,
    _format_gpu,
    _format_health,
    _format_java_log_sources,
    _format_path_inspect,
    _format_process_training,
    _format_processes,
    _format_service_status,
)
from aisshbot.router import classify
from aisshbot.training import analyze_results_csv


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
    assert inherited.operation == "gpu_overview"

    follow_up = memory.apply("alice", None, "有异常吗？")
    assert follow_up.server_id == "server2"
    assert follow_up.operation == "health"


def test_short_term_memory_keeps_training_objects_for_followups():
    memory = ShortTermMemory()
    intent = OperationIntent(
        "process_training",
        "server1",
        target="258292",
        target_type="pid",
    )
    memory.remember("alice", "查看 PID 258292 的训练情况", "第 10 轮", intent)
    context = memory.get("alice")
    assert context.last_pid == "258292"
    follow_up = memory.apply("alice", None, "它最近十轮效果怎么样？")
    assert follow_up is not None
    assert follow_up.operation == "process_training"
    assert follow_up.target == "258292"


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

    assert "systemctl is-active \"$unit\"" in _command_for(
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


def test_deep_diagnostics_intents_and_safe_file_access():
    assert detect_intent("服务器1占用GPU的进程是哪两个").operation == "gpu_processes"
    assert detect_intent("训练进度怎么样").operation == "training_overview"
    assert detect_intent("查看 /home/uav/project/train.log 最后内容").operation == "file_preview"
    assert detect_intent("列出 /home/uav/project 的文件").operation == "file_list"
    assert detect_intent("Java日志有没有").operation == "java_log_sources"
    assert detect_intent("Java日志有没有").target == "all"
    assert detect_intent("查看/home/uav/train.py内容").target == "/home/uav/train.py"

    config = {
        "read_roots": ["/home/uav"],
        "denied_read_patterns": ["/home/uav/**/.ssh/*"],
    }
    command = _command_for(OperationIntent("file_preview", "server1", target="/home/uav/project/train.log"), config)
    assert "tail -n 60" in command
    assert "/home/uav/project/train.log" in command
    with pytest.raises(GatewayError):
        _command_for(OperationIntent("file_preview", "server1", target="/home/uav/../etc/shadow"), config)
    with pytest.raises(GatewayError):
        _command_for(OperationIntent("file_preview", "server1", target="/home/uav/.ssh/id_rsa"), config)


def test_gpu_process_and_file_preview_redact_secrets():
    gpu = _format_gpu_processes(
        "AI GPU服务器1",
        "__GPU_PROCESSES__\n19298|uav 258292 1 Sl 01:12:20 89.4 1.9 python\n",
    )
    assert "python（PID 258292）" in gpu
    assert "GPU 显存 19298 MiB" in gpu

    preview = _format_file_preview(
        "AI GPU服务器1",
        OperationIntent("file_preview", "server1", target="/home/uav/project/train.log"),
        "__META__\npath=/home/uav/project/train.log\nsize=200\nmime=text/plain\n__CONTENT__\ntoken=abc123\nEpoch 2/10 loss=0.12\n",
    )
    assert "token=<redacted>" in preview
    assert "Epoch 2/10" in preview


def test_java_log_sources_supports_all_running_java_processes():
    output = _format_java_log_sources(
        "阿里云服务器",
        OperationIntent("java_log_sources", "server2", target="all"),
        "__JAVA_LOG_SOURCES__\n"
        "__PID__|10984\n"
        "root 10984 1 Sl 2-03:19:12 0.2 19.9 java\n"
        "/opt/sensor-stack/test-yudao/logs/startup.log\n"
        "__PID__|25252\n"
        "root 25252 1 Sl 40-01:00:00 0.1 8.0 java\n"
        "/data/sensor/logs/yudao-server.log\n",
    )
    assert "PID 10984" in output
    assert "PID 25252" in output
    assert "startup.log" in output


def test_training_analyzer_finds_latest_and_best_results():
    csv_text = (
        "epoch,train/box_loss,train/cls_loss,metrics/mAP50(B),metrics/mAP50-95(B)\n"
        "1,2.0,1.0,0.20,0.10\n"
        "2,1.8,0.8,0.30,0.20\n"
        "3,1.6,0.7,0.35,0.25\n"
    )
    analysis = analyze_results_csv(csv_text, total_epochs=10, process_alive=True)
    assert analysis.current_epoch == 3
    assert analysis.progress_percent == 30
    assert analysis.best_epoch == 3
    assert analysis.latest_metrics["map5095"] == "0.25"
    assert analysis.status == "RUNNING"
    assert analysis.trend == "improving"


def test_path_inspect_and_process_training_formatters_are_concise():
    directory_raw = (
        "__TYPE__|directory\n__PATH__|/home/uav/gu/runs/demo\n__ENTRIES__\n"
        "d|0|2026-07-16 10:00|weights\n"
        "f|123|2026-07-16 10:01|results.csv\n"
        "__TRAINING_CSV_PATH__\n/home/uav/gu/runs/demo/results.csv\n"
        "__TRAINING_CSV__\n"
        "epoch,train/box_loss,metrics/mAP50(B),metrics/mAP50-95(B)\n"
        "1,1.0,0.5,0.3\n2,0.8,0.6,0.4\n"
    )
    directory = _format_path_inspect(
        "AI GPU服务器1",
        OperationIntent("path_inspect", "server1", target="/home/uav/gu/runs/demo", target_type="path"),
        directory_raw,
    )
    assert "训练目录" in directory
    assert "第 2 / ? 轮" in directory

    process_raw = (
        "__PROCESS__\n"
        "uav 258292 258288 258288 Ssl 13:00:00 89.4 1.9 python\n"
        "__CWD__\n/home/uav/gu/runs/demo\n"
        "__CMDLINE__\npython train.py --token <redacted>\n"
        "__GPU__\n18098\n"
        "__ARTIFACTS__\n1|123456|/home/uav/gu/runs/demo/results.csv\n"
        "__CSV_PATH__\n/home/uav/gu/runs/demo/results.csv\n"
        "__CSV__\n"
        "epoch,train/box_loss,metrics/mAP50(B),metrics/mAP50-95(B)\n"
        "1,1.0,0.5,0.3\n2,0.8,0.6,0.4\n"
        "__CONFIG__\nepochs: 10\n"
    )
    process = _format_process_training(
        "AI GPU服务器1",
        OperationIntent("process_training", "server1", target="258292", target_type="pid"),
        process_raw,
    )
    assert "第 2 / 10 轮" in process
    assert "GPU 显存：18098 MiB" in process
    assert "--token <redacted>" in process
