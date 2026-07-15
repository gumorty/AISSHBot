import asyncio
import json
from pathlib import Path

from aisshbot.access_control import AccessPolicy, Principal, authorize
from aisshbot.intent import detect_intent
from aisshbot.intent_planner import plan_operation


def test_wechat_raw_and_session_ids_bind_to_same_user(tmp_path: Path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"users": [{"user_id": "u1", "identities": [
        {"platform": "openclaw-weixin", "external_id": "person_abc@im.wechat"}],
        "grants": {"server1": {"operations": ["health"]}}}]}), encoding="utf-8")
    policy = AccessPolicy(policy_path)
    assert policy.resolve_principal("openclaw-weixin", "person_abc@im.wechat") is not None
    assert policy.resolve_principal("openclaw-weixin", "abc@im.wechat") is not None
    assert policy.resolve_principal("openclaw-weixin", "other@im.wechat") is None


def test_rule_intents_never_return_shell_commands():
    assert detect_intent("查看 AI服务器1 CPU和内存").operation == "health"
    assert detect_intent("查看阿里云服务器 Java进程状态").operation == "java_status"
    assert detect_intent("我现在有什么服务器可以直接操作").operation == "inventory"
    process_intent = detect_intent("当前服务器运行几个进程？")
    assert process_intent.operation == "processes"
    assert process_intent.detail == "count"


def test_known_request_never_calls_fallback():
    plan = asyncio.run(plan_operation(None, None, "查看 AI服务器1 CPU和内存", ["server1"]))
    assert plan.intent.operation == "health"
    assert plan.source == "rule"


def test_inventory_does_not_depend_on_default_server():
    principal = Principal(
        user_id="u2",
        display_name="server2-only",
        grants={"server2": {"operations": ["health"]}},
    )
    assert authorize(principal, "server1", "inventory").allowed is True
    assert authorize(principal, "server1", "select_server").allowed is False
