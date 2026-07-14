import json
from pathlib import Path

from aisshbot.access_control import AccessPolicy
from aisshbot.intent import detect_intent


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
