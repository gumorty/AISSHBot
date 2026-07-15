"""Identity binding and least-privilege server-operation authorization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_FILE = PROJECT_ROOT / "data" / "access_policy.json"


class AccessError(RuntimeError):
    """The local authorization policy cannot be read safely."""


@dataclass(frozen=True)
class Principal:
    user_id: str
    display_name: str
    grants: dict


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    principal: Principal | None = None


def equivalent_external_ids(external_id: str) -> set[str]:
    """Normalize the official WeChat ID and LangBot's ``person_`` session ID."""
    value = str(external_id or "")
    if not value:
        return set()
    if value.startswith("person_"):
        return {value, value.removeprefix("person_")}
    return {value, f"person_{value}"}


def _load_policy(policy_file: Path = POLICY_FILE) -> dict:
    try:
        return json.loads(policy_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AccessError("访问控制策略不可用") from exc


def _resolve(policy: dict, platform: str, external_id: str) -> Principal | None:
    presented = equivalent_external_ids(external_id)
    for user in policy.get("users", []):
        for identity in user.get("identities", []):
            if identity.get("platform") == platform and identity.get("external_id") in presented:
                return Principal(
                    user_id=user["user_id"],
                    display_name=user.get("display_name", user["user_id"]),
                    grants=user.get("grants", {}),
                )
    return None


def resolve_principal(platform: str, external_id: str) -> Principal | None:
    return _resolve(_load_policy(), platform, external_id)


def allowed_server_ids(principal: Principal) -> list[str]:
    return sorted(principal.grants)


def authorize(principal: Principal | None, server_id: str, operation: str) -> AccessDecision:
    if principal is None:
        return AccessDecision(False, "该微信账号尚未绑定 AISSHBot 用户。")
    if operation == "inventory":
        if principal.grants:
            return AccessDecision(True, "allowed", principal)
        return AccessDecision(False, "你当前没有获授权的服务器。", principal)
    grant = principal.grants.get(server_id)
    if grant is None:
        return AccessDecision(False, "你没有访问该服务器的权限。", principal)
    if operation == "select_server" or operation in grant.get("operations", []):
        return AccessDecision(True, "allowed", principal)
    return AccessDecision(False, "你没有执行该运维操作的权限。", principal)


class AccessPolicy:
    """Injectable policy facade used by tests and standalone adapters."""

    def __init__(self, policy_file: Path):
        self.policy_file = policy_file

    def resolve_principal(self, platform: str, external_id: str) -> Principal | None:
        return _resolve(_load_policy(self.policy_file), platform, external_id)

    @staticmethod
    def visible_servers(principal: Principal) -> list[str]:
        return allowed_server_ids(principal)

    @staticmethod
    def authorize(principal: Principal | None, server_id: str, operation: str) -> AccessDecision:
        return authorize(principal, server_id, operation)
