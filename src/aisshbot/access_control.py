"""Identity binding and least-privilege server-operation authorization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


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


def equivalent_external_ids(external_id: str) -> set[str]:
    """Normalize the official WeChat ID and LangBot's ``person_`` session ID."""
    value = str(external_id or "")
    if not value:
        return set()
    return {value, value.removeprefix("person_"), f"person_{value}"}


class AccessPolicy:
    def __init__(self, policy_file: Path):
        self.policy_file = policy_file

    def _load(self) -> dict:
        try:
            return json.loads(self.policy_file.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AccessError("访问控制策略不可用") from exc

    def resolve_principal(self, platform: str, external_id: str) -> Principal | None:
        presented = equivalent_external_ids(external_id)
        for user in self._load().get("users", []):
            for identity in user.get("identities", []):
                if identity.get("platform") == platform and identity.get("external_id") in presented:
                    return Principal(
                        user_id=user["user_id"],
                        display_name=user.get("display_name", user["user_id"]),
                        grants=user.get("grants", {}),
                    )
        return None

    @staticmethod
    def visible_servers(principal: Principal) -> list[str]:
        return sorted(principal.grants)

    @staticmethod
    def authorize(principal: Principal | None, server_id: str, operation: str) -> AccessDecision:
        if principal is None:
            return AccessDecision(False, "该聊天账号尚未绑定 AISSHBot 用户。")
        grant = principal.grants.get(server_id)
        if grant is None:
            return AccessDecision(False, "你没有访问该服务器的权限。")
        if operation == "inventory" or operation in grant.get("operations", []):
            return AccessDecision(True, "allowed")
        return AccessDecision(False, "你没有执行该运维操作的权限。")
