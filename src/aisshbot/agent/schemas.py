"""Stable, serializable contracts shared by planner, tools and execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ObjectRef:
    """A user-owned server object referenced by a plan or a follow-up."""

    type: str
    id: str
    server_id: str
    project_id: str | None = None
    canonical_path: str | None = None
    source: str = "user"
    owner_id: str | None = None
    observed_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None

    def expired(self, now: datetime | None = None) -> bool:
        return self.expires_at is not None and (now or utc_now()) >= self.expires_at


@dataclass(frozen=True)
class PlannedStep:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    step_id: str | None = None
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolPlan:
    request_id: str
    principal_id: str
    server_id: str
    goal: str
    object_ref: ObjectRef | None = None
    steps: tuple[PlannedStep, ...] = ()
    response_focus: tuple[str, ...] = ()
    max_steps: int = 6
    max_tool_calls: int = 12
    confidence: float = 1.0
    source: str = "rules"

    def step_count(self) -> int:
        return len(self.steps)


@dataclass(frozen=True)
class ExecutionContext:
    """Explicit request context; never rely on thread-local session state."""

    request_id: str
    principal_id: str
    channel: str
    conversation_id: str
    server_id: str
    roles: frozenset[str] = frozenset({"viewer"})
    project_ids: frozenset[str] = frozenset()
    path_scopes: tuple[str, ...] = ()
    allowed_server_ids: frozenset[str] = frozenset()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    request_id: str
    step_id: str
    tool: str
    args: dict[str, Any]
    server_id: str


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()
    error: str | None = None
    exit_code: int | None = None
    elapsed_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == "SUCCESS"

    def summary(self, max_chars: int = 300) -> str:
        if self.error:
            return f"{self.tool_name}: {self.status} ({self.error[:max_chars]})"
        text = str(self.data)
        return f"{self.tool_name}: {self.status} {text[:max_chars]}"
