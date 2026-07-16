"""Small per-user short-term memory for contextual server operations."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field, replace

from .intent import OperationIntent


@dataclass(frozen=True)
class MemoryTurn:
    question: str
    answer: str
    operation: str
    server_id: str
    target: str | None = None
    target_type: str | None = None


@dataclass
class SessionContext:
    last_server_id: str | None = None
    last_operation: str | None = None
    last_target: str | None = None
    last_pid: str | None = None
    last_path: str | None = None
    last_project: str | None = None
    last_training_run: str | None = None
    last_artifact: str | None = None
    last_service: str | None = None
    turns: list[MemoryTurn] = field(default_factory=list)
    updated_at: float = field(default_factory=time.monotonic)


class ShortTermMemory:
    """In-process memory; no external identifiers or credentials are stored."""

    def __init__(self, ttl_seconds: int = 1800, max_turns: int = 6):
        self.ttl_seconds = ttl_seconds
        self.max_turns = max_turns
        self._items: dict[str, SessionContext] = {}
        self._lock = threading.Lock()

    def get(self, user_id: str) -> SessionContext:
        now = time.monotonic()
        with self._lock:
            context = self._items.get(user_id)
            if context is None or now - context.updated_at > self.ttl_seconds:
                context = SessionContext(updated_at=now)
                self._items[user_id] = context
            return SessionContext(
                last_server_id=context.last_server_id,
                last_operation=context.last_operation,
                last_target=context.last_target,
                last_pid=context.last_pid,
                last_path=context.last_path,
                last_project=context.last_project,
                last_training_run=context.last_training_run,
                last_artifact=context.last_artifact,
                last_service=context.last_service,
                turns=list(context.turns),
                updated_at=context.updated_at,
            )

    def apply(self, user_id: str, intent: OperationIntent | None, message: str) -> OperationIntent | None:
        """Apply the selected server and last operation to a short follow-up."""
        context = self.get(user_id)
        if intent is not None:
            if intent.assumed_server and context.last_server_id:
                return replace(intent, server_id=context.last_server_id, assumed_server=False)
            return intent

        normalized = "".join((message or "").lower().split())
        training_follow_up = any(word in normalized for word in (
            "训练", "实验", "epoch", "loss", "指标", "效果", "模型", "权重", "曲线", "最佳",
        ))
        if training_follow_up and context.last_pid and context.last_server_id:
            return OperationIntent(
                "process_training",
                context.last_server_id,
                False,
                target=context.last_pid,
                detail="summary",
                target_type="pid",
            )
        if training_follow_up and context.last_training_run and context.last_server_id:
            return OperationIntent(
                "training_overview",
                context.last_server_id,
                False,
                target=context.last_training_run,
                detail="summary",
                target_type="path",
            )
        if any(word in normalized for word in ("这个目录", "这个文件", "该目录", "该文件")) and context.last_path:
            return OperationIntent(
                "path_inspect",
                context.last_server_id or "server1",
                False,
                target=context.last_path,
                detail="summary",
                target_type="path",
            )
        follow_up = any(word in normalized for word in (
            "那它", "这个呢", "它呢", "继续", "再看", "有异常吗", "正常吗", "怎么样", "然后呢",
        ))
        if follow_up and context.last_server_id and context.last_operation:
            return OperationIntent(
                operation=context.last_operation,
                server_id=context.last_server_id,
                assumed_server=False,
                target=context.last_target,
                detail="summary",
            )
        return None

    def remember(
        self,
        user_id: str,
        message: str,
        answer: str,
        intent: OperationIntent,
    ) -> None:
        now = time.monotonic()
        turn = MemoryTurn(
            question=(message or "")[:300],
            answer=(answer or "")[:800],
            operation=intent.operation,
            server_id=intent.server_id,
            target=intent.target,
            target_type=intent.target_type,
        )
        with self._lock:
            context = self._items.get(user_id) or SessionContext()
            if intent.operation != "inventory":
                context.last_server_id = intent.server_id
            if intent.operation not in ("inventory", "select_server"):
                context.last_operation = intent.operation
                context.last_target = intent.target
            if intent.target_type == "pid" or intent.operation in ("process_detail", "process_training"):
                context.last_pid = intent.target
            if intent.target_type == "path" or intent.operation in ("path_inspect", "file_list", "file_preview"):
                context.last_path = intent.target
            if intent.operation in ("training_overview", "process_training"):
                context.last_training_run = intent.target or context.last_training_run
                context.last_project = intent.target or context.last_project
            if intent.target_type == "service" or intent.operation in ("service_status", "service_logs", "service_errors"):
                context.last_service = intent.target
            if intent.operation in ("file_preview", "file_list"):
                context.last_artifact = intent.target
            context.turns = (context.turns + [turn])[-self.max_turns :]
            context.updated_at = now
            self._items[user_id] = context

    def clear(self, user_id: str) -> None:
        with self._lock:
            self._items.pop(user_id, None)


SHORT_TERM_MEMORY = ShortTermMemory()
