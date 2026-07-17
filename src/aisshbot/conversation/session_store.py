"""TTL-bounded context keyed by principal, channel and conversation."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from ..agent.schemas import ObjectRef, ToolResult


@dataclass(frozen=True)
class SessionKey:
    principal_id: str
    channel: str
    conversation_id: str


@dataclass
class SessionState:
    active_server_id: str | None = None
    active_project_id: str | None = None
    active_process_ref: ObjectRef | None = None
    active_training_run_ref: ObjectRef | None = None
    active_path_ref: ObjectRef | None = None
    active_service_ref: ObjectRef | None = None
    recent_tool_results: list[ToolResult] = field(default_factory=list)
    recent_turns: list[tuple[str, str]] = field(default_factory=list)
    updated_at: float = field(default_factory=time.monotonic)


class SessionStore:
    def __init__(self, ttl_seconds: int = 1800, max_turns: int = 6, max_results: int = 12):
        self.ttl_seconds = ttl_seconds
        self.max_turns = max_turns
        self.max_results = max_results
        self._items: dict[SessionKey, SessionState] = {}
        self._lock = threading.RLock()

    def get(self, key: SessionKey) -> SessionState:
        now = time.monotonic()
        with self._lock:
            state = self._items.get(key)
            if state is None or now - state.updated_at > self.ttl_seconds:
                state = SessionState(updated_at=now)
                self._items[key] = state
            return self._copy(state)

    def update(self, key: SessionKey, state: SessionState) -> None:
        state.updated_at = time.monotonic()
        with self._lock:
            self._items[key] = self._copy(state)

    def record_turn(self, key: SessionKey, question: str, conclusion: str) -> None:
        state = self.get(key)
        state.recent_turns = (state.recent_turns + [(question[:300], conclusion[:800])])[-self.max_turns :]
        self.update(key, state)

    def record_tool_result(self, key: SessionKey, result: ToolResult) -> None:
        state = self.get(key)
        state.recent_tool_results = (state.recent_tool_results + [result])[-self.max_results :]
        self.update(key, state)

    def clear(self, key: SessionKey) -> None:
        with self._lock:
            self._items.pop(key, None)

    @staticmethod
    def _copy(state: SessionState) -> SessionState:
        return SessionState(
            active_server_id=state.active_server_id,
            active_project_id=state.active_project_id,
            active_process_ref=state.active_process_ref,
            active_training_run_ref=state.active_training_run_ref,
            active_path_ref=state.active_path_ref,
            active_service_ref=state.active_service_ref,
            recent_tool_results=list(state.recent_tool_results),
            recent_turns=list(state.recent_turns),
            updated_at=state.updated_at,
        )
