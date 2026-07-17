"""Audit plan/tool/result metadata without raw credentials or full output."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    principal_id: str
    server_id: str
    event_type: str
    status: str
    tool: str | None = None
    parameter_hash: str | None = None
    result_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryAuditRecorder:
    def __init__(self):
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def list(self, request_id: str | None = None) -> tuple[AuditEvent, ...]:
        with self._lock:
            events = tuple(self._events)
        return tuple(event for event in events if request_id is None or event.request_id == request_id)
