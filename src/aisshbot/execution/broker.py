"""Explicit argv-based execution; no implicit shell or thread-local session."""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Protocol

from ..agent.schemas import ExecutionContext
from ..security.redaction import redact_text


class UnsafeCommand(ValueError):
    pass


@dataclass(frozen=True)
class CommandSpec:
    program: str
    args: tuple[str, ...] = ()
    cwd: str | None = None
    timeout_seconds: int = 8
    max_output_bytes: int = 262_144

    def argv(self) -> list[str]:
        if not self.program or self.program.startswith("-"):
            raise UnsafeCommand("程序名非法")
        values = [self.program, *self.args]
        if any("\x00" in value for value in values):
            raise UnsafeCommand("命令参数包含 NUL")
        if any(re.search(r"(?:^|\s)(?:sudo|su|doas|pkexec)(?:\s|$)", value, re.I) for value in values):
            raise UnsafeCommand("自动提权被禁止")
        return values


@dataclass(frozen=True)
class ExecutionOutput:
    exit_code: int
    stdout: str
    stderr: str = ""
    timed_out: bool = False


class ExecutionBroker(Protocol):
    async def run(self, spec: CommandSpec, context: ExecutionContext) -> ExecutionOutput: ...


class LocalExecutionBroker:
    async def run(self, spec: CommandSpec, context: ExecutionContext) -> ExecutionOutput:
        argv = spec.argv()

        def execute() -> ExecutionOutput:
            try:
                completed = subprocess.run(
                    argv,
                    cwd=spec.cwd,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=spec.timeout_seconds,
                    check=False,
                )
                return ExecutionOutput(
                    completed.returncode,
                    redact_text(completed.stdout[: spec.max_output_bytes].decode("utf-8", "replace")),
                    redact_text(completed.stderr[: spec.max_output_bytes].decode("utf-8", "replace")),
                )
            except subprocess.TimeoutExpired as exc:
                stdout = (exc.stdout or b"")[: spec.max_output_bytes]
                stderr = (exc.stderr or b"")[: spec.max_output_bytes]
                return ExecutionOutput(-1, redact_text(stdout.decode("utf-8", "replace")), redact_text(stderr.decode("utf-8", "replace")), True)

        return await asyncio.to_thread(execute)
