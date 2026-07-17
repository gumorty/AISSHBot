"""Execution-side redaction before data reaches prompts, logs or chat."""

from __future__ import annotations

import re


_SECRET = re.compile(
    r"(?i)(password|passwd|token|secret|authorization|api[_-]?key)"
    r"(\s*[=:]\s*)([^\s,;]+)"
)


def redact_text(value: str, replacement: str = "<redacted>") -> str:
    return _SECRET.sub(rf"\1\2{replacement}", value or "")
