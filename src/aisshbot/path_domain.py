"""Path classification contract used by file and training tools."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PathKind(StrEnum):
    DIRECTORY = "directory"
    TEXT = "text"
    CSV = "csv"
    IMAGE = "image"
    MODEL = "model"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PathInspection:
    path: str
    kind: PathKind
    size_bytes: int = 0
    modified_at: str | None = None
    mime: str | None = None
    is_training_candidate: bool = False


def classify_path(path: str, *, is_directory: bool = False, mime: str | None = None) -> PathKind:
    if is_directory:
        return PathKind.DIRECTORY
    value = path.lower()
    if value.endswith((".csv", ".tsv")):
        return PathKind.CSV
    if value.endswith((".png", ".jpg", ".jpeg", ".webp")) or (mime or "").startswith("image/"):
        return PathKind.IMAGE
    if value.endswith((".pt", ".pth", ".onnx", ".safetensors")):
        return PathKind.MODEL
    if (mime or "").startswith("text/") or value.endswith((".log", ".txt", ".json", ".yaml", ".yml", ".xml")):
        return PathKind.TEXT
    return PathKind.UNKNOWN
