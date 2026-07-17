"""Evidence ledger used to prevent answers that are not backed by tools."""

from __future__ import annotations

from dataclasses import dataclass

from .schemas import ToolResult


@dataclass(frozen=True)
class EvidenceItem:
    tool_name: str
    status: str
    summary: str


class EvidenceLedger:
    def __init__(self) -> None:
        self._items: list[EvidenceItem] = []

    def add(self, result: ToolResult) -> None:
        self._items.append(EvidenceItem(result.tool_name, result.status, result.summary()))

    def items(self) -> tuple[EvidenceItem, ...]:
        return tuple(self._items)

    def has_success(self) -> bool:
        return any(item.status == "SUCCESS" for item in self._items)

    def compact(self, max_items: int = 8) -> list[str]:
        return [f"{item.tool_name}: {item.summary}" for item in self._items[-max_items:]]


class EvidenceEvaluator:
    """Conservative stopping rule for the first Agent orchestration slice."""

    def sufficient(self, results: tuple[ToolResult, ...], required_tools: tuple[str, ...] = ()) -> bool:
        successful = {result.tool_name for result in results if result.ok}
        return bool(successful) and all(tool in successful for tool in required_tools)
