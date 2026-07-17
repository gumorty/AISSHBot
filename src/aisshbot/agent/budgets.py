"""Hard budgets for ReAct-style loops."""

from __future__ import annotations


class BudgetExceeded(RuntimeError):
    pass


class ExecutionBudget:
    def __init__(self, max_steps: int = 6, max_tool_calls: int = 12):
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls
        self.steps = 0
        self.tool_calls = 0

    def consume(self) -> None:
        if self.steps >= self.max_steps or self.tool_calls >= self.max_tool_calls:
            raise BudgetExceeded("Agent 已达到执行预算")
        self.steps += 1
        self.tool_calls += 1
