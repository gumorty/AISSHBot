"""Small response layer for structured results; never invents missing facts."""

from __future__ import annotations

from ..agent.schemas import ToolResult


class ResponseComposer:
    def compose(self, results: tuple[ToolResult, ...], focus: tuple[str, ...] = ()) -> str:
        if not results:
            return "没有获得可用于回答的服务器证据。"
        failed = [result for result in results if not result.ok]
        successful = [result for result in results if result.ok]
        text_results = [result.data.get("text") for result in successful if result.data.get("text")]
        if text_results:
            answer = "\n\n".join(str(text) for text in text_results)
            if failed:
                answer += "\n\n未完成：" + "；".join(result.error or result.status for result in failed)
            return answer
        lines: list[str] = []
        if successful:
            lines.append("已完成检查：" + "、".join(result.tool_name for result in successful))
        if focus:
            lines.append("回答重点：" + "、".join(focus))
        if failed:
            lines.append("未完成：" + "；".join(result.error or result.status for result in failed))
        return "\n".join(lines)
