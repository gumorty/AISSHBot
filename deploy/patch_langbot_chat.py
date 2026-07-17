"""Patch the private LangBot deployment's handler to use AISSHBot AgentRuntime.

LangBot itself is deployed separately and is intentionally not vendored into
this repository. This idempotent patch is the tracked integration boundary
used by deployment automation.
"""

from __future__ import annotations

from pathlib import Path


CHAT_HANDLER = Path(
    "/home/uav/gu/LLM/aisshbot/python-packages/langbot/"
    "pkg/pipeline/process/handlers/chat.py"
)

IMPORT_ANCHOR = "from aisshbot.intent_planner import plan_operation"
IMPORT_LINE = "from aisshbot.compatibility.agent_runtime import execute_with_agent"

OLD_BLOCK = """                    else:
                        try:
                            response_text = await execute_readonly(
                                resolved_intent,
                                principal.user_id,
                                visible_servers,
                            )
                            SHORT_TERM_MEMORY.remember(
                                principal.user_id,
                                message_text,
                                response_text,
                                resolved_intent,
                            )
"""

NEW_BLOCK = """                    else:
                        try:
                            agent_run = await execute_with_agent(
                                resolved_intent,
                                principal,
                                visible_servers,
                                channel=adapter_name,
                                conversation_id=str(getattr(query, \"query_id\", \"unknown\")),
                                goal=message_text,
                            )
                            if agent_run is not None:
                                response_text = agent_run.answer
                                self.ap.logger.info(
                                    \"AISSHBot AgentRuntime completed request=%s status=%s\",
                                    agent_run.plan.request_id,
                                    agent_run.status,
                                )
                            else:
                                response_text = await execute_readonly(
                                    resolved_intent,
                                    principal.user_id,
                                    visible_servers,
                                )
                            SHORT_TERM_MEMORY.remember(
                                principal.user_id,
                                message_text,
                                response_text,
                                resolved_intent,
                            )
"""


def main() -> None:
    if not CHAT_HANDLER.exists():
        raise SystemExit(f"missing LangBot handler: {CHAT_HANDLER}")
    text = CHAT_HANDLER.read_text(encoding="utf-8")
    if IMPORT_LINE not in text:
        if IMPORT_ANCHOR not in text:
            raise SystemExit("LangBot handler anchor not found")
        text = text.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + "\n" + IMPORT_LINE, 1)
    if OLD_BLOCK in text:
        text = text.replace(OLD_BLOCK, NEW_BLOCK, 1)
    elif "agent_run = await execute_with_agent(" not in text:
        raise SystemExit("AISSHBot execution block anchor not found")
    CHAT_HANDLER.write_text(text, encoding="utf-8")
    print(f"patched {CHAT_HANDLER}")


if __name__ == "__main__":
    main()
