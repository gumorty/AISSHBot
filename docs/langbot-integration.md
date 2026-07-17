# LangBot integration contract

The LangBot/OpenClaw message handler is only an adapter. It must not open an SSH session or call a model with unrestricted tools.

```text
incoming WeChat message
  → router.classify()
  → known read-only query: execute directly; complex request: immediate PROCESSING_ACK
  → resolve_principal(adapter.name, sender_id)
  → allowed_server_ids() and authorize()
  → SessionStore.get() + intent_planner.plan_tool_operation()
  → ObjectContext resolves active server/PID/training/path/service
  → PolicyEngine validates ToolPlan and every ToolCall
  → AgentRuntime / Orchestrator executes within step and output budgets
  → EvidenceLedger + ResponseComposer produce the answer
  → audit record + SessionStore record_tool_result()/record_turn()

During migration, `compatibility.legacy_router` and `compatibility.legacy_tools`
can route the same plan to the existing read-only gateway. Native training,
file-download and multi-step handlers must replace this adapter before those
capabilities are enabled for production.
```

For recognized operations, `plan_operation()` returns a local rule result and does not call the LLM. Only an unrecognized message may use a fallback planner, which receives the current user text, short context metadata, allowed operation names and allowed asset IDs—never SSH credentials, shell commands, file contents or command output.

The memory key is the bound internal user ID, not a nickname or chat-room ID. It expires after 30 minutes and keeps at most six turns. Raw log output must not be forwarded into the LLM planner.

The adapter should record only a one-way hash of the sender ID in diagnostic logs. A new platform must add an explicit identity binding; do not map users by display name.
