# LangBot integration contract

The LangBot/OpenClaw message handler is only an adapter. It must not open an SSH session or call a model with unrestricted tools.

```text
incoming WeChat message
  → router.classify()
  → immediate PROCESSING_ACK for server requests
  → AccessPolicy.resolve_principal(adapter.name, sender_id)
  → AccessPolicy.visible_servers() and authorize()
  → intent_planner.plan_operation()
  → ReadonlyGateway.execute()
  → bounded response + audit record
```

For recognized operations, `plan_operation()` returns a local rule result and does not call the LLM. Only an unrecognized message may use a fallback planner, which receives the user text, allowed operation names and allowed asset IDs—never SSH credentials, shell commands, file contents or command output.

The adapter should record only a one-way hash of the sender ID in diagnostic logs. A new platform must add an explicit identity binding; do not map users by display name.
