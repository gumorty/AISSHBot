# AISSHBot

通过微信机器人以**受控工具**查询和管理服务器。当前版本先实现生产可审计的只读运维能力；不向模型或聊天用户开放任意 SSH Shell。

## 当前链路

```text
微信 ClawBot → LangBot → 身份绑定 / RBAC → 规则优先的意图规划
→ 白名单只读网关 → 本机或 SSH 资产 → 审计 → 微信回复
```

LLM 只能在规则不能确定时，从固定的 `inventory`、`health`、`processes`、`paper_progress`、`java_status` 中选择工具和已授权资产；它不会获得 SSH 凭据，也不能生成 Shell 命令。

## 安全边界

- 默认拒绝未绑定聊天账号和未授权服务器。
- 所有远程 SSH 资产必须提供已验证的 `known_hosts` 公钥；缺失时拒绝连接，绝不自动接受主机密钥。
- 当前无上传、删除、重启、部署、任意路径读取或任意 Shell 功能。
- 审计记录仅保存操作者、资产、操作、结果状态和时间；不保存命令输出或凭据。
- 运行时凭据、审计数据、可信主机密钥和服务器真实配置全部被 `.gitignore` 排除。

## 配置

从 `data/*.example.json` 复制为运行时配置，并将 `data/access_policy.json`、`data/servers.json`、`secrets/server_credentials.json` 设为仅运行账户可读。不要将真实 IP、密码、API Key 或微信身份标识提交到 Git。

## 开发验证

```bash
python -m pip install -e .
python -m pytest
```

部署适配层负责将 LangBot 的 `adapter.name` 和 `sender_id` 传给 `AccessPolicy`，并只在 `authorize()` 成功后调用 `ReadonlyGateway.execute()`。
