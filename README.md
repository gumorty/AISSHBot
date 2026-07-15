# AISSHBot

通过微信机器人以**受控工具**查询和管理服务器。当前版本先实现生产可审计的只读运维能力；不向模型或聊天用户开放任意 SSH Shell。

## 当前链路

```text
微信 ClawBot → LangBot → 身份绑定 / RBAC → 每用户短期上下文
→ 规则优先的意图规划 → 白名单只读网关 → 本机或 SSH 资产
→ 精简格式化 / 审计 → 微信回复
```

LLM 只能在本地规则不能确定时，从固定的 `inventory`、`select_server`、`health`、`processes`、`process_detail`、`gpu_overview`、`training_overview`、`java_status`、`middleware_overview` 中选择工具和已授权资产；路径、PID、服务名等动态目标由本地规则校验，LLM 不会获得 SSH 凭据，也不能生成 Shell 命令。

每个内部用户拥有独立的 30 分钟短期上下文，最多保留 6 轮，用于理解“那它呢”“再看一下进程”等追问。上下文只存在于 AISSHBot 进程内，不跨用户共享，服务重启后自动清空。

当前响应会先提取数量、异常状态和关键指标，再输出适合手机聊天窗口的短分组和项目符号；不会直接返回完整命令行、环境变量或无限制日志。训练查询可从 GPU 任务工作目录中读取受控的 `results.csv`、指标 CSV、TensorBoard 事件和日志摘要；Java/中间件查询可查看进程、服务状态、日志来源和错误摘要。

## 安全边界

- 默认拒绝未绑定聊天账号和未授权服务器。
- 所有远程 SSH 资产必须提供已验证的 `known_hosts` 公钥；缺失时拒绝连接，绝不自动接受主机密钥。
- 当前无上传、删除、重启、部署、任意 Shell 功能。文件查询只允许配置的读取根目录，并拒绝 `/proc`、`/sys`、`/dev`、`/run`、SSH 密钥、云凭据、环境文件、私钥等敏感路径；文件预览限制为小型文本类文件并进行敏感字段脱敏。服务日志只允许白名单中的 nginx、docker、mysql、MQTT、Redis 等服务，并限制返回行数。
- 审计记录仅保存操作者、资产、操作、结果状态和时间；不保存命令输出或凭据。
- 运行时凭据、审计数据、可信主机密钥和服务器真实配置全部被 `.gitignore` 排除。

## 配置

从 `data/*.example.json` 复制为运行时配置，并将 `data/access_policy.json`、`data/servers.json`、`secrets/server_credentials.json` 设为仅运行账户可读。不要将真实 IP、密码、API Key 或微信身份标识提交到 Git。

## 开发验证

```bash
python -m pip install -e .
python -m pytest
```

部署适配层负责将 LangBot 的 `adapter.name` 和 `sender_id` 传给 `resolve_principal()`，并只在 `authorize()` 成功后调用 `execute_readonly()`。
