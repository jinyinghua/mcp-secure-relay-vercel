# MCP Secure Relay for Vercel

English documentation is available in [README.md](./README.md).

本项目在 Vercel 上接受标准的 MCP（Model Context Protocol）连接，并通过私有加密协议把命令与文件操作转发到远程服务器上执行。远程服务器无需安装任何 Agent 工具，只需部署一个单文件可执行程序。

```
MCP 客户端 ── HTTPS ──> Vercel /api/mcp ── 加密 HTTP/HTTPS ──> relay-agent ── 本地执行
```

Vercel 到 agent 的链路使用项目自带的加密：AES-256-GCM 加密 + HMAC-SHA256 认证，请求与响应使用独立的派生密钥，附带 60 秒时间戳校验和 nonce 重放防护。远端无需配置 SSL 证书——当然，如果网络环境允许，叠加 HTTPS 或私有隧道会进一步隐藏元数据。需要说明的是：这属于应用层加密，不能替代网络隔离。

## 安全模型

- `MCP_API_KEYS` 为必填项，未配置时中转站拒绝一切 MCP 请求。
- Agent 持有独立的 32 字节共享密钥，拒绝被篡改、过期或重放的加密信封。
- `execute_command` 有意支持任意 shell 命令、管道、重定向和参数，并以 agent 所配置的 Linux 用户权限运行；必须只向你完全信任的 MCP 客户端发放 API Key。
- `read_file` 和 `write_file` 只接受 `root_dir` 下的相对路径，绝对路径、`..` 穿越、符号链接、非普通文件、缺失的父目录一律拒绝。
- 写入默认关闭；开启后采用同目录临时文件 + 原子改名，不会留下半写文件。
- Agent 自带独立的读/写/输出/命令超时上限，Vercel 端会对工具响应再次截断。
- 每次操作在派发前写入 Redis、结束后更新状态。审计记录包含客户端 key 指纹、操作类型、目标、字节数、耗时、状态和错误码；不包含 API Key、文件内容或命令输出。
- 审计存储为执行前置条件：优先使用 `REDIS_URL` 直连 Redis（Redis Cloud 可用 `rediss://`），未配置时兼容 Upstash REST；任一已选后端写入失败时操作不会下发到远端。

## 部署 Vercel

1. 从本目录创建一个全新的 Vercel 项目。不要导入或修改已有的 MCP 项目。
2. 在 Project Settings > Environment Variables 中填入 `.env.example` 的全部变量，分别生成独立值：

```sh
openssl rand -base64 48  # MCP_API_KEYS、AUDIT_API_KEY
openssl rand -base64 32  # RELAY_SHARED_SECRET、agent 的 shared_secret
```

3. 推荐使用 Redis Cloud：填入其控制台提供的 `REDIS_URL=rediss://...` 连接串，项目会直接使用 TLS Redis 协议。也可不填 `REDIS_URL`，改用 Vercel Marketplace 的 Upstash Redis，并填入 `UPSTASH_REDIS_REST_URL` 与 `UPSTASH_REDIS_REST_TOKEN`。
4. `vercel --prod` 部署后，把 `NEXT_PUBLIC_APP_URL` 改为生成的 HTTPS URL 并重新部署。

MCP 端点为 `https://你的项目.vercel.app/api/mcp`。标准 Streamable HTTP MCP 客户端配置：

```json
{
  "mcpServers": {
    "secure-relay": {
      "url": "https://你的项目.vercel.app/api/mcp",
      "headers": { "Authorization": "Bearer 你的_MCP_KEY" }
    }
  }
}
```

## 编译并运行远程可执行程序

Agent 只依赖 Go 标准库，可交叉编译为单一静态二进制，不是 MCP 客户端，也不在远程服务器上安装任何 agent 工具。

```sh
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o relay-agent .
install -m 700 relay-agent /usr/local/bin/relay-agent
install -m 600 relay-agent.example.json /etc/relay-agent.json
# 编辑 /etc/relay-agent.json：shared_secret、root_dir、命令超时上限
/usr/local/bin/relay-agent -config /etc/relay-agent.json
```

示例默认监听 `127.0.0.1:8787`，建议保持该默认并通过已有的私有隧道或反向代理暴露。如果 Vercel 必须直连 agent，`REMOTE_AGENT_URL` 需要对公网可达，并尽量用主机防火墙收紧来源；即便走明文 HTTP，agent 也会对每个请求做加密认证。

Agent 默认在 `root_dir` 作为工作目录执行 shell 命令；`root_dir` 同时仍是 `read_file` / `write_file` 的路径边界。示例已启用 `allow_file_write`；若只希望执行命令，可将其设为 `false`。Agent 不会为 `write_file` 自动创建缺失目录。

## 任意命令执行与权限

从本版本起，`execute_command` 接收 `command` 字符串，而不是旧版的 `command_id`。Agent 使用 `/bin/sh -lc` 执行命令，因此支持管道、重定向、脚本片段和任意参数；默认工作目录是 `root_dir`。

这意味着 MCP API Key 是高权限凭证：持有它的客户端可以执行 `mcp-relay` 系统用户有权执行的任何命令。若希望 AI 能安装系统软件，需要额外为 `mcp-relay` 配置 sudo 权限；若赋予 `NOPASSWD: ALL`，则该 MCP 客户端等价于拥有整台服务器的 root 权限。传输加密与审计不能消除该风险。

`max_command_seconds` 是 agent 的硬上限，当前最大可设置为 25 秒，以适应 Vercel 函数超时；客户端可请求更短的 `timeout_seconds`，但不能超过远端配置。命令正文不写入 14 天审计库，仅记录其 SHA-256 指纹、状态、耗时和字节数。

## 审计访问

用单独的审计 key 拉取最近记录：

```sh
curl 'https://你的项目.vercel.app/api/audit?limit=100' \
  -H 'Authorization: Bearer 你的_AUDIT_KEY'
```

记录保留 14 天后过期；每次新审计写入时也会清理过期索引。

## 验证

```sh
npm install
npm run typecheck
npm run build
cd agent && go test ./...
```

上线前建议测试：shell 命令执行、超时命令、`../` 路径、符号链接路径、超限文件、过期信封与 Redis 不可用等场景。请用专用 OS 账户运行 agent；该账户能访问的资源，都可能被持有 MCP Key 的客户端通过命令访问。
