# MCP Secure Relay for Vercel

English documentation is available in [README.md](./README.md).

本项目在 Vercel 上接受标准的 MCP（Model Context Protocol）连接，并通过私有加密协议把受控操作转发到远程服务器上执行。远程服务器无需安装任何 Agent 工具，只需部署一个单文件可执行程序。

```
MCP 客户端 ── HTTPS ──> Vercel /api/mcp ── 加密 HTTP/HTTPS ──> relay-agent ── 本地执行
```

Vercel 到 agent 的链路使用项目自带的加密：AES-256-GCM 加密 + HMAC-SHA256 认证，请求与响应使用独立的派生密钥，附带 60 秒时间戳校验和 nonce 重放防护。远端无需配置 SSL 证书——当然，如果网络环境允许，叠加 HTTPS 或私有隧道会进一步隐藏元数据。需要说明的是：这属于应用层加密，不能替代网络隔离。

## 安全模型

- `MCP_API_KEYS` 为必填项，未配置时中转站拒绝一切 MCP 请求。
- Agent 持有独立的 32 字节共享密钥，拒绝被篡改、过期或重放的加密信封。
- `execute_command` 只接受远程预定义的 `command_id`；每个 ID 在 agent 配置中映射到一个确定的可执行文件和固定参数列表，shell（`sh`、`bash` 等）被禁止。
- `read_file` 和 `write_file` 只接受 `root_dir` 下的相对路径，绝对路径、`..` 穿越、符号链接、非普通文件、缺失的父目录一律拒绝。
- 写入默认关闭；开启后采用同目录临时文件 + 原子改名，不会留下半写文件。
- Agent 自带独立的读/写/输出/超时上限，Vercel 端会对工具响应再次截断。
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
# 编辑 /etc/relay-agent.json：shared_secret、root_dir、固定命令档案
/usr/local/bin/relay-agent -config /etc/relay-agent.json
```

示例默认监听 `127.0.0.1:8787`，建议保持该默认并通过已有的私有隧道或反向代理暴露。如果 Vercel 必须直连 agent，`REMOTE_AGENT_URL` 需要对公网可达，并尽量用主机防火墙收紧来源；即便走明文 HTTP，agent 也会对每个请求做加密认证。

需要允许受控写入时，先把 `root_dir` 收窄，再把 `allow_file_write` 设为 `true`。Agent 不会自动创建缺失目录。

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

上线前建议测试：被拒绝的 command_id、`../` 路径、符号链接路径、超限文件、关闭的写入、过期信封、Redis 不可用等场景。请用最小权限的专用 OS 账户和窄 `root_dir` 运行 agent；项目无法弥补操作系统账户权限过大带来的风险。
