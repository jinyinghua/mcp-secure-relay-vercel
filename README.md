# MCP Secure Relay for Vercel

A separate Vercel project that accepts a standard authenticated MCP connection and relays only three controlled operations to a lightweight remote executable.

```
MCP client -- HTTPS --> Vercel /api/mcp -- encrypted HTTP or HTTPS --> relay-agent -- local execution
```

The Vercel-to-agent body is a private protocol: AES-256-GCM encryption plus HMAC-SHA256 authentication, separate request/response keys derived from `RELAY_SHARED_SECRET`, 60-second timestamp validation, and nonce replay rejection. The remote hop does not need an SSL certificate. Its HTTP headers, endpoint address, timing, and payload size remain visible to the network, so use a private tunnel/firewall where possible. This is application-layer protection, not a replacement for network isolation.

## Security model

- `MCP_API_KEYS` is mandatory. The relay rejects every MCP request if it is unset.
- The agent has a separate 32-byte shared secret and rejects tampered, stale, or replayed envelopes.
- `execute_command` accepts only a remote `command_id`. Each ID maps to an exact executable and fixed argument list in the agent config. Shells (`sh`, `bash`) are prohibited.
- `read_file` and `write_file` only accept relative paths below `root_dir`. Absolute paths, `..`, symbolic links, non-regular files, and missing parent directories are rejected.
- Writes are disabled by default and use a same-directory temporary file followed by atomic rename when enabled.
- The agent has independent read/write/output/timeout limits. Vercel limits tool responses again.
- Every attempted operation is written to Redis before dispatch and completed afterward. It stores client key fingerprint, operation, target, byte counts, timing, status, and error code. It never stores API keys, file contents, or command output.
- Redis REST configuration is required for execution. If pre-dispatch audit storage is unavailable, no operation is sent to the remote server.

## Deploy Vercel

1. Create a new Vercel project from this directory. Do not import or modify the existing MCP project.
2. Add every variable in `.env.example` under Project Settings > Environment Variables. Generate independent values:

```sh
openssl rand -base64 48  # MCP_API_KEYS and AUDIT_API_KEY
openssl rand -base64 32  # RELAY_SHARED_SECRET and agent shared_secret
```

3. Provision Redis with an HTTP REST API, such as Upstash Redis from the Vercel Marketplace. Set `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
4. Deploy with `vercel --prod`, then set `NEXT_PUBLIC_APP_URL` to the resulting HTTPS URL and redeploy.

The MCP endpoint is `https://YOUR_PROJECT.vercel.app/api/mcp`. Configure a standard Streamable HTTP MCP client with `Authorization: Bearer YOUR_MCP_KEY`.

```json
{
  "mcpServers": {
    "secure-relay": {
      "url": "https://YOUR_PROJECT.vercel.app/api/mcp",
      "headers": { "Authorization": "Bearer YOUR_MCP_KEY" }
    }
  }
}
```

## Build and run the remote executable

The agent uses only the Go standard library and compiles to one static binary. It is not an MCP client and does not install any agent tooling on the remote server.

```sh
cd agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o relay-agent .
install -m 700 relay-agent /usr/local/bin/relay-agent
install -m 600 relay-agent.example.json /etc/relay-agent.json
# Edit /etc/relay-agent.json: shared_secret, root_dir, and fixed command profiles.
/usr/local/bin/relay-agent -config /etc/relay-agent.json
```

The sample binds `127.0.0.1:8787`; keep that default and expose it through an existing private tunnel or reverse proxy. If Vercel must call the agent directly, `REMOTE_AGENT_URL` must be reachable from the public Internet and the host firewall should restrict access where possible. The agent authenticates every request cryptographically, even when reachable through plain HTTP.

To permit controlled writes, set `allow_file_write` to `true` only after setting a narrow `root_dir`. The agent will not create missing directories.

## Audit access

Retrieve the latest records using the separate audit key:

```sh
curl 'https://YOUR_PROJECT.vercel.app/api/audit?limit=100' \
  -H 'Authorization: Bearer YOUR_AUDIT_API_KEY'
```

Records expire after 14 days. Redis also removes stale index entries on each new audit write.

## Verification

```sh
npm install
npm run typecheck
npm run build
cd agent && go test ./...
```

Before production use, test denied command IDs, `../` paths, symlink paths, oversize files, disabled writes, expired envelopes, and Redis unavailability. Run the agent under a dedicated unprivileged OS account with a minimal `root_dir`; the project cannot safely compensate for an over-permissive operating-system account.
