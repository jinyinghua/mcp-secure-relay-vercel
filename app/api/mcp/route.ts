import { randomUUID } from 'crypto';
import { z } from 'zod';

export const runtime = 'nodejs';
import { createMcpHandler, withMcpAuth } from 'mcp-handler';
import { createAudit, finishAudit } from '@/lib/audit';
import { verifyMcpKey } from '@/lib/auth';
import { invokeRelay, type RelayRequest, type RelayResponse } from '@/lib/relay-protocol';

const MAX_WRITE_BYTES = 64 * 1024;
const MAX_TOOL_RESPONSE_BYTES = Math.min(Math.max(Number(process.env.MAX_TOOL_RESPONSE_BYTES || 65_536), 1_024), 256 * 1024);

function text(bytes: Buffer): string {
  if (bytes.length <= MAX_TOOL_RESPONSE_BYTES) return bytes.toString('utf8');
  return `${bytes.subarray(0, MAX_TOOL_RESPONSE_BYTES).toString('utf8')}\n[output truncated by relay]`;
}

async function relay(operation: RelayRequest, target: string, inputBytes = 0): Promise<RelayResponse> {
  const id = randomUUID();
  const startedAt = new Date();
  await createAudit({
    id,
    createdAt: startedAt.toISOString(),
    clientId: operation.callerId,
    operation: operation.operation,
    target,
    status: 'started',
    inputBytes
  });

  try {
    const response = await invokeRelay(operation, id);
    const outputBytes = Buffer.byteLength(JSON.stringify(response.result || response.error || {}));
    await finishAudit(id, {
      status: response.ok ? 'succeeded' : 'rejected',
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt.getTime(),
      outputBytes,
      errorCode: response.error?.code
    });
    return response;
  } catch (error) {
    await finishAudit(id, {
      status: 'failed',
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt.getTime(),
      errorCode: error instanceof Error ? error.message.slice(0, 80) : 'RELAY_ERROR'
    });
    throw error;
  }
}

function remoteFailure(response: RelayResponse) {
  return {
    content: [{ type: 'text' as const, text: `Remote operation rejected: ${response.error?.code || 'UNKNOWN'} (${response.error?.message || 'no details'})` }],
    isError: true
  };
}

const handler = createMcpHandler(
  (server) => {
    server.tool(
      'execute_command',
      'Run one fixed command profile configured on the remote relay. Arbitrary commands and shell syntax are never accepted.',
      { command_id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/).describe('An enabled remote command profile ID') },
      async ({ command_id }, { authInfo }) => {
        try {
          const response = await relay({ operation: 'command', commandId: command_id, callerId: authInfo?.clientId || 'unknown' }, command_id);
          if (!response.ok) return remoteFailure(response);
          const result = response.result || {};
          const stdout = typeof result.stdoutBase64 === 'string' ? text(Buffer.from(result.stdoutBase64, 'base64')) : '';
          const stderr = typeof result.stderrBase64 === 'string' ? text(Buffer.from(result.stderrBase64, 'base64')) : '';
          return { content: [{ type: 'text' as const, text: `exit_code: ${result.exitCode ?? 'unknown'}\nstdout:\n${stdout}\nstderr:\n${stderr}${result.truncated ? '\n[remote output truncated]' : ''}` }] };
        } catch (error) {
          return { content: [{ type: 'text' as const, text: `Relay failure: ${error instanceof Error ? error.message : 'unknown error'}` }], isError: true };
        }
      }
    );

    server.tool(
      'read_file',
      'Read a regular file below the remote relay allowlisted root. Paths must be relative and cannot traverse symbolic links.',
      {
        path: z.string().min(1).max(1024).describe('Relative path below the configured remote root'),
        encoding: z.enum(['utf8', 'base64']).default('utf8').describe('Return text or base64')
      },
      async ({ path, encoding }, { authInfo }) => {
        try {
          const response = await relay({ operation: 'read_file', path, encoding, callerId: authInfo?.clientId || 'unknown' }, path);
          if (!response.ok) return remoteFailure(response);
          const content = typeof response.result?.contentBase64 === 'string' ? Buffer.from(response.result.contentBase64, 'base64') : Buffer.alloc(0);
          const rendered = encoding === 'base64' ? content.toString('base64') : text(content);
          return { content: [{ type: 'text' as const, text: rendered }] };
        } catch (error) {
          return { content: [{ type: 'text' as const, text: `Relay failure: ${error instanceof Error ? error.message : 'unknown error'}` }], isError: true };
        }
      }
    );

    server.tool(
      'write_file',
      'Atomically write a UTF-8 text file below the remote relay allowlisted root. Disabled unless the remote policy explicitly enables writes.',
      {
        path: z.string().min(1).max(1024).describe('Relative path below the configured remote root'),
        content: z.string().max(MAX_WRITE_BYTES).describe('UTF-8 text content, limited to 64 KiB')
      },
      async ({ path, content }, { authInfo }) => {
        const contentBase64 = Buffer.from(content, 'utf8').toString('base64');
        try {
          const response = await relay({ operation: 'write_file', path, contentBase64, callerId: authInfo?.clientId || 'unknown' }, path, Buffer.byteLength(content));
          if (!response.ok) return remoteFailure(response);
          return { content: [{ type: 'text' as const, text: `Wrote ${response.result?.bytes ?? 0} bytes to ${path}` }] };
        } catch (error) {
          return { content: [{ type: 'text' as const, text: `Relay failure: ${error instanceof Error ? error.message : 'unknown error'}` }], isError: true };
        }
      }
    );
  },
  {},
  { basePath: '/api' }
);

const authHandler = withMcpAuth(handler, verifyMcpKey, {
  required: true,
  requiredScopes: ['relay'],
  resourceMetadataPath: '/.well-known/oauth-protected-resource'
});

export { authHandler as GET, authHandler as POST, authHandler as DELETE };
