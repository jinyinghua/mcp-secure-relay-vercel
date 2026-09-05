import { createHash, timingSafeEqual } from 'crypto';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

function configuredKeys(): string[] {
  return (process.env.MCP_API_KEYS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function sameSecret(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

export async function verifyMcpKey(_request: Request, bearerToken?: string): Promise<AuthInfo | undefined> {
  if (!bearerToken) return undefined;

  const keys = configuredKeys();
  if (keys.length === 0) {
    console.error('MCP_API_KEYS is not configured; rejecting request');
    return undefined;
  }

  const valid = keys.some((key) => sameSecret(key, bearerToken));
  if (!valid) return undefined;

  const clientId = `mcp-${fingerprint(bearerToken)}`;
  return {
    token: bearerToken,
    clientId,
    scopes: ['relay'],
    extra: { keyFingerprint: fingerprint(bearerToken) }
  };
}

export function verifyAuditKey(request: Request): boolean {
  const expected = process.env.AUDIT_API_KEY;
  const header = request.headers.get('authorization');
  const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
  return Boolean(expected && token && sameSecret(expected, token));
}
