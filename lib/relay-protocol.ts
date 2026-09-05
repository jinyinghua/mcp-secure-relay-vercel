import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'crypto';

const VERSION = 1;
const MAX_CLOCK_SKEW_MS = 60_000;

export interface Envelope {
  v: number;
  id: string;
  ts: number;
  nonce: string;
  ct: string;
  mac: string;
}

export interface RelayRequest {
  operation: 'command' | 'read_file' | 'write_file';
  commandId?: string;
  path?: string;
  contentBase64?: string;
  encoding?: 'utf8' | 'base64';
  callerId: string;
}

export interface RelayResponse {
  id: string;
  ok: boolean;
  result?: Record<string, unknown>;
  error?: { code: string; message: string };
}

function secret(): Buffer {
  const value = process.env.RELAY_SHARED_SECRET;
  if (!value) throw new Error('RELAY_NOT_CONFIGURED');
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('RELAY_SHARED_SECRET must be base64 encoded 32 bytes');
  return key;
}

function keys(direction: 'request' | 'response') {
  const input = secret();
  const derive = (purpose: string) => Buffer.from(hkdfSync('sha256', input, Buffer.alloc(0), `mcp-secure-relay/v1/${direction}/${purpose}`, 32));
  return { encryption: derive('aes-gcm'), mac: derive('hmac') };
}

function aad(envelope: Pick<Envelope, 'v' | 'id' | 'ts' | 'nonce'>): Buffer {
  return Buffer.from(`${envelope.v}.${envelope.id}.${envelope.ts}.${envelope.nonce}`, 'utf8');
}

function mac(macKey: Buffer, envelope: Omit<Envelope, 'mac'>): string {
  return createHmac('sha256', macKey).update(aad(envelope)).update('.').update(envelope.ct).digest('base64');
}

function equalBase64(left: string, right: string): boolean {
  const a = Buffer.from(left, 'base64');
  const b = Buffer.from(right, 'base64');
  return a.length === b.length && timingSafeEqual(a, b);
}

function seal(payload: unknown, id: string, direction: 'request' | 'response'): Envelope {
  const nonce = randomBytes(12);
  const envelope = { v: VERSION, id, ts: Date.now(), nonce: nonce.toString('base64') };
  const cipher = createCipheriv('aes-256-gcm', keys(direction).encryption, nonce);
  cipher.setAAD(aad(envelope));
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const unsigned = { ...envelope, ct: ciphertext.toString('base64') };
  return { ...unsigned, mac: mac(keys(direction).mac, unsigned) };
}

function open(envelope: Envelope, direction: 'request' | 'response'): unknown {
  if (envelope.v !== VERSION || !envelope.id || !envelope.nonce || !envelope.ct || !envelope.mac) throw new Error('RELAY_INVALID_ENVELOPE');
  if (Math.abs(Date.now() - envelope.ts) > MAX_CLOCK_SKEW_MS) throw new Error('RELAY_EXPIRED_ENVELOPE');
  const unsigned = { v: envelope.v, id: envelope.id, ts: envelope.ts, nonce: envelope.nonce, ct: envelope.ct };
  if (!equalBase64(envelope.mac, mac(keys(direction).mac, unsigned))) throw new Error('RELAY_INVALID_MAC');
  const raw = Buffer.from(envelope.ct, 'base64');
  if (raw.length < 17) throw new Error('RELAY_INVALID_ENVELOPE');
  const nonce = Buffer.from(envelope.nonce, 'base64');
  if (nonce.length !== 12) throw new Error('RELAY_INVALID_ENVELOPE');
  const decipher = createDecipheriv('aes-256-gcm', keys(direction).encryption, nonce);
  decipher.setAAD(aad(unsigned));
  decipher.setAuthTag(raw.subarray(raw.length - 16));
  return JSON.parse(Buffer.concat([decipher.update(raw.subarray(0, -16)), decipher.final()]).toString('utf8'));
}

export function sealRequest(payload: RelayRequest, id: string): Envelope {
  return seal(payload, id, 'request');
}

export async function invokeRelay(payload: RelayRequest, id: string): Promise<RelayResponse> {
  const endpoint = process.env.REMOTE_AGENT_URL;
  if (!endpoint) throw new Error('RELAY_NOT_CONFIGURED');
  const timeout = Math.min(Math.max(Number(process.env.RELAY_HTTP_TIMEOUT_MS || 25_000), 1_000), 29_000);
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sealRequest(payload, id)),
    signal: AbortSignal.timeout(timeout),
    cache: 'no-store'
  });
  if (!response.ok) throw new Error('RELAY_UNAVAILABLE');
  const decoded = open(await response.json() as Envelope, 'response') as RelayResponse;
  if (decoded.id !== id || typeof decoded.ok !== 'boolean') throw new Error('RELAY_INVALID_RESPONSE');
  return decoded;
}
