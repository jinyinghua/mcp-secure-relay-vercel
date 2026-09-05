export type AuditStatus = 'started' | 'succeeded' | 'failed' | 'rejected';

export interface AuditRecord {
  id: string;
  createdAt: string;
  finishedAt?: string;
  clientId: string;
  operation: string;
  target: string;
  status: AuditStatus;
  inputBytes?: number;
  outputBytes?: number;
  durationMs?: number;
  errorCode?: string;
}

const RETENTION_SECONDS = 14 * 24 * 60 * 60;
const INDEX_KEY = 'mcp-relay:audit:index';
const PREFIX = 'mcp-relay:audit:';

function config() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error('AUDIT_STORAGE_UNAVAILABLE');
  return { url: url.replace(/\/$/, ''), token };
}

async function pipeline(commands: string[][]): Promise<unknown[]> {
  const { url, token } = config();
  const response = await fetch(`${url}/pipeline`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(commands),
    cache: 'no-store'
  });
  if (!response.ok) throw new Error('AUDIT_STORAGE_UNAVAILABLE');
  const data = await response.json() as Array<{ result?: unknown; error?: string }>;
  if (!Array.isArray(data) || data.some((item) => item.error)) throw new Error('AUDIT_STORAGE_UNAVAILABLE');
  return data.map((item) => item.result);
}

function recordKey(id: string) {
  return `${PREFIX}${id}`;
}

function hsetPairs(values: object): string[] {
  return Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .flatMap(([key, value]) => [key, String(value)]);
}

export async function createAudit(record: AuditRecord): Promise<void> {
  const score = String(Date.parse(record.createdAt));
  const cutoff = String(Date.now() - RETENTION_SECONDS * 1000);
  await pipeline([
    ['HSET', recordKey(record.id), ...hsetPairs(record)],
    ['EXPIRE', recordKey(record.id), String(RETENTION_SECONDS)],
    ['ZADD', INDEX_KEY, score, record.id],
    ['ZREMRANGEBYSCORE', INDEX_KEY, '-inf', cutoff]
  ]);
}

export async function finishAudit(id: string, fields: Pick<AuditRecord, 'status' | 'finishedAt' | 'outputBytes' | 'durationMs' | 'errorCode'>): Promise<void> {
  await pipeline([
    ['HSET', recordKey(id), ...hsetPairs(fields)],
    ['EXPIRE', recordKey(id), String(RETENTION_SECONDS)]
  ]);
}

export async function listAudit(limit: number): Promise<AuditRecord[]> {
  const oldest = String(Date.now() - RETENTION_SECONDS * 1000);
  const [ids] = await pipeline([['ZREVRANGEBYSCORE', INDEX_KEY, '+inf', oldest, 'LIMIT', '0', String(limit)]]);
  if (!Array.isArray(ids) || ids.length === 0) return [];
  const hashes = await pipeline(ids.map((id) => ['HGETALL', recordKey(String(id))]));
  return hashes.flatMap((hash) => {
    if (!Array.isArray(hash) || hash.length === 0) return [];
    const item: Record<string, string> = {};
    for (let index = 0; index < hash.length; index += 2) item[String(hash[index])] = String(hash[index + 1] ?? '');
    return [{
      ...item,
      inputBytes: item.inputBytes ? Number(item.inputBytes) : undefined,
      outputBytes: item.outputBytes ? Number(item.outputBytes) : undefined,
      durationMs: item.durationMs ? Number(item.durationMs) : undefined
    } as AuditRecord];
  });
}
