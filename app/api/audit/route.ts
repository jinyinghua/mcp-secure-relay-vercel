import { NextRequest, NextResponse } from 'next/server';
import { listAudit } from '@/lib/audit';
import { verifyAuditKey } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  if (!verifyAuditKey(request)) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
  }

  const requested = Number(request.nextUrl.searchParams.get('limit') || '100');
  const limit = Number.isFinite(requested) ? Math.min(Math.max(Math.floor(requested), 1), 500) : 100;
  try {
    return NextResponse.json({ retentionDays: 14, records: await listAudit(limit) }, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return NextResponse.json({ error: 'audit_storage_unavailable' }, { status: 503 });
  }
}
