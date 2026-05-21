import { proxyFastApi } from '@/lib/fastapi-proxy';
import { NextRequest } from 'next/server';

type Params = { params: Promise<{ caseId: string }> };

export async function GET(request: NextRequest, { params }: Params) {
  const { caseId } = await params;
  const limit = request.nextUrl.searchParams.get('limit') ?? '100';

  return proxyFastApi(
    `/cases/${encodeURIComponent(caseId)}/checkpoints?limit=${encodeURIComponent(limit)}`
  );
}
