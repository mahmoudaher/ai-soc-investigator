import { proxyFastApi } from '@/lib/fastapi-proxy';
import { NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  const runWorkflow = request.nextUrl.searchParams.get('run_workflow') ?? 'true';
  const body = await request.text();

  return proxyFastApi(`/alerts/wazuh?run_workflow=${encodeURIComponent(runWorkflow)}`, {
    method: 'POST',
    body
  });
}
