import { proxyFastApi } from '@/lib/fastapi-proxy';
import { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const limit = request.nextUrl.searchParams.get('limit') ?? '200';
  return proxyFastApi(`/cases?limit=${encodeURIComponent(limit)}`);
}
