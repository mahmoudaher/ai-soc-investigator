import { proxyFastApi } from '@/lib/fastapi-proxy';

type Params = { params: Promise<{ caseId: string }> };

export async function GET(_request: Request, { params }: Params) {
  const { caseId } = await params;
  return proxyFastApi(`/cases/${encodeURIComponent(caseId)}`);
}
