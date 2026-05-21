import { NextResponse } from 'next/server';

const DEFAULT_FASTAPI_URL = 'http://localhost:8000';

export function getFastApiBaseUrl() {
  return (
    process.env.AI_SOC_API_URL ||
    process.env.NEXT_PUBLIC_AI_SOC_API_URL ||
    DEFAULT_FASTAPI_URL
  ).replace(/\/$/, '');
}

export async function proxyFastApi(path: string, init?: RequestInit) {
  const url = `${getFastApiBaseUrl()}${path.startsWith('/') ? path : `/${path}`}`;

  try {
    const response = await fetch(url, {
      cache: 'no-store',
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...init?.headers
      }
    });

    const text = await response.text();
    const payload = text ? JSON.parse(text) : null;

    return NextResponse.json(payload, { status: response.status });
  } catch (error) {
    return NextResponse.json(
      {
        detail:
          error instanceof Error
            ? `FastAPI backend unavailable: ${error.message}`
            : 'FastAPI backend unavailable'
      },
      { status: 503 }
    );
  }
}
