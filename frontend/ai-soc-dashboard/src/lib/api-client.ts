const BASE_URL = '/api';

export async function apiClient<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });

  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;

    try {
      const payload = (await res.json()) as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {
      // Keep the HTTP status text when the backend does not return JSON.
    }

    throw new Error(`API error: ${detail}`);
  }

  return res.json() as Promise<T>;
}
