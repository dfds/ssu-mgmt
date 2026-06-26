import { getAccessToken } from './auth/useAuth';

export class UnauthenticatedError extends Error {
  constructor(
    public kind: 'no-token' | 'rejected',
    message: string,
    public detail?: string,
  ) {
    super(message);
    this.name = 'UnauthenticatedError';
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = await getAccessToken();
  if (!token) {
    throw new UnauthenticatedError('no-token', 'session expired');
  }
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    let detail = '';
    try {
      const body = (await res.clone().json()) as { detail?: string };
      detail = body?.detail ?? '';
    } catch {
      /* response body not JSON — ignore */
    }
    throw new UnauthenticatedError(
      'rejected',
      detail ? `unauthenticated: ${detail}` : 'unauthenticated',
      detail || undefined,
    );
  }
  return res;
}
