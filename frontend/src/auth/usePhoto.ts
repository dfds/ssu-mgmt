import { ref } from 'vue';
import { User, type UserManager } from 'oidc-client-ts';
import { getAuthConfig, getGraphUserManager, getUserManager, withRtLock } from './client';

const photoUrl = ref<string | null>(null);
let loadPromise: Promise<void> | null = null;

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  scope?: string;
  expires_in?: number;
}

const GRAPH_SCOPE = 'openid profile offline_access https://graph.microsoft.com/User.Read';

async function postRefreshToken(
  refreshToken: string,
): Promise<
  | { ok: true; data: TokenResponse }
  | { ok: false; status: number; error: string; description: string }
> {
  const cfg = await getAuthConfig();
  const params = new URLSearchParams();
  params.set('client_id', cfg.client_id);
  params.set('grant_type', 'refresh_token');
  params.set('refresh_token', refreshToken);
  params.set('scope', GRAPH_SCOPE);

  const res = await fetch(`https://login.microsoftonline.com/${cfg.tenant_id}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  if (!res.ok) {
    let error = '';
    let description = '';
    try {
      const body = (await res.json()) as { error?: string; error_description?: string };
      error = body?.error ?? '';
      description = body?.error_description ?? '';
    } catch {
      /* response body not JSON — leave fields empty */
    }
    return { ok: false, status: res.status, error, description };
  }
  return { ok: true, data: (await res.json()) as TokenResponse };
}

async function rotateApiUser(apiManager: UserManager): Promise<User | null> {
  const existing = await apiManager.getUser();
  if (existing && !existing.expired && existing.refresh_token) {
    return existing;
  }
  try {
    const u = await apiManager.signinSilent();
    if (u) return u;
  } catch {
    /* fallthrough — fall back to whatever is in storage */
  }
  return apiManager.getUser();
}

async function seedGraphUserOnce(): Promise<string | null> {
  const apiManager = await getUserManager();

  return withRtLock(async () => {
    let apiUser = await rotateApiUser(apiManager);
    if (!apiUser?.refresh_token) return null;

    let result = await postRefreshToken(apiUser.refresh_token);
    if (!result.ok && result.error === 'invalid_grant') {
      apiUser = await rotateApiUser(apiManager);
      if (!apiUser?.refresh_token) return null;
      result = await postRefreshToken(apiUser.refresh_token);
    }
    if (!result.ok) return null;

    const data = result.data;
    if (!data.access_token) return null;

    if (data.refresh_token) {
      const fresh = await apiManager.getUser();
      if (fresh) {
        fresh.refresh_token = data.refresh_token;
        await apiManager.storeUser(fresh);
      }
    }

    const graphManager = await getGraphUserManager();
    const graphUser = new User({
      access_token: data.access_token,
      id_token: data.id_token,
      token_type: data.token_type ?? 'Bearer',
      scope: data.scope ?? 'profile',
      profile: (apiUser.profile ?? {}) as User['profile'],
      expires_at: data.expires_in ? Math.floor(Date.now() / 1000) + data.expires_in : undefined,
      session_state: null,
    });
    await graphManager.storeUser(graphUser);

    return data.access_token;
  });
}

async function getGraphAccessToken(): Promise<string | null> {
  try {
    const graphManager = await getGraphUserManager();
    const cached = await graphManager.getUser();
    if (cached && !cached.expired && cached.access_token) {
      return cached.access_token;
    }
    return await seedGraphUserOnce();
  } catch {
    return null;
  }
}

async function load(): Promise<void> {
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    const token = await getGraphAccessToken();
    if (!token) return;
    try {
      const res = await fetch('https://graph.microsoft.com/v1.0/me/photo/$value', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const blob = await res.blob();
      photoUrl.value = URL.createObjectURL(blob);
    } catch {
      /* fallthrough — caller renders initials */
    }
  })();
  return loadPromise;
}

function clear(): void {
  if (photoUrl.value) {
    URL.revokeObjectURL(photoUrl.value);
    photoUrl.value = null;
  }
  loadPromise = null;
  void getGraphUserManager()
    .then((m) => m.removeUser())
    .catch(() => {});
}

export function usePhoto() {
  return { photoUrl, load, clear };
}
