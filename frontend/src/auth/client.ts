import { UserManager, WebStorageStateStore, type SigninSilentArgs, type User } from 'oidc-client-ts';

interface PublicAuthConfig {
  tenant_id: string;
  client_id: string;
  api_scope: string;
}

let configPromise: Promise<PublicAuthConfig> | null = null;
let managerPromise: Promise<UserManager> | null = null;
let graphManagerPromise: Promise<UserManager> | null = null;

export async function getAuthConfig(): Promise<PublicAuthConfig> {
  if (!configPromise) {
    configPromise = (async () => {
      const res = await fetch('/api/auth/config');
      if (!res.ok) throw new Error(`GET /api/auth/config: ${res.status}`);
      return (await res.json()) as PublicAuthConfig;
    })();
  }
  return configPromise;
}

export async function getUserManager(): Promise<UserManager> {
  if (!managerPromise) {
    managerPromise = (async () => {
      const cfg = await getAuthConfig();
      const um = new UserManager({
        authority: `https://login.microsoftonline.com/${cfg.tenant_id}/v2.0/`,
        client_id: cfg.client_id,
        redirect_uri: `${window.location.origin}/auth/callback`,
        silent_redirect_uri: `${window.location.origin}/auth/silent`,
        post_logout_redirect_uri: window.location.origin,
        response_type: 'code',
        scope: `openid profile email offline_access ${cfg.api_scope}`,
        automaticSilentRenew: true,
        stateStore: new WebStorageStateStore({ store: window.localStorage }),
        userStore: new WebStorageStateStore({ store: window.localStorage }),
      });
      return wrapSigninSilent(um);
    })();
  }
  return managerPromise;
}

const RT_LOCK = 'oidc-api-rt-rotation';

let inFlightFallback: Promise<unknown> | null = null;

export async function withRtLock<T>(fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== 'undefined' && 'locks' in navigator) {
    return navigator.locks.request(RT_LOCK, async () => fn());
  }
  while (inFlightFallback) {
    try {
      await inFlightFallback;
    } catch {
      /* swallow — we just want serialization */
    }
  }
  const p = fn();
  inFlightFallback = p.finally(() => {
    inFlightFallback = null;
  });
  return p;
}

function wrapSigninSilent(um: UserManager): UserManager {
  const original = um.signinSilent.bind(um);
  um.signinSilent = (args?: SigninSilentArgs): Promise<User | null> =>
    withRtLock(() => original(args));
  return um;
}

export async function getGraphUserManager(): Promise<UserManager> {
  if (!graphManagerPromise) {
    graphManagerPromise = (async () => {
      const cfg = await getAuthConfig();
      return new UserManager({
        authority: `https://login.microsoftonline.com/${cfg.tenant_id}/v2.0/`,
        client_id: cfg.client_id,
        redirect_uri: `${window.location.origin}/auth/callback`,
        post_logout_redirect_uri: window.location.origin,
        response_type: 'code',
        scope: 'openid profile offline_access https://graph.microsoft.com/User.Read',
        automaticSilentRenew: false,
        stateStore: new WebStorageStateStore({ store: window.localStorage, prefix: 'oidc.graph.' }),
        userStore: new WebStorageStateStore({ store: window.localStorage, prefix: 'oidc.graph.' }),
      });
    })();
  }
  return graphManagerPromise;
}
