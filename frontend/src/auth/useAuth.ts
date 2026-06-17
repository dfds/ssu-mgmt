import { computed, ref } from 'vue';
import type { User } from 'oidc-client-ts';
import { getUserManager } from './client';
import { usePhoto } from './usePhoto';

const user = ref<User | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);
const sessionExpired = ref(false);

let initPromise: Promise<void> | null = null;

interface JwtPayload {
  roles?: string[];
  email?: string;
  preferred_username?: string;
  upn?: string;
  unique_name?: string;
  [k: string]: unknown;
}

function decodeJwtPayload(token: string): JwtPayload | null {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    const padded = part.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), '='));
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

const accessToken = computed<string | null>(() => user.value?.access_token ?? null);

const accessTokenPayload = computed<JwtPayload | null>(() => {
  const tok = accessToken.value;
  if (!tok) return null;
  return decodeJwtPayload(tok);
});

const roles = computed<string[]>(() => {
  const payload = accessTokenPayload.value;
  return Array.isArray(payload?.roles) ? (payload?.roles as string[]) : [];
});

const email = computed<string>(() => {
  const payload = accessTokenPayload.value;
  if (!payload) return '';
  const raw = payload.email ?? payload.preferred_username ?? payload.upn ?? payload.unique_name;
  return typeof raw === 'string' ? raw : '';
});

const isAuthenticated = computed(() => !!user.value && !user.value.expired);

const displayName = computed(() => {
  const profile = user.value?.profile;
  return (profile?.name as string | undefined) ?? (profile?.preferred_username as string | undefined) ?? '';
});

export async function initAuth(): Promise<void> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    try {
      const um = await getUserManager();
      um.events.addUserLoaded((u) => {
        user.value = u;
      });
      um.events.addUserUnloaded(() => {
        user.value = null;
      });
      um.events.addAccessTokenExpired(() => {
        void um.signinSilent().catch(() => {
          user.value = null;
        });
      });
      const existing = await um.getUser();
      if (existing && !existing.expired) {
        user.value = existing;
      } else if (existing && existing.expired) {
        try {
          user.value = await um.signinSilent();
        } catch {
          user.value = null;
        }
      }
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
    } finally {
      loading.value = false;
    }
  })();
  return initPromise;
}

export async function signIn(): Promise<void> {
  const um = await getUserManager();
  // Persist the in-app route so we can return after the round-trip to
  // login.microsoftonline.com. Skip /auth/* paths — those are auth plumbing,
  // not a place users mean to land.
  const here = window.location.pathname + window.location.search;
  const returnTo = here.startsWith('/auth/') ? '/' : here || '/';
  window.localStorage.setItem('auth.returnTo', returnTo);
  sessionExpired.value = false;
  await um.signinRedirect();
}

export async function signOut(): Promise<void> {
  usePhoto().clear();
  const um = await getUserManager();
  await um.removeUser();
  user.value = null;
  sessionExpired.value = false;
}

export async function getAccessToken(): Promise<string | null> {
  await initAuth();
  if (user.value && !user.value.expired) return user.value.access_token;
  // Try a silent renew before giving up — handles the case where the
  // existing token expired between requests.
  try {
    const um = await getUserManager();
    const refreshed = await um.signinSilent();
    if (refreshed) {
      user.value = refreshed;
      return refreshed.access_token;
    }
  } catch {
    /* fallthrough — flip sessionExpired so the SPA can render the recovery splash */
  }
  sessionExpired.value = true;
  return null;
}

export function useAuth() {
  return {
    user,
    accessToken,
    roles,
    email,
    isAuthenticated,
    displayName,
    loading,
    error,
    sessionExpired,
    signIn,
    signOut,
  };
}
