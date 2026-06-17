import { createApp } from 'vue';
import App from './App.vue';
import { router } from './router';
import { getUserManager } from './auth/client';
import { initAuth } from './auth/useAuth';
import './style.css';

async function bootstrap(): Promise<void> {
  const path = window.location.pathname;

  // Azure redirected back to /auth/callback?code=... — finish the PKCE
  // exchange, then return to wherever the user was. The static SPA fallback
  // serves index.html for /auth/callback, so we have to intercept it here
  // before Vue mounts.
  if (path === '/auth/callback') {
    try {
      const um = await getUserManager();
      await um.signinRedirectCallback();
      const returnTo = window.localStorage.getItem('auth.returnTo') ?? '/';
      window.localStorage.removeItem('auth.returnTo');
      window.location.replace(window.location.origin + (returnTo.startsWith('/') ? returnTo : '/' + returnTo));
    } catch (err) {
      document.body.innerText = 'sign-in failed: ' + (err instanceof Error ? err.message : String(err));
    }
    return;
  }

  if (path === '/auth/silent') {
    try {
      const um = await getUserManager();
      await um.signinSilentCallback();
    } catch {
      /* the parent window will surface failure via events */
    }
    return;
  }

  await initAuth();
  createApp(App).use(router).mount('#app');
}

void bootstrap();
