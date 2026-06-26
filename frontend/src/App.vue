<script setup lang="ts">
import { RouterView } from 'vue-router';
import HexMark from './components/HexMark.vue';
import { useAuth } from './auth/useAuth';
import { useTheme } from './composables/useTheme';

const { isAuthenticated, loading, error: authError, sessionExpired, signIn } = useAuth();
const { toggle: toggleTheme } = useTheme();
</script>

<template>
  <!-- pre-auth screens use the console's terminal aesthetic (.term / --t-* tokens)
       so every screen a user sees matches the console look. -->
  <div
    v-if="loading"
    class="term"
    style="min-height:100vh;background:var(--t-bg);color:var(--t-dim);display:flex;align-items:center;justify-content:center;gap:8px;font-size:13px"
  >
    <span style="color:var(--t-accent)">▌</span> loading…
  </div>

  <div
    v-else-if="!isAuthenticated"
    class="term"
    style="position:relative;min-height:100vh;background:var(--t-bg);color:var(--t-text);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:22px;padding:24px;text-align:center"
  >
    <button
      type="button"
      title="toggle theme"
      style="position:absolute;top:14px;right:14px;background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 7px;cursor:pointer"
      @click="toggleTheme()"
    >
      theme
    </button>

    <HexMark style="width:44px;height:44px;color:var(--color-brand)" />
    <div>
      <div style="font-weight:700;letter-spacing:.08em;font-size:20px">ssu-mgmt</div>
      <p style="color:var(--t-dim);font-size:12.5px;margin:6px 0 0">
        Sign in with your DFDS account to continue.
      </p>
    </div>

    <button
      type="button"
      style="background:var(--t-accent);color:var(--t-bg);border:1px solid var(--t-accent);font-family:inherit;font-weight:600;font-size:13px;padding:8px 20px;cursor:pointer;letter-spacing:.02em"
      @click="void signIn()"
    >
      sign in →
    </button>

    <p v-if="sessionExpired" style="color:var(--t-amber);font-size:12px;margin:0">Your session expired — please sign in again.</p>
    <p v-if="authError" style="color:var(--t-red);font-size:12px;margin:0">{{ authError }}</p>
  </div>

  <RouterView v-else />
</template>
