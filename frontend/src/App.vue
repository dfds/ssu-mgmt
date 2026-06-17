<script setup lang="ts">
import { RouterView } from 'vue-router';
import HexMark from './components/HexMark.vue';
import ThemeToggle from './components/ThemeToggle.vue';
import { useAuth } from './auth/useAuth';

const { isAuthenticated, loading, error: authError, sessionExpired, signIn } = useAuth();
</script>

<template>
  <div v-if="loading" class="min-h-screen flex items-center justify-center text-[var(--color-text-secondary)]">
    Loading…
  </div>

  <div
    v-else-if="!isAuthenticated"
    class="relative min-h-screen flex flex-col items-center justify-center gap-6 px-6 text-center"
  >
    <div class="absolute top-4 right-4">
      <ThemeToggle />
    </div>
    <HexMark class="w-12 h-12 text-[var(--color-brand)]" />
    <div>
      <h1 class="text-xl font-semibold text-[var(--color-text-primary)]">SSU Management</h1>
      <p class="mt-1 text-sm text-[var(--color-text-secondary)]">
        Sign in with your DFDS account to continue.
      </p>
    </div>
    <button class="btn-action" @click="void signIn()">Sign in</button>
    <p v-if="sessionExpired" class="text-sm text-[var(--color-warning)]">Your session expired — please sign in again.</p>
    <p v-if="authError" class="text-sm text-[var(--color-error)]">{{ authError }}</p>
  </div>

  <RouterView v-else />
</template>
