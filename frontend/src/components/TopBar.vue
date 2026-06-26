<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { RouterLink } from 'vue-router';
import { useAuth } from '../auth/useAuth';
import { usePhoto } from '../auth/usePhoto';
import HexMark from './HexMark.vue';
import ThemeToggle from './ThemeToggle.vue';

defineProps<{
  title: string;
  subtitle?: string;
}>();

const { displayName, roles, email, signOut } = useAuth();
const { photoUrl, load: loadPhoto } = usePhoto();

const canAdmin = computed(() => roles.value.includes('ce.cloudengineer'));

const userMenuOpen = ref(false);
const userMenuRef = ref<HTMLDivElement | null>(null);

const initials = computed(() => {
  const n = displayName.value;
  if (!n) return '?';
  const parts = n.trim().split(/\s+/);
  const first = parts[0]?.[0] ?? '';
  const last = parts.length > 1 ? parts[parts.length - 1][0] : '';
  return (first + last).toUpperCase() || n[0]?.toUpperCase() || '?';
});

function onDocumentMousedown(event: MouseEvent): void {
  if (!userMenuOpen.value) return;
  const root = userMenuRef.value;
  if (root && event.target instanceof Node && root.contains(event.target)) return;
  userMenuOpen.value = false;
}

onMounted(() => {
  document.addEventListener('mousedown', onDocumentMousedown);
  void loadPhoto();
});

onUnmounted(() => {
  document.removeEventListener('mousedown', onDocumentMousedown);
});
</script>

<template>
  <header
    class="sticky top-0 z-10 h-[52px] flex items-center px-5 md:px-8 bg-[var(--color-surface)] border-b border-[var(--color-border-divider)]"
  >
    <RouterLink
      :to="{ name: 'home' }"
      class="flex items-center hover:opacity-80 transition-opacity"
      aria-label="Go to home"
    >
      <HexMark class="w-6 h-6 text-[var(--color-brand)] flex-shrink-0" />
      <span class="ml-3 text-[13px] text-[var(--color-text-secondary)]">build.dfds.cloud</span>
    </RouterLink>
    <span class="mx-2 text-[var(--color-text-muted)]">/</span>
    <span class="text-[13px] font-semibold text-[var(--color-text-primary)]">{{ title }}</span>
    <span
      v-if="subtitle"
      class="ml-2 text-[13px] text-[var(--color-text-secondary)] truncate"
    >{{ subtitle }}</span>

    <span class="flex-1"></span>

    <RouterLink
      v-if="canAdmin"
      :to="{ name: 'console-status' }"
      class="btn-outline mr-2"
    >Console</RouterLink>

    <ThemeToggle />

    <div ref="userMenuRef" class="relative ml-2">
      <button
        type="button"
        class="flex items-center justify-center w-8 h-8 p-0 border-0 rounded-full bg-[var(--color-action)]/10 text-[var(--color-action)] font-mono text-[11px] font-semibold uppercase tracking-[0.04em] hover:bg-[var(--color-action)]/20 transition-colors overflow-hidden"
        :title="displayName || 'Account'"
        :aria-label="displayName || 'Account'"
        :aria-expanded="userMenuOpen"
        aria-haspopup="true"
        @click="userMenuOpen = !userMenuOpen"
      >
        <img
          v-if="photoUrl"
          :src="photoUrl"
          alt=""
          class="block w-full h-full object-cover"
        />
        <span v-else>{{ initials }}</span>
      </button>
      <div
        v-if="userMenuOpen"
        class="absolute right-0 top-full mt-1 z-20 w-72 rounded-[6px] border border-[var(--color-border-card)] bg-[var(--color-surface)] shadow-[var(--shadow-overlay)] overflow-hidden"
        role="menu"
      >
        <div class="px-3 py-2 border-b border-[var(--color-border-divider)]">
          <div class="text-[13px] font-semibold text-[var(--color-text-primary)] truncate">
            {{ displayName || 'signed in' }}
          </div>
          <div
            v-if="email"
            class="mt-0.5 text-[12px] text-[var(--color-text-secondary)] truncate"
            :title="email"
          >{{ email }}</div>
        </div>
        <div class="px-3 py-2 border-b border-[var(--color-border-divider)]">
          <div class="text-[10px] font-mono uppercase tracking-[0.08em] text-[var(--color-text-muted)] mb-1">
            Roles
          </div>
          <div v-if="roles.length" class="flex flex-wrap gap-1">
            <span
              v-for="r in roles"
              :key="r"
              class="inline-block px-1.5 py-0.5 rounded-[3px] bg-[var(--color-action)]/10 text-[var(--color-action)] font-mono text-[11px] leading-tight break-all"
            >{{ r }}</span>
          </div>
          <div v-else class="text-[12px] text-[var(--color-text-secondary)] italic">
            no roles
          </div>
        </div>
        <button
          type="button"
          class="w-full text-left px-3 py-2 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-muted)]"
          @click="userMenuOpen = false; void signOut()"
        >
          Sign out
        </button>
      </div>
    </div>
  </header>
</template>
