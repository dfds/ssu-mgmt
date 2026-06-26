<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { RouterView, useRoute, useRouter } from 'vue-router';
import HexMark from '../components/HexMark.vue';
import { useTheme } from '../composables/useTheme';
import { useIsMobile } from '../composables/useIsMobile';
import { useAuth } from '../auth/useAuth';
import { useConsoleStream } from './useConsoleStream';

const route = useRoute();
const router = useRouter();
const { toggle: toggleTheme } = useTheme();
const isMobile = useIsMobile();
const { displayName, email, roles, signOut } = useAuth();
// Live progress stream — opened once for the whole console (all tabs share it).
const { connect: connectStream, disconnect: disconnectStream } = useConsoleStream();

interface Tab {
  key: string;
  label: string;
  name: string;
  live: boolean;
}

const tabs: Tab[] = [
  { key: '1', label: 'status', name: 'console-status', live: true },
  { key: '2', label: 'alerts', name: 'console-alerts', live: true },
  { key: '3', label: 'query', name: 'console-query', live: true },
  { key: '4', label: 'graph', name: 'console-graph', live: true },
  { key: '5', label: 'inspect', name: 'console-inspect', live: true },
  { key: '6', label: 'actors', name: 'console-actors', live: true },
];

const activeName = computed(() => route.name);

// Mobile: the six-tab strip collapses to a menu trigger + dropdown.
const navOpen = ref(false);
const navMenuRef = ref<HTMLElement | null>(null);
const activeTab = computed(() => tabs.find((t) => t.name === activeName.value));

// Desktop account menu (identity + roles + sign out). On mobile this same
// content folds into the nav dropdown instead, so the menu is desktop-only.
const accountOpen = ref(false);
const accountMenuRef = ref<HTMLElement | null>(null);

// Account button label: the user's id/upn/email (falls back to display name).
const accountLabel = computed(() => email.value || displayName.value || 'account');

function onDocumentMousedown(event: MouseEvent): void {
  const target = event.target instanceof Node ? event.target : null;
  if (navOpen.value) {
    const root = navMenuRef.value;
    if (!root || !target || !root.contains(target)) navOpen.value = false;
  }
  if (accountOpen.value) {
    const root = accountMenuRef.value;
    if (!root || !target || !root.contains(target)) accountOpen.value = false;
  }
}

function tabStyle(t: Tab): Record<string, string> {
  const active = t.name === activeName.value;
  return {
    color: active ? 'var(--t-text)' : t.live ? 'var(--t-dim)' : 'var(--t-faint)',
    borderBottom: active ? '2px solid var(--t-accent)' : '2px solid transparent',
    background: active ? 'var(--t-pane)' : 'transparent',
  };
}

function go(t: Tab): void {
  void router.push({ name: t.name });
}

// Live clock — the console renders an "as of <time>" stamp like the mock.
const now = ref(new Date());
let clock: ReturnType<typeof setInterval> | undefined;

const clockText = computed(() =>
  now.value.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
);

const footerScope = computed(() => {
  const t = tabs.find((x) => x.name === activeName.value);
  return t ? t.label : 'console';
});

function onKey(e: KeyboardEvent): void {
  // Ignore shortcuts while typing in an input/textarea.
  const el = e.target as HTMLElement | null;
  if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) return;
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const tab = tabs.find((t) => t.key === e.key);
  if (tab && tab.live) {
    e.preventDefault();
    go(tab);
    return;
  }
  if (e.key === 't') {
    e.preventDefault();
    toggleTheme();
  }
  if (e.key === 'Escape') {
    if (navOpen.value) navOpen.value = false;
    if (accountOpen.value) accountOpen.value = false;
  }
}

onMounted(() => {
  clock = setInterval(() => (now.value = new Date()), 1000);
  window.addEventListener('keydown', onKey);
  document.addEventListener('mousedown', onDocumentMousedown);
  connectStream();
});

onUnmounted(() => {
  if (clock) clearInterval(clock);
  window.removeEventListener('keydown', onKey);
  document.removeEventListener('mousedown', onDocumentMousedown);
  disconnectStream();
});
</script>

<template>
  <div
    class="term"
    style="display:grid;grid-template-rows:auto 1fr auto;height:100vh;width:100%;overflow:hidden"
  >
    <!-- header -->
    <header
      style="display:flex;align-items:stretch;height:46px;border-bottom:1px solid var(--t-line);background:var(--t-hdr);position:relative"
    >
      <div
        class="term-hdr-pad"
        style="display:flex;align-items:center;gap:9px;border-right:1px solid var(--t-line)"
      >
        <HexMark style="width:16px;height:16px;color:var(--color-brand)" />
        <span style="font-weight:700;letter-spacing:.06em">ssu-mgmt</span>
      </div>

      <!-- desktop: the full six-tab strip -->
      <nav v-if="!isMobile" style="display:flex;align-items:stretch">
        <template v-for="t in tabs" :key="t.key">
          <RouterLink v-if="t.live" :to="{ name: t.name }" custom v-slot="{ href, navigate }">
            <a
              :href="href"
              :style="tabStyle(t)"
              style="display:flex;align-items:center;gap:7px;padding:0 16px;border-bottom:2px solid transparent;font-family:inherit;font-size:13px;cursor:pointer;text-decoration:none"
              @click="navigate"
            >
              <span style="opacity:.6">{{ t.key }}</span>
              <span>{{ t.label }}</span>
            </a>
          </RouterLink>
          <span
            v-else
            :style="tabStyle(t)"
            style="display:flex;align-items:center;gap:7px;padding:0 16px;border-bottom:2px solid transparent;font-family:inherit;font-size:13px;color:var(--t-faint)"
            title="coming up"
          >
            <span style="opacity:.6">{{ t.key }}</span>
            <span>{{ t.label }}</span>
            <span style="font-size:9px;color:var(--t-faint)">soon</span>
          </span>
        </template>
      </nav>

      <div v-else ref="navMenuRef" style="display:flex;align-items:stretch;flex:1">
        <button
          type="button"
          aria-haspopup="true"
          :aria-expanded="navOpen"
          style="display:flex;align-items:center;justify-content:center;flex:1;gap:7px;padding:0 12px;background:none;border:none;border-bottom:2px solid transparent;font-family:inherit;font-size:13px;color:var(--t-text);cursor:pointer"
          @click="navOpen = !navOpen"
        >
          <span style="font-size:15px;line-height:1">☰</span>
          <span style="opacity:.6">{{ activeTab?.key }}</span>
          <span>{{ activeTab?.label }}</span>
          <span style="color:var(--t-dim)">▾</span>
        </button>
        <div
          v-if="navOpen"
          role="menu"
          style="position:absolute;top:46px;left:0;right:0;z-index:30;background:var(--t-hdr);border-bottom:1px solid var(--t-line);box-shadow:0 8px 16px rgba(0,0,0,.25)"
        >
          <template v-for="t in tabs" :key="t.key">
            <RouterLink v-if="t.live" :to="{ name: t.name }" custom v-slot="{ href, navigate }">
              <a
                :href="href"
                role="menuitem"
                :style="tabStyle(t)"
                style="display:flex;align-items:center;gap:9px;padding:11px 16px;border-bottom:1px solid var(--t-line);font-family:inherit;font-size:14px;cursor:pointer;text-decoration:none"
                @click="navigate(); navOpen = false"
              >
                <span style="opacity:.6">{{ t.key }}</span>
                <span>{{ t.label }}</span>
              </a>
            </RouterLink>
            <span
              v-else
              :style="tabStyle(t)"
              style="display:flex;align-items:center;gap:9px;padding:11px 16px;border-bottom:1px solid var(--t-line);font-family:inherit;font-size:14px;color:var(--t-faint)"
            >
              <span style="opacity:.6">{{ t.key }}</span>
              <span>{{ t.label }}</span>
              <span style="font-size:9px;color:var(--t-faint)">soon</span>
            </span>
          </template>

          <!-- mobile account block: identity + roles + sign out fold in here
               (no separate header button on mobile). -->
          <div style="padding:11px 16px;border-bottom:1px solid var(--t-line);background:var(--t-pane)">
            <div style="color:var(--t-faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em">signed in as</div>
            <div style="color:var(--t-text);font-size:13px;margin-top:3px;overflow-wrap:anywhere">
              {{ displayName || email || 'signed in' }}
            </div>
            <div
              v-if="email && displayName"
              style="color:var(--t-dim);font-size:11.5px;margin-top:1px;overflow-wrap:anywhere"
            >{{ email }}</div>
            <div style="color:var(--t-faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin:9px 0 6px">roles</div>
            <div v-if="roles.length" style="display:flex;flex-wrap:wrap;gap:4px">
              <span
                v-for="r in roles"
                :key="r"
                style="border:1px solid var(--t-line2);color:var(--t-dim);font-size:11px;padding:1px 6px;line-height:1.5;overflow-wrap:anywhere"
              >{{ r }}</span>
            </div>
            <div v-else style="color:var(--t-faint);font-size:12px;font-style:italic">no roles</div>
          </div>
          <button
            type="button"
            role="menuitem"
            style="display:block;width:100%;text-align:left;background:none;border:none;color:var(--t-text);font-family:inherit;font-size:14px;padding:11px 16px;cursor:pointer"
            @click="navOpen = false; void signOut()"
          >
            sign out / switch account
          </button>
        </div>
      </div>

      <span v-if="!isMobile" style="flex:1"></span>

      <div
        class="term-hdr-pad"
        style="display:flex;align-items:center;gap:14px;border-left:1px solid var(--t-line);color:var(--t-dim);font-size:11.5px"
      >
        <span v-if="!isMobile">1 source <span style="color:var(--t-accent)">●</span></span>
        <span style="color:var(--t-text)">{{ clockText }}</span>
        <button
          type="button"
          title="theme [t]"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 7px;cursor:pointer"
          @click="toggleTheme()"
        >
          theme
        </button>

        <!-- desktop: account menu (identity + roles + sign out). On mobile this
             content folds into the ☰ nav dropdown instead. -->
        <div v-if="!isMobile" ref="accountMenuRef" style="position:relative;display:flex;align-items:center">
          <button
            type="button"
            aria-haspopup="true"
            :aria-expanded="accountOpen"
            :title="accountLabel"
            style="display:flex;align-items:center;gap:5px;max-width:220px;background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 7px;cursor:pointer"
            @click="accountOpen = !accountOpen"
          >
            <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ accountLabel }}</span>
            <span style="color:var(--t-faint)">▾</span>
          </button>
          <div
            v-if="accountOpen"
            role="menu"
            style="position:absolute;top:34px;right:0;z-index:30;width:248px;background:var(--t-hdr);border:1px solid var(--t-line);box-shadow:0 8px 16px rgba(0,0,0,.25)"
          >
            <div style="padding:9px 12px;border-bottom:1px solid var(--t-line)">
              <div style="color:var(--t-faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em">signed in as</div>
              <div style="color:var(--t-text);font-size:12.5px;margin-top:3px;overflow-wrap:anywhere">
                {{ displayName || email || 'signed in' }}
              </div>
              <div
                v-if="email && displayName"
                style="color:var(--t-dim);font-size:11px;margin-top:1px;overflow-wrap:anywhere"
              >{{ email }}</div>
            </div>
            <div style="padding:9px 12px;border-bottom:1px solid var(--t-line)">
              <div style="color:var(--t-faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">roles</div>
              <div v-if="roles.length" style="display:flex;flex-wrap:wrap;gap:4px">
                <span
                  v-for="r in roles"
                  :key="r"
                  style="border:1px solid var(--t-line2);color:var(--t-dim);font-size:10.5px;padding:1px 6px;line-height:1.5;overflow-wrap:anywhere"
                >{{ r }}</span>
              </div>
              <div v-else style="color:var(--t-faint);font-size:11.5px;font-style:italic">no roles</div>
            </div>
            <button
              type="button"
              role="menuitem"
              style="display:block;width:100%;text-align:left;background:none;border:none;color:var(--t-text);font-family:inherit;font-size:12px;padding:9px 12px;cursor:pointer"
              @click="accountOpen = false; void signOut()"
            >
              sign out / switch account
            </button>
          </div>
        </div>
      </div>
    </header>

    <!-- content (1px gap grid background creates the hairline dividers) -->
    <div style="min-height:0;background:var(--t-line);overflow:hidden;position:relative">
      <RouterView />
    </div>

    <!-- footer status line -->
    <footer
      style="display:flex;align-items:center;height:26px;border-top:1px solid var(--t-line);background:var(--t-hdr);font-size:11px;color:var(--t-dim)"
    >
      <span
        style="background:var(--t-accent);color:var(--t-bg);font-weight:700;padding:0 9px;height:100%;display:flex;align-items:center"
      >NORMAL</span>
      <span style="padding:0 12px">prod-global · {{ footerScope }}</span>
      <span style="flex:1"></span>
      <span class="term-footer-hints" style="padding:0 12px;color:var(--t-faint)">[1-6] panes · [/] search · [t] theme · [esc] exit</span>
    </footer>
  </div>
</template>
