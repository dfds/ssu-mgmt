import { ref } from 'vue';

const STORAGE_KEY = 'ssu-mgmt-theme';
type ThemeChoice = 'light' | 'dark' | 'system';

function readChoice(): ThemeChoice {
  const v = window.localStorage.getItem(STORAGE_KEY);
  return v === 'light' || v === 'dark' || v === 'system' ? v : 'system';
}

function systemPrefersDark(): boolean {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function applyTheme(dark: boolean): void {
  document.documentElement.classList.toggle('dark', dark);
}

// Module-level singleton: the theme is applied as soon as this module is first
// imported (which happens before the sign-in page or loading screen render), and
// every caller — the sign-in toggle and the in-app TopBar toggle alike — shares
// one source of truth plus a single system-preference listener.
const choice = ref<ThemeChoice>(readChoice());
const isDark = ref<boolean>(choice.value === 'system' ? systemPrefersDark() : choice.value === 'dark');

applyTheme(isDark.value);

const mql = window.matchMedia('(prefers-color-scheme: dark)');
mql.addEventListener('change', () => {
  if (choice.value === 'system') {
    isDark.value = mql.matches;
    applyTheme(isDark.value);
  }
});

function toggle(): void {
  const next: ThemeChoice = isDark.value ? 'light' : 'dark';
  choice.value = next;
  isDark.value = next === 'dark';
  window.localStorage.setItem(STORAGE_KEY, next);
  applyTheme(isDark.value);
}

export function useTheme() {
  return { isDark, toggle };
}
