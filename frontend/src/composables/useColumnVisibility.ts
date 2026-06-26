import { ref } from 'vue';

// Per-table persisted column show/hide. The storage key is namespaced by the
// per-table `storageKey` so each console table persists independently. A column
// absent from storage defaults to visible.
function storageKeyFor(storageKey: string): string {
  return `${storageKey}-columns-v1`;
}

function readVisibility(
  knownIds: string[],
  key: string,
  defaultHidden: ReadonlySet<string>,
): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  let stored: Record<string, unknown> = {};
  try {
    const raw = window.localStorage.getItem(key);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        stored = parsed as Record<string, unknown>;
      }
    }
  } catch {
    // Ignore malformed storage; fall back to defaults.
  }
  for (const id of knownIds) {
    const s = stored[id];
    // A stored boolean wins; otherwise fall back to the column's default
    // (default-hidden columns start off, everything else starts visible).
    if (s === false) out[id] = false;
    else if (s === true) out[id] = true;
    else out[id] = !defaultHidden.has(id);
  }
  return out;
}

function writeVisibility(state: Record<string, boolean>, key: string): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(state));
  } catch {
    // Storage may be unavailable (private mode, quota); silently ignore.
  }
}

export function useColumnVisibility(
  knownIds: string[],
  storageKey: string,
  defaultHidden: readonly string[] = [],
) {
  const key = storageKeyFor(storageKey);
  const hidden = new Set(defaultHidden);
  const visibility = ref<Record<string, boolean>>(readVisibility(knownIds, key, hidden));

  function setColumn(id: string, visible: boolean): void {
    visibility.value = { ...visibility.value, [id]: visible };
    writeVisibility(visibility.value, key);
  }

  function setVisibility(next: Record<string, boolean>): void {
    const merged: Record<string, boolean> = {};
    for (const id of knownIds) merged[id] = next[id] !== false;
    visibility.value = merged;
    writeVisibility(visibility.value, key);
  }

  function setAll(value: boolean): void {
    const next: Record<string, boolean> = {};
    for (const id of knownIds) next[id] = value;
    visibility.value = next;
    writeVisibility(visibility.value, key);
  }

  function showAll(): void {
    setAll(true);
  }

  function hideAll(): void {
    setAll(false);
  }

  return { visibility, setColumn, setVisibility, showAll, hideAll };
}
