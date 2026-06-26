import { ref } from 'vue';
import type { ColumnSizingState } from '@tanstack/vue-table';

// Per-table persisted column widths. The storage key is namespaced by the
// per-table `storageKey` so each console table (Query, Entity activity, Actors,
// Alerts) persists independently.
function storageKeyFor(storageKey: string): string {
  return `${storageKey}-column-sizing-v1`;
}

function readSizing(knownIds: string[], key: string): ColumnSizingState {
  const out: ColumnSizingState = {};
  try {
    const raw = window.localStorage.getItem(key);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        const stored = parsed as Record<string, unknown>;
        for (const id of knownIds) {
          const v = stored[id];
          if (typeof v === 'number' && Number.isFinite(v) && v > 0) {
            out[id] = v;
          }
        }
      }
    }
  } catch {
    // Ignore malformed storage; fall back to auto-fit.
  }
  return out;
}

function writeSizing(state: ColumnSizingState, key: string): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(state));
  } catch {
    // Storage may be unavailable (private mode, quota); silently ignore.
  }
}

export function useColumnSizing(knownIds: string[], storageKey: string) {
  const key = storageKeyFor(storageKey);
  const initial = readSizing(knownIds, key);
  const sizing = ref<ColumnSizingState>(initial);
  // True when a persisted layout was restored. The table treats this as a
  // user-chosen layout and skips the auto-fit that otherwise scales columns to
  // the container width on mount.
  const hasStored = Object.keys(initial).length > 0;

  function setSizing(next: ColumnSizingState): void {
    sizing.value = next;
    writeSizing(next, key);
  }

  function clear(): void {
    sizing.value = {};
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Storage may be unavailable; silently ignore.
    }
  }

  return { sizing, hasStored, setSizing, clear };
}
