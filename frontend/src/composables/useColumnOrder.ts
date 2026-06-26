import { ref } from 'vue';
import type { ColumnOrderState } from '@tanstack/vue-table';

function storageKeyFor(storageKey: string): string {
  return `${storageKey}-column-order-v1`;
}

function readOrder(knownIds: string[], key: string): ColumnOrderState {
  let stored: unknown = null;
  try {
    const raw = window.localStorage.getItem(key);
    if (raw) stored = JSON.parse(raw);
  } catch {
    // Ignore malformed storage; fall back to natural order.
  }
  const known = new Set(knownIds);
  const seen = new Set<string>();
  const out: string[] = [];
  if (Array.isArray(stored)) {
    for (const id of stored) {
      if (typeof id === 'string' && known.has(id) && !seen.has(id)) {
        out.push(id);
        seen.add(id);
      }
    }
  }
  // Append any known id absent from storage (new/custom column) in natural order.
  for (const id of knownIds) {
    if (!seen.has(id)) out.push(id);
  }
  return out;
}

function writeOrder(state: ColumnOrderState, key: string): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(state));
  } catch {
    // Storage may be unavailable (private mode, quota); silently ignore.
  }
}

export function useColumnOrder(knownIds: string[], storageKey: string) {
  const key = storageKeyFor(storageKey);
  const order = ref<ColumnOrderState>(readOrder(knownIds, key));

  function setOrder(next: ColumnOrderState): void {
    order.value = next;
    writeOrder(next, key);
  }

  function move(dragId: string, targetId: string): void {
    if (dragId === targetId) return;
    const cur = [...order.value];
    const from = cur.indexOf(dragId);
    const to = cur.indexOf(targetId);
    if (from < 0 || to < 0) return;
    cur.splice(from, 1);
    let idx = cur.indexOf(targetId);
    if (from < to) idx += 1;
    cur.splice(idx, 0, dragId);
    setOrder(cur);
  }

  function clear(): void {
    order.value = [...knownIds];
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Storage may be unavailable; silently ignore.
    }
  }

  return { order, move, setOrder, clear };
}
