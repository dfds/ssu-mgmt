import { ref } from 'vue';
import { parsePath } from '../ssumgmt/api';

// A user-defined table column: a label plus a JSON path into each row's `raw`
// payload (same dotted/bracketed syntax as the query language, e.g.
// `requestParameters.roleName` or `tags["dfds.cost.centre"]`). Persisted per
// table so the user's columns survive reloads.
export interface CustomColumnDef {
  id: string; // `custom:<path>` — stable, so visibility/sizing key off it
  label: string;
  path: string;
}

function storageKeyFor(storageKey: string): string {
  return `${storageKey}-custom-columns-v1`;
}

function read(key: string): CustomColumnDef[] {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((c): c is CustomColumnDef =>
        c && typeof c.id === 'string' && typeof c.label === 'string' && typeof c.path === 'string',
      )
      .map((c) => ({ id: c.id, label: c.label, path: c.path }));
  } catch {
    return [];
  }
}

function write(key: string, cols: CustomColumnDef[]): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(cols));
  } catch {
    // Storage may be unavailable; silently ignore.
  }
}

export function useCustomColumns(storageKey: string) {
  const key = storageKeyFor(storageKey);
  const columns = ref<CustomColumnDef[]>(read(key));

  // Add a column. Returns an error string on invalid input, or null on success.
  function addColumn(label: string, path: string): string | null {
    const p = path.trim();
    const l = label.trim();
    if (!p) return 'path is required';
    if (parsePath(p).length === 0) return 'invalid path';
    const id = `custom:${p}`;
    if (columns.value.some((c) => c.id === id)) return 'column already added';
    columns.value = [...columns.value, { id, label: l || p, path: p }];
    write(key, columns.value);
    return null;
  }

  function removeColumn(id: string): void {
    columns.value = columns.value.filter((c) => c.id !== id);
    write(key, columns.value);
  }

  return { columns, addColumn, removeColumn };
}
