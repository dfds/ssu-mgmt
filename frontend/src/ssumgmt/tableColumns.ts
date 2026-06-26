import { parsePath } from './api';

export type CellFormat =
  | 'text'
  | 'datetime'
  | 'time'
  | 'relage'
  | 'source'
  | 'status'
  | 'mono'
  | 'ip'
  | 'risk'
  | 'severity';

export type ColumnKind = 'normalized' | 'raw' | 'custom';

export interface ConsoleColumn<Row = any> {
  // Stable id. Custom columns use `custom:<path>`; the persistence composables
  // (visibility/sizing) key off it, so it must round-trip across reloads.
  id: string;
  // Header label (rendered UPPERCASE in the th).
  header: string;
  kind: ColumnKind;
  // Proportional default width (weights scaled to fill the container on mount).
  size: number;
  // Value getter. normalized: row[field]; raw/custom: walks row.raw by path.
  accessor: (row: Row) => unknown;
  // Cell rendering hook. Default 'text' shows '—' when empty.
  format?: CellFormat;
  serverSortKey?: string;
  defaultHidden?: boolean;
  // Custom columns only — the JSON path, persisted so the column round-trips.
  path?: string;
  // Custom columns only — show a remove affordance in the columns menu.
  removable?: boolean;
  // Optional per-column min width and cell alignment.
  minSize?: number;
  align?: 'left' | 'right';
}

// Walk a `raw` jsonb payload by a dotted/bracketed path (same syntax as the
// query language). Returns undefined on any missing segment.
export function rawPathAccessor<Row extends { raw?: unknown }>(path: string): (row: Row) => unknown {
  const segs = parsePath(path);
  return (row) => {
    let cur: unknown = row?.raw;
    for (const s of segs) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = (cur as Record<string, unknown>)[s];
    }
    return cur;
  };
}

export function displayValue(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'object') {
    try {
      return JSON.stringify(v);
    } catch {
      return String(v);
    }
  }
  return String(v);
}
