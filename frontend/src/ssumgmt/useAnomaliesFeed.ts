import { computed, ref, type ComputedRef, type Ref } from 'vue';
import { fetchAnomalies, type Anomaly } from './api';
import { ForbiddenError } from '../api';

// The four detector kinds, plus an "all" sentinel — drives the kind filter.
export const ANOMALY_KINDS: { key: string; label: string }[] = [
  { key: '', label: 'all kinds' },
  { key: 'volume_spike', label: 'volume spike' },
  { key: 'new_source', label: 'new source' },
  { key: 'new_country', label: 'new country' },
  { key: 'off_hours_spike', label: 'off-hours spike' },
];

export const ANOMALY_KIND_KEYS: readonly string[] = ANOMALY_KINDS.map((k) => k.key).filter(Boolean);

export interface AnomaliesFeed {
  kind: Ref<string>;
  rows: ComputedRef<Anomaly[]>;
  total: ComputedRef<number>;
  capped: ComputedRef<boolean>;
  offset: Ref<number>;
  loading: Ref<boolean>;
  error: Ref<string | null>;
  forbidden: Ref<boolean>;
  pageStart: ComputedRef<number>;
  pageEnd: ComputedRef<number>;
  canPrev: ComputedRef<boolean>;
  canNext: ComputedRef<boolean>;
  pageSize: number;
  load: () => Promise<void>;
  setKind: (k: string) => void;
  prev: () => void;
  next: () => void;
}

export function useAnomaliesFeed(opts: { pageSize?: number; limit?: number } = {}): AnomaliesFeed {
  const pageSize = opts.pageSize ?? 50;
  const fetchLimit = opts.limit ?? 500;

  const kind = ref('');
  const offset = ref(0);
  const all = ref<Anomaly[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const forbidden = ref(false);

  const total = computed(() => all.value.length);
  // A full page back means the window likely held more than we asked for.
  const capped = computed(() => all.value.length >= fetchLimit);
  const rows = computed(() => all.value.slice(offset.value, offset.value + pageSize));
  const pageStart = computed(() => (total.value === 0 ? 0 : offset.value + 1));
  const pageEnd = computed(() => Math.min(offset.value + pageSize, total.value));
  const canPrev = computed(() => offset.value > 0);
  const canNext = computed(() => offset.value + pageSize < total.value);

  async function load(): Promise<void> {
    loading.value = true;
    error.value = null;
    try {
      all.value = await fetchAnomalies({ kind: kind.value || undefined, limit: fetchLimit });
      // Clamp the page if the new result set is shorter than the prior offset.
      if (offset.value >= all.value.length) offset.value = 0;
      forbidden.value = false;
    } catch (e) {
      if (e instanceof ForbiddenError) forbidden.value = true;
      else error.value = e instanceof Error ? e.message : String(e);
    } finally {
      loading.value = false;
    }
  }

  function setKind(k: string): void {
    if (k === kind.value) return;
    kind.value = k;
    offset.value = 0;
    void load();
  }

  // Client-side pagination over the already-fetched window — no refetch.
  function prev(): void {
    if (canPrev.value) offset.value = Math.max(0, offset.value - pageSize);
  }
  function next(): void {
    if (canNext.value) offset.value += pageSize;
  }

  return {
    kind,
    rows,
    total,
    capped,
    offset,
    loading,
    error,
    forbidden,
    pageStart,
    pageEnd,
    canPrev,
    canNext,
    pageSize,
    load,
    setKind,
    prev,
    next,
  };
}
