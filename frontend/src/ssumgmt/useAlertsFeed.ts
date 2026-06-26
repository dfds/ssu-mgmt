import { computed, ref, type ComputedRef, type Ref } from 'vue';
import {
  ackAlert,
  resolveAlert,
  unackAlert,
  unresolveAlert,
  fetchAlertsPage,
  fetchOverviewAlerts,
  fetchKpis,
  type Alert,
} from './api';
import { ForbiddenError } from '../api';
import { useConsoleStream } from './useConsoleStream';

export type AlertFilter = 'live' | 'all' | 'open' | 'acked' | 'resolved';
export type TriageAction = 'ack' | 'resolve' | 'unack' | 'unresolve';

export const ALERT_FILTERS: { key: AlertFilter; label: string }[] = [
  { key: 'live', label: 'live' },
  { key: 'all', label: 'all' },
  { key: 'open', label: 'open' },
  { key: 'acked', label: 'acked' },
  { key: 'resolved', label: 'resolved' },
];

export interface AlertsFeed {
  filter: Ref<AlertFilter>;
  rows: ComputedRef<Alert[]>;
  total: ComputedRef<number>;
  offset: Ref<number>;
  loading: Ref<boolean>;
  error: Ref<string | null>;
  forbidden: Ref<boolean>;
  pageStart: ComputedRef<number>;
  pageEnd: ComputedRef<number>;
  canPrev: ComputedRef<boolean>;
  canNext: ComputedRef<boolean>;
  paginated: ComputedRef<boolean>;
  pageSize: number;
  load: () => Promise<void>;
  setFilter: (f: AlertFilter) => void;
  prev: () => void;
  next: () => void;
  triage: (a: Alert, action: TriageAction) => Promise<void>;
}

export function useAlertsFeed(opts: { pageSize?: number; initialFilter?: AlertFilter } = {}): AlertsFeed {
  const pageSize = opts.pageSize ?? 50;
  // The live ticker + KPI tiles are the shared, WS-fed refs.
  const { alerts: liveAlerts, kpis } = useConsoleStream();

  const filter = ref<AlertFilter>(opts.initialFilter ?? 'live');
  const offset = ref(0);
  const pageRows = ref<Alert[]>([]);
  const pageTotal = ref(0);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const forbidden = ref(false);

  const paginated = computed(() => filter.value !== 'live');
  const rows = computed(() => (filter.value === 'live' ? liveAlerts.value : pageRows.value));
  const total = computed(() => (filter.value === 'live' ? liveAlerts.value.length : pageTotal.value));

  const pageStart = computed(() => (pageTotal.value === 0 ? 0 : offset.value + 1));
  const pageEnd = computed(() => Math.min(offset.value + pageRows.value.length, pageTotal.value));
  const canPrev = computed(() => paginated.value && offset.value > 0);
  const canNext = computed(() => paginated.value && offset.value + pageSize < pageTotal.value);

  // The status query param: 'all' → no facet (every status); 'live' never queries.
  function statusParam(): string | undefined {
    return filter.value === 'all' || filter.value === 'live' ? undefined : filter.value;
  }

  async function load(): Promise<void> {
    if (filter.value === 'live') return;
    loading.value = true;
    error.value = null;
    try {
      const res = await fetchAlertsPage({ status: statusParam(), limit: pageSize, offset: offset.value });
      pageRows.value = res.rows;
      pageTotal.value = res.total;
      forbidden.value = false;
    } catch (e) {
      if (e instanceof ForbiddenError) forbidden.value = true;
      else error.value = e instanceof Error ? e.message : String(e);
    } finally {
      loading.value = false;
    }
  }

  function setFilter(f: AlertFilter): void {
    if (f === filter.value) return;
    filter.value = f;
    offset.value = 0;
    void load();
  }

  function prev(): void {
    if (!canPrev.value) return;
    offset.value = Math.max(0, offset.value - pageSize);
    void load();
  }

  function next(): void {
    if (!canNext.value) return;
    offset.value += pageSize;
    void load();
  }

  async function triage(a: Alert, action: TriageAction): Promise<void> {
    try {
      if (action === 'ack') await ackAlert(a.id);
      else if (action === 'resolve') await resolveAlert(a.id);
      else if (action === 'unack') await unackAlert(a.id);
      else await unresolveAlert(a.id);
      if (filter.value === 'live') liveAlerts.value = await fetchOverviewAlerts({ limit: 12 });
      else await load();
      kpis.value = await fetchKpis();
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
    }
  }

  return {
    filter,
    rows,
    total,
    offset,
    loading,
    error,
    forbidden,
    pageStart,
    pageEnd,
    canPrev,
    canNext,
    paginated,
    pageSize,
    load,
    setFilter,
    prev,
    next,
    triage,
  };
}
