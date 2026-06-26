<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useRoute, useRouter, type LocationQueryRaw } from 'vue-router';
import {
  fetchEvents,
  eventsExportCsvUrl,
  parseQuery,
  QUERY_FIELD_HELP,
  QUERY_EXAMPLES,
  type SsuMgmtEvent,
  type EventQueryParams,
  type OrderField,
} from '../ssumgmt/api';
import { ForbiddenError } from '../api';
import { sourceColor, statusColor, formatDateTime, formatMs, formatBytes } from '../ssumgmt/format';
import ConsoleTable from '../components/ConsoleTable.vue';
import { QUERY_COLUMNS } from '../ssumgmt/queryColumns';
import { type ConsoleColumn, rawPathAccessor } from '../ssumgmt/tableColumns';
import { useCustomColumns } from '../composables/useCustomColumns';

const STORAGE_KEY = 'ssumgmt-query';
const { columns: customColumns, addColumn, removeColumn } = useCustomColumns(STORAGE_KEY);

const columns = computed<ConsoleColumn<SsuMgmtEvent>[]>(() => [
  ...QUERY_COLUMNS,
  ...customColumns.value.map((c) => ({
    id: c.id,
    header: c.label,
    kind: 'custom' as const,
    size: 200,
    accessor: rawPathAccessor<SsuMgmtEvent>(c.path),
    format: 'text' as const,
    path: c.path,
    removable: true,
  })),
]);
const columnsKey = computed(() => columns.value.map((c) => c.id).join(','));

const serverSort = computed(() =>
  order.value ? { key: order.value.field as string, dir: order.value.dir } : null,
);
function onServerSort(key: string): void {
  toggleSort(key as OrderField);
}

const PAGE_SIZE = 50;

const route = useRoute();
const router = useRouter();

const DEFAULT_COUNT_CAP = '10000';

const queryText = ref('');
const sourceFilter = ref('');
const statusFilter = ref('');
const countCapText = ref(DEFAULT_COUNT_CAP);

const rows = ref<SsuMgmtEvent[]>([]);
const total = ref(0);
const totalCapped = ref(false);
const offset = ref(0);
const loading = ref(false);
const error = ref<string | null>(null);
const forbidden = ref(false);
const selected = ref<SsuMgmtEvent | null>(null);

// Exec readout: elapsed time (ticks while loading) + decoded response size.
const elapsedMs = ref(0);
const responseBytes = ref<number | null>(null);
let timerHandle: number | null = null;

let lastCountedSignature: string | null = null;

const searchInput = ref<HTMLInputElement | null>(null);
const showHelp = ref(false);

function useExample(ex: string): void {
  queryText.value = ex;
  showHelp.value = false;
  void run(true);
}

const parsed = computed(() => parseQuery(queryText.value));
const parseErrors = computed(() => parsed.value.errors);

// Parse the cap box: empty/invalid → 0 (unbounded exact count).
const countCapValue = computed(() => {
  const n = parseInt(countCapText.value, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
});

const params = computed<EventQueryParams>(() => ({
  ast: parsed.value.ast,
  source: sourceFilter.value || undefined,
  status: statusFilter.value || undefined,
  countCap: countCapValue.value,
  orderBy: parsed.value.order?.field,
  orderDir: parsed.value.order?.dir,
  limit: PAGE_SIZE,
  offset: offset.value,
}));

const order = computed(() => parsed.value.order);

function toggleSort(field: OrderField): void {
  let dir: 'asc' | 'desc';
  if (order.value?.field === field) dir = order.value.dir === 'asc' ? 'desc' : 'asc';
  else dir = field === 'ts' ? 'desc' : 'asc';
  const base = queryText.value.replace(/(?:^|\s)order\s+by\s+[a-z_]+(?:\s+(?:asc|desc))?\s*$/i, '').trim();
  queryText.value = `${base ? base + ' ' : ''}order by ${field} ${dir}`;
  void run(true);
}

const exportUrl = computed(() => eventsExportCsvUrl({ ...params.value, limit: undefined, offset: undefined }));

const pageStart = computed(() => (total.value === 0 ? 0 : offset.value + 1));
const pageEnd = computed(() => Math.min(offset.value + rows.value.length, total.value));
const canPrev = computed(() => offset.value > 0);
const canNext = computed(() => offset.value + PAGE_SIZE < total.value);

// --- URL state persistence -------------------------------------------------
function currentQuery(): LocationQueryRaw {
  const q: LocationQueryRaw = {};
  const t = queryText.value.trim();
  if (t) q.q = t;
  if (sourceFilter.value) q.source = sourceFilter.value;
  if (statusFilter.value) q.status = statusFilter.value;
  if (countCapText.value !== DEFAULT_COUNT_CAP) q.cap = countCapText.value;
  if (offset.value > 0) q.offset = String(offset.value);
  return q;
}

function readFromRoute(): void {
  queryText.value = (route.query.q as string) ?? '';
  sourceFilter.value = (route.query.source as string) ?? '';
  statusFilter.value = (route.query.status as string) ?? '';
  countCapText.value = (route.query.cap as string) ?? DEFAULT_COUNT_CAP;
  offset.value = Number(route.query.offset) || 0;
}

function routeMatchesState(): boolean {
  const q = currentQuery();
  return (
    ((route.query.q as string) ?? '') === ((q.q as string) ?? '') &&
    ((route.query.source as string) ?? '') === ((q.source as string) ?? '') &&
    ((route.query.status as string) ?? '') === ((q.status as string) ?? '') &&
    ((route.query.cap as string) ?? DEFAULT_COUNT_CAP) === ((q.cap as string) ?? DEFAULT_COUNT_CAP) &&
    (Number(route.query.offset) || 0) === (offset.value || 0)
  );
}

function syncUrl(): void {
  if (routeMatchesState()) return;
  void router.replace({ query: currentQuery() }).catch(() => {});
}

function stopTimer(): void {
  if (timerHandle !== null) {
    clearInterval(timerHandle);
    timerHandle = null;
  }
}

async function run(resetPage = true): Promise<void> {
  if (resetPage) offset.value = 0;
  syncUrl();
  loading.value = true;
  error.value = null;
  forbidden.value = false;
  const t0 = performance.now();
  elapsedMs.value = 0;
  responseBytes.value = null;
  stopTimer();
  timerHandle = window.setInterval(() => {
    elapsedMs.value = performance.now() - t0;
  }, 50);
  const sig = JSON.stringify([
    parsed.value.ast,
    sourceFilter.value,
    statusFilter.value,
    countCapValue.value,
    parsed.value.order?.field,
    parsed.value.order?.dir,
  ]);
  const wantCount = sig !== lastCountedSignature;
  try {
    const res = await fetchEvents({ ...params.value, count: wantCount });
    rows.value = res.rows;
    if (wantCount) {
      total.value = res.total ?? 0;
      totalCapped.value = res.total_capped ?? false;
      lastCountedSignature = sig;
    }
    responseBytes.value = res.bytes;
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
    else error.value = e instanceof Error ? e.message : String(e);
    rows.value = [];
    total.value = 0;
    totalCapped.value = false;
  } finally {
    stopTimer();
    elapsedMs.value = performance.now() - t0;
    loading.value = false;
  }
}

function onSubmit(): void {
  void run(true);
}

function setSource(s: string): void {
  sourceFilter.value = sourceFilter.value === s ? '' : s;
  void run(true);
}

function setStatus(s: string): void {
  statusFilter.value = statusFilter.value === s ? '' : s;
  void run(true);
}

function clearAll(): void {
  queryText.value = '';
  sourceFilter.value = '';
  statusFilter.value = '';
  void run(true);
}

function prev(): void {
  if (!canPrev.value) return;
  offset.value = Math.max(0, offset.value - PAGE_SIZE);
  void run(false);
}

function next(): void {
  if (!canNext.value) return;
  offset.value += PAGE_SIZE;
  void run(false);
}

const SOURCES = ['selfservice', 'cloudtrail', 'github', 'ssu-mgmt'];
const STATUSES = ['success', 'failure'];

function rawText(e: SsuMgmtEvent): string {
  if (e.raw == null) return '—';
  try {
    return JSON.stringify(e.raw, null, 2);
  } catch {
    return String(e.raw);
  }
}

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    if (selected.value) {
      selected.value = null;
      e.preventDefault();
    }
    return;
  }
  const el = e.target as HTMLElement | null;
  const typing = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
  if (e.key === '/' && !typing) {
    e.preventDefault();
    searchInput.value?.focus();
  }
}

watch(
  () => route.query,
  () => {
    if (routeMatchesState()) return;
    readFromRoute();
    void run(false);
  },
);

onMounted(() => {
  window.addEventListener('keydown', onKey);
  readFromRoute();
  void run(false);
});

onUnmounted(() => {
  window.removeEventListener('keydown', onKey);
  stopTimer();
});
</script>

<template>
  <div class="term-view-root" style="height:100%;display:grid;grid-template-rows:auto 1fr;gap:1px;background:var(--t-line);min-height:0">
    <!-- command bar -->
    <div style="background:var(--t-pane);padding:12px 14px">
      <form class="term-toolbar" style="display:flex;align-items:center;gap:10px" @submit.prevent="onSubmit">
        <span style="color:var(--t-accent);font-weight:700">search&nbsp;❯</span>
        <input
          ref="searchInput"
          v-model="queryText"
          spellcheck="false"
          placeholder='source=cloudtrail action:Console -action:AssumeRole  ·  press / to focus'
          style="flex:1;background:none;border:none;outline:none;color:var(--t-text);font-family:inherit;font-size:14px"
          :style="{ caretColor: 'var(--t-accent)' }"
        />
        <button
          type="submit"
          style="background:none;border:1px solid var(--t-accent-line);color:var(--t-accent);font-family:inherit;font-size:11.5px;padding:3px 12px;cursor:pointer"
        >run</button>
        <a
          :href="exportUrl"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11.5px;padding:3px 10px;cursor:pointer;text-decoration:none"
        >:csv</a>
        <button
          type="button"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11.5px;padding:3px 10px;cursor:pointer"
          @click="clearAll"
        >:clear</button>
        <button
          type="button"
          :style="{
            background: 'none',
            border: '1px solid ' + (showHelp ? 'var(--t-accent-line)' : 'var(--t-line2)'),
            color: showHelp ? 'var(--t-accent)' : 'var(--t-dim)',
          }"
          style="font-family:inherit;font-size:11.5px;padding:3px 10px;cursor:pointer"
          title="search syntax reference"
          @click="showHelp = !showHelp"
        >?syntax</button>
      </form>

      <!-- facets -->
      <div style="display:flex;align-items:center;gap:6px;margin-top:10px;flex-wrap:wrap">
        <span style="color:var(--t-faint);font-size:11px">--source</span>
        <button
          v-for="s in SOURCES"
          :key="s"
          type="button"
          :style="{
            background: sourceFilter === s ? 'var(--t-accent-soft)' : 'none',
            border: '1px solid ' + (sourceFilter === s ? 'var(--t-accent-line)' : 'var(--t-line2)'),
            color: sourceFilter === s ? 'var(--t-accent)' : 'var(--t-dim)',
          }"
          style="font-family:inherit;font-size:11px;padding:2px 9px;cursor:pointer"
          @click="setSource(s)"
        >{{ s }}</button>

        <span style="color:var(--t-faint);font-size:11px;margin-left:10px">--status</span>
        <button
          v-for="s in STATUSES"
          :key="s"
          type="button"
          :style="{
            background: statusFilter === s ? 'var(--t-accent-soft)' : 'none',
            border: '1px solid ' + (statusFilter === s ? 'var(--t-accent-line)' : 'var(--t-line2)'),
            color: statusFilter === s ? statusColor(s) : 'var(--t-dim)',
          }"
          style="font-family:inherit;font-size:11px;padding:2px 9px;cursor:pointer"
          @click="setStatus(s)"
        >{{ s }}</button>

        <span style="color:var(--t-faint);font-size:11px;margin-left:10px">--max</span>
        <input
          v-model="countCapText"
          spellcheck="false"
          inputmode="numeric"
          placeholder="∞"
          title="rows to count before reporting N+ · default 10000 · blank = exact (unbounded) count — slower"
          style="width:64px;background:var(--t-inset);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:11px;padding:2px 6px;outline:none"
          @keydown.enter.prevent="onSubmit"
        />

        <span style="color:var(--t-faint);font-size:10.5px;margin-left:10px">status facet only meaningful for CloudTrail</span>
      </div>

      <div
        v-if="showHelp"
        style="margin-top:10px;border:1px solid var(--t-line2);background:var(--t-inset);padding:10px 12px;font-size:11.5px;line-height:1.6;max-height:38vh;overflow:auto"
      >
        <div style="color:var(--t-faint);font-size:10.5px;letter-spacing:.08em;margin-bottom:6px">OPERATORS</div>
        <div style="display:grid;grid-template-columns:auto 1fr;gap:2px 14px;align-items:baseline">
          <code style="color:var(--t-accent)">field:value</code><span style="color:var(--t-dim)">substring match (so does <code style="color:var(--t-text)">~</code>)</span>
          <code style="color:var(--t-accent)">field=value</code><span style="color:var(--t-dim)">exact match</span>
          <code style="color:var(--t-accent)">field!=value</code><span style="color:var(--t-dim)">exact, negated (<code style="color:var(--t-text)">!~</code> = not-substring)</span>
          <code style="color:var(--t-accent)">-field:value</code><span style="color:var(--t-dim)">negate (also <code style="color:var(--t-text)">NOT term</code>)</span>
          <code style="color:var(--t-accent)">json.path &gt;= n</code><span style="color:var(--t-dim)">JSON path / ts compare: <code style="color:var(--t-text)">&gt; &gt;= &lt; &lt;=</code></span>
          <code style="color:var(--t-accent)">raw:term</code><span style="color:var(--t-dim)">free-text over the raw payload</span>
          <code style="color:var(--t-accent)">order by f [asc|desc]</code><span style="color:var(--t-dim)">sort results (or click a column header)</span>
        </div>

        <div style="color:var(--t-dim);margin-top:8px">
          combine with <code style="color:var(--t-text)">AND</code> / <code style="color:var(--t-text)">OR</code> (bare space = AND) and
          <code style="color:var(--t-text)">( … )</code> groups · quote values with spaces:
          <code style="color:var(--t-text)">actor:"john doe"</code> · bracket dotted JSON keys:
          <code style="color:var(--t-text)">json.tags["dfds.cost.centre"]</code>
        </div>

        <div style="color:var(--t-faint);font-size:10.5px;letter-spacing:.08em;margin:10px 0 4px">FIELDS</div>
        <div style="display:grid;grid-template-columns:auto 1fr;gap:2px 14px;align-items:baseline">
          <template v-for="f in QUERY_FIELD_HELP" :key="f.field">
            <code style="color:var(--t-accent)">{{ f.field }}</code>
            <span style="color:var(--t-dim)">{{ f.values ? '{' + f.values.join(' | ') + '}' : '' }}</span>
          </template>
          <code style="color:var(--t-accent)">ts</code><span style="color:var(--t-dim)">event time — compare e.g. <code style="color:var(--t-text)">ts &gt;= 2026-06-20</code></span>
          <code style="color:var(--t-accent)">json.&lt;path&gt;</code><span style="color:var(--t-dim)">any key in the raw payload, e.g. <code style="color:var(--t-text)">json.requestParameters.roleName</code></span>
        </div>

        <div style="color:var(--t-faint);font-size:10.5px;margin-top:8px">
          the <code style="color:var(--t-dim)">--source</code> / <code style="color:var(--t-dim)">--status</code> facet buttons above are exact-match shortcuts ANDed onto the query.
          <code style="color:var(--t-dim)">--max</code> bounds the result count (default 10000, shown as <code style="color:var(--t-dim)">N+</code>); clear it for an exact count, or narrow with <code style="color:var(--t-dim)">ts &gt;= …</code> to speed up rare-match searches.
        </div>

        <div style="color:var(--t-faint);font-size:10.5px;letter-spacing:.08em;margin:10px 0 4px">EXAMPLES</div>
        <div style="display:flex;flex-direction:column;gap:2px;align-items:flex-start">
          <button
            v-for="ex in QUERY_EXAMPLES"
            :key="ex"
            type="button"
            class="q-example"
            style="background:none;border:none;padding:0;cursor:pointer;font-family:inherit;font-size:11.5px;color:var(--t-dim);text-align:left"
            @click="useExample(ex)"
          ><span style="color:var(--t-accent)">›</span> {{ ex }}</button>
        </div>
      </div>

      <div v-if="parseErrors.length" style="margin-top:8px;color:var(--t-amber);font-size:11px">
        {{ parseErrors.join(' · ') }}
      </div>
    </div>

    <!-- results -->
    <div class="term-pane-scroll" style="background:var(--t-pane);display:flex;flex-direction:column;min-height:0;min-width:0">
      <div
        class="term-toolbar"
        style="display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid var(--t-line);flex:none;font-size:11.5px"
      >
        <span style="color:var(--t-accent)">▌</span>
        <span style="font-weight:600;letter-spacing:.08em">RESULTS</span>
        <span style="color:var(--t-faint)">
          {{ pageStart }}–{{ pageEnd }} of {{ total.toLocaleString() }}<span v-if="totalCapped" :title="'count stopped at ' + total.toLocaleString() + ' — raise --max or clear it for an exact count'">+</span>
        </span>
        <span v-if="loading" style="color:var(--t-accent)">⏱ {{ formatMs(elapsedMs) }}</span>
        <span v-else-if="responseBytes !== null" style="color:var(--t-faint)">
          ⏱ {{ formatMs(elapsedMs) }} · {{ formatBytes(responseBytes) }}
        </span>
        <span style="flex:1"></span>
        <button
          type="button"
          :disabled="!canPrev"
          :style="{ opacity: canPrev ? 1 : 0.4, cursor: canPrev ? 'pointer' : 'default' }"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 9px"
          @click="prev"
        >← prev</button>
        <button
          type="button"
          :disabled="!canNext"
          :style="{ opacity: canNext ? 1 : 0.4, cursor: canNext ? 'pointer' : 'default' }"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 9px"
          @click="next"
        >next →</button>
      </div>

      <div v-if="forbidden" style="overflow:auto;min-height:0;padding:40px;text-align:center;color:var(--t-dim)">
        You need the <code>ce.cloudengineer</code> role to view the console.
      </div>
      <div v-else-if="error" style="overflow:auto;min-height:0;padding:40px;text-align:center;color:var(--t-red)">{{ error }}</div>
      <div v-else style="flex:1;min-height:0;min-width:0;display:flex">
        <ConsoleTable
          :key="columnsKey"
          :columns="columns"
          :rows="rows"
          :row-key="(e: SsuMgmtEvent) => e.source + e.uid"
          :storage-key="STORAGE_KEY"
          :server-sort="serverSort"
          :loading="loading"
          enable-custom-columns
          :on-add-custom="addColumn"
          :on-remove-custom="removeColumn"
          empty-text="no matching events"
          @row-click="(e: SsuMgmtEvent) => (selected = e)"
          @server-sort="onServerSort"
        />
      </div>
    </div>

    <!-- detail modal -->
    <div
      v-if="selected"
      style="position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:24px"
      @click.self="selected = null"
    >
      <div
        class="term"
        style="width:min(760px,100%);max-height:80vh;overflow:auto;background:var(--t-pane);border:1px solid var(--t-line2)"
      >
        <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--t-line)">
          <span :style="{ color: sourceColor(selected.source) }">{{ selected.source }}</span>
          <span style="color:var(--t-text);font-weight:600">{{ selected.action }}</span>
          <span style="flex:1"></span>
          <button
            type="button"
            style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer"
            @click="selected = null"
          >[esc]</button>
        </div>
        <div style="padding:14px 16px;display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:12px">
          <span style="color:var(--t-faint)">uid</span><span style="color:var(--t-text)">{{ selected.uid }}</span>
          <span style="color:var(--t-faint)">ts</span><span style="color:var(--t-text)">{{ formatDateTime(selected.ts) }}</span>
          <span style="color:var(--t-faint)">actor</span><span style="color:var(--t-text)">{{ selected.actor ?? '—' }}</span>
          <span style="color:var(--t-faint)">resource</span><span style="color:var(--t-text)">{{ selected.resource ?? '—' }}</span>
          <span style="color:var(--t-faint)">source_ip</span><span style="color:var(--t-text)">{{ selected.source_ip ?? '—' }}</span>
          <span style="color:var(--t-faint)">level</span><span style="color:var(--t-text)">{{ selected.level }}</span>
          <span style="color:var(--t-faint)">status</span><span :style="{ color: statusColor(selected.status) }">{{ selected.status }}</span>
          <template v-if="selected.identity_source">
            <span style="color:var(--t-faint)">identity src</span><span style="color:var(--t-text)">{{ selected.identity_source }}</span>
          </template>
          <template v-if="selected.role">
            <span style="color:var(--t-faint)">assumed role</span><span style="color:var(--t-text);word-break:break-all">{{ selected.role }}</span>
          </template>
          <template v-if="selected.account_id">
            <span style="color:var(--t-faint)">account</span><span style="color:var(--t-text)">{{ selected.account_id }}</span>
          </template>
          <template v-if="selected.caller_account_id">
            <span style="color:var(--t-faint)">caller account</span><span style="color:var(--t-text)">{{ selected.caller_account_id }}</span>
          </template>
        </div>
        <div style="padding:0 16px 16px">
          <div style="color:var(--t-faint);font-size:10.5px;letter-spacing:.06em;margin-bottom:6px">RAW</div>
          <pre style="margin:0;padding:12px;background:var(--t-inset);border:1px solid var(--t-line);overflow:auto;font-size:11.5px;color:var(--t-dim);white-space:pre-wrap;word-break:break-word">{{ rawText(selected) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.q-example:hover {
  color: var(--t-accent) !important;
}
</style>
