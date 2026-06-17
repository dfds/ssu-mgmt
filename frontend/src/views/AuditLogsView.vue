<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import {
  auditExportCsvUrl,
  auditFilterFromParams,
  auditFilterToParams,
  fetchAuditLog,
  fetchAuditLogs,
  PAGE_SIZE_DEFAULT,
  type AuditEntry,
  type AuditFilter,
  type AuditRule,
  type AuditRuleField,
  type AuditRuleOp,
} from '../api';
import { getAccessToken } from '../auth/useAuth';
import { useAuth } from '../auth/useAuth';
import TopBar from '../components/TopBar.vue';
import {
  countClauses,
  parse as parseKql,
  queryToRules,
  rulesToQuery,
  type ParseError,
} from '../audit/kql';

const { roles } = useAuth();
const canAdmin = computed(() => roles.value.includes('ce.cloudengineer'));

const PAGE_SIZE = PAGE_SIZE_DEFAULT;
const LS_MODE = 'ssu-mgmt-audit-mode';
const LS_QUERY = 'ssu-mgmt-audit-query';

const route = useRoute();
const router = useRouter();

function routeQueryToParams(): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(route.query)) {
    if (value == null) continue;
    if (Array.isArray(value)) {
      for (const v of value) {
        if (v != null) params.append(key, String(v));
      }
    } else {
      params.append(key, String(value));
    }
  }
  return params;
}

const FIELD_LABELS: Record<AuditRuleField, string> = {
  principal: 'principal',
  service: 'service',
  action: 'action',
  method: 'method',
  path: 'path',
  type: 'type',
};
const FIELD_OPTIONS = Object.keys(FIELD_LABELS) as AuditRuleField[];

const OP_LABELS: Record<AuditRuleOp, string> = {
  contains: 'contains',
  not_contains: 'does not contain',
  equals: 'equals',
  not_equals: 'does not equal',
};

function opsFor(field: AuditRuleField): AuditRuleOp[] {
  if (field === 'method' || field === 'service' || field === 'type') {
    return ['equals', 'not_equals'];
  }
  return ['contains', 'not_contains', 'equals', 'not_equals'];
}

const METHOD_SUGGESTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

function initialMode(): 'rules' | 'query' {
  try {
    const v = localStorage.getItem(LS_MODE);
    if (v === 'query' || v === 'rules') return v;
  } catch { /* ignore */ }
  return 'rules';
}

function initialQuery(): string {
  try {
    return localStorage.getItem(LS_QUERY) ?? '';
  } catch { return ''; }
}

function buildInitialFilter(): AuditFilter {
  const base: AuditFilter = {
    mode: initialMode(),
    rules: [],
    match: 'all',
    query: initialQuery(),
    from: '',
    to: '',
    limit: PAGE_SIZE,
    offset: 0,
  };
  return { ...base, ...auditFilterFromParams(routeQueryToParams()) };
}

const filter = reactive<AuditFilter>(buildInitialFilter());

function syncUrl(): void {
  const params = auditFilterToParams(filter, { omitDefaults: true });
  const next: Record<string, string | string[]> = {};
  for (const key of new Set(params.keys())) {
    const values = params.getAll(key);
    next[key] = values.length > 1 ? values : values[0];
  }
  if (sameQuery(next, route.query)) return;
  void router.replace({ query: next });
}

function sameQuery(
  a: Record<string, string | string[]>,
  b: Record<string, string | string[] | null | (string | null)[]>,
): boolean {
  const ak = Object.keys(a);
  const bk = Object.keys(b).filter((k) => b[k] != null);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    const av = Array.isArray(a[k]) ? (a[k] as string[]) : [a[k] as string];
    const raw = b[k];
    const bv = raw == null
      ? []
      : Array.isArray(raw)
        ? (raw.filter((v) => v != null) as string[])
        : [String(raw)];
    if (av.length !== bv.length) return false;
    for (let i = 0; i < av.length; i++) {
      if (av[i] !== bv[i]) return false;
    }
  }
  return true;
}

const rows = ref<AuditEntry[]>([]);
const total = ref(0);
const loading = ref(false);
const error = ref<string | null>(null);
const exporting = ref(false);

const selected = ref<AuditEntry | null>(null);
const selectedLoading = ref(false);
const selectedError = ref<string | null>(null);

const queryParseError = ref<ParseError | null>(null);
const queryClauseCount = ref(0);
let parseTimer: number | null = null;

function recomputeParse(): void {
  const q = (filter.query ?? '').trim();
  if (!q) {
    queryParseError.value = null;
    queryClauseCount.value = 0;
    return;
  }
  const res = parseKql(q);
  if ('error' in res) {
    queryParseError.value = res.error;
    queryClauseCount.value = 0;
  } else {
    queryParseError.value = null;
    queryClauseCount.value = countClauses(res.ast);
  }
}

watch(
  () => filter.query,
  () => {
    if (parseTimer != null) window.clearTimeout(parseTimer);
    parseTimer = window.setTimeout(recomputeParse, 150);
    try { localStorage.setItem(LS_QUERY, filter.query ?? ''); } catch { /* ignore */ }
  },
);

watch(
  () => filter.mode,
  (m) => {
    try { localStorage.setItem(LS_MODE, m); } catch { /* ignore */ }
  },
);

// Project the current query-mode text into rules right before any backend
// call. The server only understands rule params; AuditLogsView is the place
// that owns the parser, so the projection lives here rather than in api.ts.
function projectToRulesForSubmit(): boolean {
  if (filter.mode !== 'query') return true;
  const q = (filter.query ?? '').trim();
  if (!q) {
    filter.rules = [];
    filter.match = 'all';
    return true;
  }
  const res = parseKql(q);
  if ('error' in res) {
    queryParseError.value = res.error;
    error.value = `Query error at offset ${res.error.offset}: ${res.error.message}`;
    return false;
  }
  const projected = queryToRules(res.ast);
  if (projected.complex) {
    error.value = 'Query has nested groups or wildcards that cannot be sent to the server. Simplify or switch to rules mode.';
    return false;
  }
  filter.rules = projected.rules;
  filter.match = projected.match;
  return true;
}

async function load(): Promise<void> {
  syncUrl();
  if (!projectToRulesForSubmit()) return;
  loading.value = true;
  error.value = null;
  try {
    const res = await fetchAuditLogs({ ...filter });
    rows.value = res.rows;
    total.value = res.total;
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

function applyFilters(): void {
  filter.offset = 0;
  void load();
}

function resetFilters(): void {
  filter.rules = [];
  filter.match = 'all';
  filter.query = '';
  filter.from = '';
  filter.to = '';
  filter.offset = 0;
  recomputeParse();
  void load();
}

function addRule(field: AuditRuleField = 'principal'): void {
  const op = opsFor(field)[0];
  filter.rules.push({ field, op, value: '' });
}

function removeRule(idx: number): void {
  filter.rules.splice(idx, 1);
}

function onFieldChange(rule: AuditRule): void {
  if (!opsFor(rule.field).includes(rule.op)) {
    rule.op = opsFor(rule.field)[0];
  }
}

function valuePlaceholder(field: AuditRuleField): string {
  switch (field) {
    case 'principal': return 'user@dfds.com';
    case 'service': return 'capsvc';
    case 'action': return 'capability.created';
    case 'path': return '/api/v1/capabilities';
    case 'method': return 'GET';
    case 'type': return 'request';
    default: return '';
  }
}

function switchToQuery(): void {
  if (filter.mode === 'query') return;
  const text = rulesToQuery(filter.rules, filter.match);
  filter.query = text;
  filter.mode = 'query';
  recomputeParse();
  syncUrl();
}

function switchToRules(): void {
  if (filter.mode === 'rules') return;
  const q = (filter.query ?? '').trim();
  if (!q) {
    filter.rules = [];
    filter.match = 'all';
    filter.mode = 'rules';
    syncUrl();
    return;
  }
  const res = parseKql(q);
  if ('error' in res) {
    queryParseError.value = res.error;
    error.value = `Cannot switch to rules: parse error at offset ${res.error.offset}: ${res.error.message}`;
    return;
  }
  const projected = queryToRules(res.ast);
  if (projected.complex) {
    const proceed = window.confirm(
      'This query has nested groups or wildcards that the rule editor cannot represent.\n\nSwitching to rules will discard the query. Continue?',
    );
    if (!proceed) return;
    filter.rules = [];
    filter.match = 'all';
  } else {
    filter.rules = projected.rules;
    filter.match = projected.match;
  }
  filter.mode = 'rules';
  syncUrl();
}

const pageStart = computed(() => (total.value === 0 ? 0 : (filter.offset ?? 0) + 1));
const pageEnd = computed(() => Math.min(((filter.offset ?? 0) + (filter.limit ?? PAGE_SIZE)), total.value));
const canPrev = computed(() => (filter.offset ?? 0) > 0);
const canNext = computed(() => (filter.offset ?? 0) + (filter.limit ?? PAGE_SIZE) < total.value);

function prevPage(): void {
  filter.offset = Math.max(0, (filter.offset ?? 0) - (filter.limit ?? PAGE_SIZE));
  void load();
}
function nextPage(): void {
  filter.offset = (filter.offset ?? 0) + (filter.limit ?? PAGE_SIZE);
  void load();
}

async function openRow(row: AuditEntry): Promise<void> {
  selected.value = row;
  selectedError.value = null;
  selectedLoading.value = true;
  try {
    selected.value = await fetchAuditLog(row.id);
  } catch (e) {
    selectedError.value = e instanceof Error ? e.message : String(e);
  } finally {
    selectedLoading.value = false;
  }
}

function closeDetail(): void {
  selected.value = null;
  selectedError.value = null;
}

async function exportCsv(): Promise<void> {
  if (!projectToRulesForSubmit()) return;
  exporting.value = true;
  try {
    const token = await getAccessToken();
    if (!token) throw new Error('Not signed in.');
    const res = await fetch(auditExportCsvUrl({ ...filter, limit: undefined, offset: undefined }), {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`Export failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssu-audit-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    exporting.value = false;
  }
}

function formatDate(s: string): string {
  if (!s) return '';
  // Backend serializes NaiveDateTime as ISO without a Z suffix; treat it as UTC.
  const iso = /[Zz]|[+\-]\d{2}:?\d{2}$/.test(s) ? s : `${s}Z`;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return s;
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

function formatBody(value: unknown): string {
  if (value == null) return '—';
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

onMounted(() => {
  recomputeParse();
  if (canAdmin.value) void load();
});
</script>

<template>
  <TopBar title="Audit Log" subtitle="cloudengineering.selfservice.audit" />
  <main class="px-5 md:px-8 py-6">
    <div
      v-if="!canAdmin"
      class="bg-[var(--color-surface)] border border-[var(--color-border-card)] rounded-[8px] shadow-[var(--shadow-card)] p-6 text-sm text-[var(--color-text-secondary)]"
    >
      <p class="m-0 mb-3">You need the <code>ce.cloudengineer</code> role to view audit logs.</p>
      <RouterLink :to="{ name: 'home' }" class="btn-outline">Back to home</RouterLink>
    </div>

    <section
      v-else
      class="bg-[var(--color-surface)] border border-[var(--color-border-card)] rounded-[8px] shadow-[var(--shadow-card)] overflow-hidden"
    >
      <header
        class="flex items-center gap-3 px-4 py-2.5 border-b border-[var(--color-border-divider)] flex-wrap"
      >
        <h2 class="text-base font-semibold text-[var(--color-text-primary)] m-0">Audit Log</h2>
        <span class="text-sm text-[var(--color-text-secondary)]">
          {{ total.toLocaleString() }} {{ total === 1 ? 'entry' : 'entries' }}
        </span>
        <span class="flex-1"></span>
        <div class="inline-flex rounded-[6px] overflow-hidden border border-[var(--color-border-card)]">
          <button
            type="button"
            class="px-3 py-1.5 text-[13px] font-mono uppercase tracking-[0.06em]"
            :class="filter.mode === 'rules'
              ? 'bg-[var(--color-action)] text-white'
              : 'bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'"
            @click="switchToRules"
          >Rules</button>
          <button
            type="button"
            class="px-3 py-1.5 text-[13px] font-mono uppercase tracking-[0.06em] border-l border-[var(--color-border-card)]"
            :class="filter.mode === 'query'
              ? 'bg-[var(--color-action)] text-white'
              : 'bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'"
            @click="switchToQuery"
          >Query</button>
        </div>
        <button class="btn-outline" type="button" :disabled="loading" @click="load">Refresh</button>
        <button class="btn-outline" type="button" :disabled="exporting || total === 0" @click="exportCsv">
          {{ exporting ? 'Exporting…' : 'Export CSV' }}
        </button>
      </header>

      <form
        class="flex flex-col gap-3 px-4 py-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface-muted)]"
        @submit.prevent="applyFilters"
      >
        <div class="flex flex-wrap items-end gap-3">
          <label v-if="filter.mode === 'rules'" class="flex flex-col gap-1 text-[11px] font-mono uppercase tracking-[0.06em] text-[var(--color-text-muted)]">
            <span>match</span>
            <select
              v-model="filter.match"
              class="px-2 py-1.5 rounded-[4px] border border-[var(--color-border-card)] bg-[var(--color-surface)] text-[13px] font-normal normal-case tracking-normal text-[var(--color-text-primary)]"
            >
              <option value="all">ALL of the rules</option>
              <option value="any">ANY of the rules</option>
            </select>
          </label>
          <label class="flex flex-col gap-1 text-[11px] font-mono uppercase tracking-[0.06em] text-[var(--color-text-muted)]">
            <span>from</span>
            <input
              v-model="filter.from"
              type="datetime-local"
              class="px-2 py-1.5 rounded-[4px] border border-[var(--color-border-card)] bg-[var(--color-surface)] text-[13px] font-normal normal-case tracking-normal text-[var(--color-text-primary)]"
            />
          </label>
          <label class="flex flex-col gap-1 text-[11px] font-mono uppercase tracking-[0.06em] text-[var(--color-text-muted)]">
            <span>to</span>
            <input
              v-model="filter.to"
              type="datetime-local"
              class="px-2 py-1.5 rounded-[4px] border border-[var(--color-border-card)] bg-[var(--color-surface)] text-[13px] font-normal normal-case tracking-normal text-[var(--color-text-primary)]"
            />
          </label>
          <span class="flex-1"></span>
          <p
            v-if="filter.mode === 'rules' && filter.match === 'any' && filter.rules.some((r) => r.op === 'not_contains' || r.op === 'not_equals')"
            class="text-[11px] text-[var(--color-text-muted)] max-w-[28ch] leading-snug"
          >
            Note: exclude rules always apply (AND-NOT) regardless of match mode.
          </p>
        </div>

        <datalist id="audit-method-list">
          <option v-for="m in METHOD_SUGGESTIONS" :key="m" :value="m" />
        </datalist>

        <div v-if="filter.mode === 'rules'" class="flex flex-col gap-2">
          <p v-if="!filter.rules.length" class="text-[12px] text-[var(--color-text-muted)] italic m-0">
            No rules — showing every entry (subject to time range). Add a rule to filter.
          </p>
          <div
            v-for="(rule, idx) in filter.rules"
            :key="idx"
            class="flex flex-wrap items-center gap-2"
          >
            <select
              v-model="rule.field"
              class="px-2 py-1.5 rounded-[4px] border border-[var(--color-border-card)] bg-[var(--color-surface)] text-[13px] text-[var(--color-text-primary)] min-w-[140px]"
              @change="onFieldChange(rule)"
            >
              <option v-for="f in FIELD_OPTIONS" :key="f" :value="f">{{ FIELD_LABELS[f] }}</option>
            </select>
            <select
              v-model="rule.op"
              class="px-2 py-1.5 rounded-[4px] border border-[var(--color-border-card)] bg-[var(--color-surface)] text-[13px] text-[var(--color-text-primary)] min-w-[170px]"
            >
              <option v-for="op in opsFor(rule.field)" :key="op" :value="op">{{ OP_LABELS[op] }}</option>
            </select>
            <input
              v-model.trim="rule.value"
              type="text"
              :placeholder="valuePlaceholder(rule.field)"
              :list="rule.field === 'method' ? 'audit-method-list' : undefined"
              class="flex-1 min-w-[200px] px-2 py-1.5 rounded-[4px] border border-[var(--color-border-card)] bg-[var(--color-surface)] text-[13px] text-[var(--color-text-primary)]"
            />
            <button
              class="btn-ghost-icon"
              type="button"
              :aria-label="`Remove rule ${idx + 1}`"
              @click="removeRule(idx)"
            >×</button>
          </div>
        </div>

        <div v-else class="flex flex-col gap-1">
          <textarea
            v-model="filter.query"
            rows="3"
            spellcheck="false"
            autocomplete="off"
            placeholder='principal:*dfds.com* AND NOT action:"capability.deleted"'
            class="w-full px-2 py-1.5 rounded-[4px] border bg-[var(--color-surface)] text-[13px] font-mono leading-snug text-[var(--color-text-primary)] resize-y min-h-[60px]"
            :class="queryParseError ? 'border-[var(--color-error)]' : 'border-[var(--color-border-card)]'"
          ></textarea>
          <p
            v-if="queryParseError"
            class="text-[11px] font-mono text-[var(--color-error)] m-0"
          >▲ offset {{ queryParseError.offset }}: {{ queryParseError.message }}</p>
          <p
            v-else-if="(filter.query ?? '').trim()"
            class="text-[11px] font-mono text-[var(--color-text-muted)] m-0"
          >✓ {{ queryClauseCount }} {{ queryClauseCount === 1 ? 'clause' : 'clauses' }}</p>
          <p
            v-else
            class="text-[11px] font-mono text-[var(--color-text-muted)] m-0"
          >fields: principal, service, action, method, path, type · ops: AND OR NOT · -field:value · field:"exact" · field:*wild*</p>
        </div>

        <div class="flex gap-2 justify-between items-center">
          <button
            v-if="filter.mode === 'rules'"
            class="btn-outline"
            type="button"
            @click="addRule()"
          >+ Add filter</button>
          <span v-else></span>
          <div class="flex gap-2">
            <button class="btn-outline" type="button" @click="resetFilters">Reset</button>
            <button class="btn-action" type="submit" :disabled="loading || (filter.mode === 'query' && !!queryParseError)">
              {{ loading ? 'Loading…' : 'Apply' }}
            </button>
          </div>
        </div>
      </form>

      <div
        v-if="error"
        class="px-4 py-2 text-sm text-[var(--color-error)] border-b border-[var(--color-border-divider)] bg-[var(--color-surface-muted)]"
      >
        {{ error }}
      </div>

      <div class="overflow-auto">
        <table class="w-full text-sm" style="border-collapse: separate; border-spacing: 0">
          <thead class="sticky top-0 z-[1]">
            <tr>
              <th class="bg-[var(--color-surface)] shadow-[inset_0_-1px_0_var(--color-border-divider)] px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-muted)]">when</th>
              <th class="bg-[var(--color-surface)] shadow-[inset_0_-1px_0_var(--color-border-divider)] px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-muted)]">principal</th>
              <th class="bg-[var(--color-surface)] shadow-[inset_0_-1px_0_var(--color-border-divider)] px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-muted)]">service</th>
              <th class="bg-[var(--color-surface)] shadow-[inset_0_-1px_0_var(--color-border-divider)] px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-muted)]">action</th>
              <th class="bg-[var(--color-surface)] shadow-[inset_0_-1px_0_var(--color-border-divider)] px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-muted)]">method</th>
              <th class="bg-[var(--color-surface)] shadow-[inset_0_-1px_0_var(--color-border-divider)] px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--color-text-muted)]">path</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in rows"
              :key="row.id"
              class="cursor-pointer hover:bg-[var(--color-surface-muted)]"
              @click="openRow(row)"
            >
              <td class="px-3 py-1.5 font-mono text-[12px] text-[var(--color-text-secondary)] border-b border-[var(--color-border-divider)] whitespace-nowrap">{{ formatDate(row.created_at) }}</td>
              <td class="px-3 py-1.5 text-[13px] text-[var(--color-text-primary)] border-b border-[var(--color-border-divider)]">{{ row.principal || '—' }}</td>
              <td class="px-3 py-1.5 font-mono text-[12px] text-[var(--color-text-secondary)] border-b border-[var(--color-border-divider)]">{{ row.service || '—' }}</td>
              <td class="px-3 py-1.5 font-mono text-[12px] text-[var(--color-text-primary)] border-b border-[var(--color-border-divider)]">{{ row.action || '—' }}</td>
              <td class="px-3 py-1.5 font-mono text-[12px] text-[var(--color-text-secondary)] border-b border-[var(--color-border-divider)]">{{ row.method || '—' }}</td>
              <td class="px-3 py-1.5 font-mono text-[12px] text-[var(--color-text-primary)] border-b border-[var(--color-border-divider)] truncate max-w-[420px]">{{ row.path || '—' }}</td>
            </tr>
            <tr v-if="!rows.length && !loading">
              <td colspan="6" class="text-center text-[var(--color-text-muted)] py-8 text-sm">no audit entries</td>
            </tr>
            <tr v-if="loading && !rows.length">
              <td colspan="6" class="text-center text-[var(--color-text-muted)] py-8 text-sm">loading…</td>
            </tr>
          </tbody>
        </table>
      </div>

      <footer class="flex items-center justify-between px-4 py-2.5 border-t border-[var(--color-border-divider)] bg-[var(--color-surface-muted)]">
        <span class="text-[12px] text-[var(--color-text-secondary)]">
          {{ pageStart.toLocaleString() }}–{{ pageEnd.toLocaleString() }} of {{ total.toLocaleString() }}
        </span>
        <div class="flex gap-2">
          <button class="btn-outline" type="button" :disabled="!canPrev || loading" @click="prevPage">Prev</button>
          <button class="btn-outline" type="button" :disabled="!canNext || loading" @click="nextPage">Next</button>
        </div>
      </footer>
    </section>

    <div
      v-if="selected"
      class="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4"
      @click="(e) => { if (e.target === e.currentTarget) closeDetail(); }"
    >
      <div
        class="bg-[var(--color-surface)] border border-[var(--color-border-card)] rounded-[8px] shadow-[var(--shadow-overlay)] w-[min(90vw,900px)] max-h-[85vh] flex flex-col overflow-hidden"
        role="dialog"
        aria-modal="true"
      >
        <div class="flex items-center gap-3 px-4 py-3 border-b border-[var(--color-border-divider)]">
          <h3 class="font-mono text-sm text-[var(--color-text-primary)] m-0 truncate">
            #{{ selected.id }} · {{ selected.method }} {{ selected.path }}
          </h3>
          <span class="flex-1"></span>
          <button class="btn-outline" type="button" @click="closeDetail">Close</button>
        </div>
        <div class="p-4 overflow-auto flex-1 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Message ID</span><br/><span class="font-mono text-[12px] break-all">{{ selected.message_id || '—' }}</span></div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Type</span><br/><span class="font-mono text-[12px]">{{ selected.type || '—' }}</span></div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Timestamp</span><br/>{{ formatDate(selected.timestamp) }}</div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Created at</span><br/>{{ formatDate(selected.created_at) }}</div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Principal</span><br/><span class="break-all">{{ selected.principal || '—' }}</span></div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Service</span><br/><span class="font-mono text-[12px]">{{ selected.service || '—' }}</span></div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Action</span><br/><span class="font-mono text-[12px] break-all">{{ selected.action || '—' }}</span></div>
          <div><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Method</span><br/><span class="font-mono text-[12px]">{{ selected.method || '—' }}</span></div>
          <div class="md:col-span-2"><span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Path</span><br/><span class="font-mono text-[12px] break-all">{{ selected.path || '—' }}</span></div>
          <div class="md:col-span-2">
            <span class="text-[var(--color-text-muted)] font-mono text-[11px] uppercase tracking-[0.06em]">Request data</span>
            <div v-if="selectedLoading" class="text-[var(--color-text-secondary)] text-[12px]">loading…</div>
            <div v-else-if="selectedError" class="text-[var(--color-error)] text-[12px]">{{ selectedError }}</div>
            <pre
              v-else
              class="font-mono text-[12px] leading-relaxed text-[var(--color-text-primary)] bg-[var(--color-surface-muted)] rounded-[4px] p-2 mt-1 whitespace-pre-wrap break-all m-0"
            >{{ formatBody(selected.request_data) }}</pre>
          </div>
        </div>
      </div>
    </div>
  </main>
</template>
