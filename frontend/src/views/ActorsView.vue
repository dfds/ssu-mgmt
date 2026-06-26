<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter, type LocationQueryRaw } from 'vue-router';
import { fetchActors, ACTOR_ORIGINS, type ActorListRow } from '../ssumgmt/api';
import { ForbiddenError } from '../api';
import { originColor, originLabel, riskColor, relAge } from '../ssumgmt/format';
import ConsoleTable from '../components/ConsoleTable.vue';
import { ACTOR_COLUMNS } from '../ssumgmt/actorColumns';

const route = useRoute();
const router = useRouter();

const STORAGE_KEY = 'ssumgmt-actors';

const PAGE = 50;
const KINDS = ['person', 'service', 'unresolved'] as const;
type Sort = 'risk' | 'recent' | 'name';
const SORTS: { key: Sort; label: string }[] = [
  { key: 'risk', label: 'risk' },
  { key: 'recent', label: 'recent' },
  { key: 'name', label: 'name' },
];

const q = ref('');
const kind = ref('');
const origin = ref('');
const sort = ref<Sort>('risk');
const offset = ref(0);

const rows = ref<ActorListRow[]>([]);
const total = ref(0);
const loading = ref(false);
const error = ref<string | null>(null);
const forbidden = ref(false);

const pageStart = computed(() => (total.value === 0 ? 0 : offset.value + 1));
const pageEnd = computed(() => Math.min(offset.value + rows.value.length, total.value));
const canPrev = computed(() => offset.value > 0);
const canNext = computed(() => offset.value + PAGE < total.value);

async function load(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    const res = await fetchActors({
      q: q.value || undefined,
      kind: kind.value || undefined,
      origin: origin.value || undefined,
      sort: sort.value,
      limit: PAGE,
      offset: offset.value,
    });
    rows.value = res.rows;
    total.value = res.total;
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
    else error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

// Reset to page 1 whenever a filter/sort changes, then reload.
function applyFilters(): void {
  offset.value = 0;
  void load();
}

function prev(): void {
  if (!canPrev.value) return;
  offset.value = Math.max(0, offset.value - PAGE);
  void load();
}

function next(): void {
  if (!canNext.value) return;
  offset.value += PAGE;
  void load();
}

function rowLink(a: ActorListRow): { name: string; params: { id: string } } {
  return { name: 'console-inspect', params: { id: a.id } };
}

// --- URL state persistence -------------------------------------------------
function currentQuery(): LocationQueryRaw {
  const out: LocationQueryRaw = {};
  if (q.value) out.q = q.value;
  if (kind.value) out.kind = kind.value;
  if (origin.value) out.origin = origin.value;
  if (sort.value !== 'risk') out.sort = sort.value;
  if (offset.value > 0) out.offset = String(offset.value);
  return out;
}

function routeMatchesState(): boolean {
  return (
    ((route.query.q as string) ?? '') === q.value &&
    ((route.query.kind as string) ?? '') === kind.value &&
    ((route.query.origin as string) ?? '') === origin.value &&
    ((route.query.sort as string) ?? 'risk') === sort.value &&
    (Number(route.query.offset) || 0) === (offset.value || 0)
  );
}

function readFromRoute(): void {
  q.value = (route.query.q as string) ?? '';
  const k = (route.query.kind as string) ?? '';
  kind.value = (KINDS as readonly string[]).includes(k) ? k : '';
  const o = (route.query.origin as string) ?? '';
  origin.value = ACTOR_ORIGINS.includes(o) ? o : '';
  const s = (route.query.sort as string) ?? 'risk';
  sort.value = (['risk', 'recent', 'name'] as string[]).includes(s) ? (s as Sort) : 'risk';
  offset.value = Number(route.query.offset) || 0;
}

watch([q, kind, origin, sort, offset], () => {
  if (routeMatchesState()) return;
  void router.replace({ query: currentQuery() }).catch(() => {});
});

watch(
  () => route.query,
  () => {
    if (routeMatchesState()) return;
    readFromRoute();
    void load();
  },
);

onMounted(() => {
  readFromRoute();
  void load();
});

function actorOrigins(a: ActorListRow): string[] {
  return (a.origins ?? []).filter(Boolean);
}

function bar(score: number | null): { full: string; empty: string } {
  const n = Math.round(((score ?? 0) / 100) * 8);
  return { full: '█'.repeat(n), empty: '░'.repeat(Math.max(0, 8 - n)) };
}

const serverSort = computed(() => ({ key: sort.value, dir: sort.value === 'name' ? 'asc' : 'desc' } as const));
function onServerSort(key: string): void {
  if (key === 'risk' || key === 'recent' || key === 'name') {
    sort.value = key;
    applyFilters();
  }
}
</script>

<template>
  <div class="term term-view-root" style="height:100%;display:flex;flex-direction:column;background:var(--t-pane);min-height:0;min-width:0">
    <div v-if="forbidden" style="padding:40px;text-align:center;color:var(--t-dim)">
      You need the <code>ce.cloudengineer</code> role to view actors.
    </div>
    <template v-else>
      <!-- header: search + filters + pagination -->
      <div style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--t-line);flex:none;font-size:11.5px;flex-wrap:wrap">
        <span style="color:var(--t-accent)">▌</span>
        <span style="font-weight:600;letter-spacing:.08em">ACTORS</span>

        <input
          v-model="q"
          placeholder="search id / email / name / team…"
          style="background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:11.5px;padding:3px 8px;outline:none;min-width:240px"
          @keyup.enter="applyFilters"
        />

        <select
          v-model="kind"
          style="background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:3px 6px;outline:none"
          @change="applyFilters"
        >
          <option value="">all kinds</option>
          <option v-for="k in KINDS" :key="k" :value="k">{{ k }}</option>
        </select>

        <select
          v-model="origin"
          style="background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:3px 6px;outline:none"
          @change="applyFilters"
        >
          <option value="">all origins</option>
          <option v-for="o in ACTOR_ORIGINS" :key="o" :value="o">{{ originLabel(o) }}</option>
        </select>

        <span class="term-btngroup" style="display:flex;gap:3px;align-items:center">
          <span style="color:var(--t-faint)">sort</span>
          <button
            v-for="s in SORTS"
            :key="s.key"
            type="button"
            @click="sort = s.key; applyFilters()"
            :style="{
              background: 'none',
              border: '1px solid ' + (s.key === sort ? 'var(--t-accent)' : 'var(--t-line2)'),
              color: s.key === sort ? 'var(--t-accent)' : 'var(--t-dim)',
              fontFamily: 'inherit',
              fontSize: '10.5px',
              lineHeight: 1.4,
              padding: '1px 7px',
              cursor: 'pointer',
            }"
          >{{ s.label }}</button>
        </span>

        <span style="flex:1"></span>
        <span style="color:var(--t-faint)">{{ pageStart }}–{{ pageEnd }} of {{ total.toLocaleString() }}</span>
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

      <div v-if="error" style="padding:10px 14px;color:var(--t-red);font-size:12px;flex:none">{{ error }}</div>

      <!-- table -->
      <div class="term-pane-scroll" style="flex:1;min-height:0;min-width:0;display:flex">
        <ConsoleTable
          :columns="ACTOR_COLUMNS"
          :rows="rows"
          :row-key="(a: ActorListRow) => a.id"
          :storage-key="STORAGE_KEY"
          :server-sort="serverSort"
          :row-link="rowLink"
          :loading="loading"
          empty-text="no actors match"
          @server-sort="onServerSort"
        >
          <template #cell-risk="{ row }">
            <span :style="{ color: riskColor((row as ActorListRow).score ?? 0), fontWeight: 700 }">{{ (row as ActorListRow).score ?? '–' }}</span>
          </template>
          <template #cell-bar="{ row }">
            <span style="letter-spacing:.5px">
              <span :style="{ color: riskColor((row as ActorListRow).score ?? 0) }">{{ bar((row as ActorListRow).score).full }}</span><span style="color:var(--t-line2)">{{ bar((row as ActorListRow).score).empty }}</span>
            </span>
          </template>
          <template #cell-actor="{ row }">
            <span style="color:var(--t-text)">{{ (row as ActorListRow).display_name ?? (row as ActorListRow).id }}</span>
            <span v-if="(row as ActorListRow).display_name" style="color:var(--t-faint);font-size:10.5px"> · {{ (row as ActorListRow).id }}</span>
          </template>
          <template #cell-kind="{ row }">
            <span :style="{ color: (row as ActorListRow).kind === 'unresolved' ? 'var(--t-faint)' : 'var(--t-dim)' }">{{ (row as ActorListRow).kind }}</span>
          </template>
          <template #cell-origins="{ row }">
            <span style="display:inline-flex;gap:3px;flex-wrap:wrap;vertical-align:middle">
              <span
                v-for="o in actorOrigins(row as ActorListRow)"
                :key="o"
                :style="{ color: originColor(o), border: '1px solid ' + originColor(o), fontSize: '9.5px', padding: '0 5px', lineHeight: '15px', letterSpacing: '.03em' }"
              >{{ originLabel(o) }}</span>
              <span v-if="!actorOrigins(row as ActorListRow).length" style="color:var(--t-faint);font-size:10px">—</span>
            </span>
          </template>
        </ConsoleTable>
      </div>
    </template>
  </div>
</template>
