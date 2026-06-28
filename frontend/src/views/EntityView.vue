<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import {
  fetchEntity,
  fetchEntityActivity,
  fetchActorsByRisk,
  ACTOR_ORIGINS,
  type EntityDetail,
  type ActorRisk,
  type SsuMgmtEvent,
} from '../ssumgmt/api';
import { ForbiddenError } from '../api';
import { sourceColor, statusColor, formatDateTime, riskColor, relAge, originColor, originLabel } from '../ssumgmt/format';
import ConsoleTable from '../components/ConsoleTable.vue';
import CacheBadge from '../components/CacheBadge.vue';
import { ACTIVITY_COLUMNS } from '../ssumgmt/queryColumns';
import { type ConsoleColumn, rawPathAccessor } from '../ssumgmt/tableColumns';
import { useCustomColumns } from '../composables/useCustomColumns';

const route = useRoute();

// Activity table column management (shared across actors via one storage key).
const ACTIVITY_STORAGE_KEY = 'ssumgmt-entity-activity';
const { columns: activityCustomCols, addColumn: addActivityCol, removeColumn: removeActivityCol } =
  useCustomColumns(ACTIVITY_STORAGE_KEY);
const activityColumns = computed<ConsoleColumn<SsuMgmtEvent>[]>(() => [
  ...ACTIVITY_COLUMNS,
  ...activityCustomCols.value.map((c) => ({
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
const activityColumnsKey = computed(() => activityColumns.value.map((c) => c.id).join(','));

const detail = ref<EntityDetail | null>(null);
const actors = ref<ActorRisk[]>([]);
const filter = ref('');
const originFilter = ref('');
const loading = ref(false);
const error = ref<string | null>(null);
const forbidden = ref(false);

const currentId = computed(() => (route.params.id as string | undefined) ?? '');

const queryLink = computed(() => ({
  name: 'console-query',
  query: { q: `actor:"${currentId.value}"` },
}));
const graphLink = computed(() => ({ name: 'console-graph', query: { actor: currentId.value } }));

const ACTIVITY_PAGE = 50;
const activityRows = ref<SsuMgmtEvent[]>([]);
const activityTotal = ref(0);
const activityOffset = ref(0);
const activityLoading = ref(false);

const actPageStart = computed(() => (activityTotal.value === 0 ? 0 : activityOffset.value + 1));
const actPageEnd = computed(() => Math.min(activityOffset.value + activityRows.value.length, activityTotal.value));
const actCanPrev = computed(() => activityOffset.value > 0);
const actCanNext = computed(() => activityOffset.value + ACTIVITY_PAGE < activityTotal.value);

async function loadActivity(): Promise<void> {
  if (!currentId.value) return;
  activityLoading.value = true;
  try {
    const res = await fetchEntityActivity(currentId.value, { limit: ACTIVITY_PAGE, offset: activityOffset.value });
    activityRows.value = res.rows;
    activityTotal.value = res.total;
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    activityLoading.value = false;
  }
}

function prevActivity(): void {
  if (!actCanPrev.value) return;
  activityOffset.value = Math.max(0, activityOffset.value - ACTIVITY_PAGE);
  void loadActivity();
}

function nextActivity(): void {
  if (!actCanNext.value) return;
  activityOffset.value += ACTIVITY_PAGE;
  void loadActivity();
}

onMounted(async () => {
  window.addEventListener('keydown', onKey);
  try {
    actors.value = await fetchActorsByRisk(50);
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
  }
  if (currentId.value) await loadDetail(currentId.value);
});

onUnmounted(() => window.removeEventListener('keydown', onKey));

const selectedEvent = ref<SsuMgmtEvent | null>(null);

function rawText(e: SsuMgmtEvent): string {
  if (e.raw == null) return '—';
  try {
    return JSON.stringify(e.raw, null, 2);
  } catch {
    return String(e.raw);
  }
}

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape' && selectedEvent.value) selectedEvent.value = null;
}

watch(currentId, (id) => {
  if (id) void loadDetail(id);
  else detail.value = null;
});

async function loadDetail(id: string): Promise<void> {
  loading.value = true;
  error.value = null;
  detail.value = null;
  try {
    detail.value = await fetchEntity(id);
    // Seed the activity feed from the bundle's first page (no extra round-trip).
    activityOffset.value = 0;
    activityRows.value = detail.value.activity;
    activityTotal.value = detail.value.activity_total;
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
    else error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

const filteredActors = computed(() => {
  const f = filter.value.trim().toLowerCase();
  const o = originFilter.value;
  return actors.value.filter((a) => {
    if (o && !(a.origins ?? []).includes(o)) return false;
    if (!f) return true;
    return a.id.toLowerCase().includes(f) || (a.display_name ?? '').toLowerCase().includes(f);
  });
});

// Risk component rows sorted by contribution, for the explainable gauge.
const components = computed(() => {
  const r = detail.value?.risk;
  if (!r) return [] as { name: string; contribution: number; raw: number; weight: number }[];
  return Object.entries(r.components)
    .map(([name, c]) => ({ name, contribution: c.contribution, raw: c.raw, weight: c.weight }))
    .sort((a, b) => b.contribution - a.contribution);
});

const compMax = computed(() => components.value.reduce((m, c) => Math.max(m, c.contribution), 0));

function bar(v: number, max: number, width = 16): string {
  const n = max > 0 ? Math.round((v / max) * width) : 0;
  return '█'.repeat(n) + '░'.repeat(Math.max(0, width - n));
}

</script>

<template>
  <div class="term-view-root" style="height:100%;display:grid;grid-template-columns:260px 1fr;gap:1px;background:var(--t-line);overflow:hidden">
    <!-- actor picker -->
    <div class="term-picker" style="background:var(--t-pane);display:flex;flex-direction:column;min-height:0">
      <div style="padding:8px 12px;border-bottom:1px solid var(--t-line);flex:none;display:flex;flex-direction:column;gap:6px">
        <input
          v-model="filter"
          placeholder="filter actors…"
          style="width:100%;background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:12px;padding:5px 8px;outline:none"
        />
        <select
          v-model="originFilter"
          style="width:100%;background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:4px 6px;outline:none"
        >
          <option value="">all origins</option>
          <option v-for="o in ACTOR_ORIGINS" :key="o" :value="o">{{ originLabel(o) }}</option>
        </select>
      </div>
      <div style="overflow:auto;min-height:0">
        <router-link
          v-for="a in filteredActors"
          :key="a.id"
          :to="{ name: 'console-inspect', params: { id: a.id } }"
          :style="{
            display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px',
            borderBottom: '1px solid var(--t-line)', fontSize: '12px', cursor: 'pointer',
            textDecoration: 'none',
            background: a.id === currentId ? 'var(--t-bg)' : 'transparent',
          }"
        >
          <span :style="{ color: riskColor(a.score), flex: 'none', width: '24px', textAlign: 'right', fontWeight: 700 }">{{ a.score }}</span>
          <div style="flex:1;min-width:0;display:flex;flex-direction:column;gap:2px">
            <span style="color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ a.display_name ?? a.id }}</span>
            <span v-if="(a.origins ?? []).length" style="display:flex;gap:3px;flex-wrap:wrap">
              <span
                v-for="o in a.origins"
                :key="o"
                :style="{ color: originColor(o), border: '1px solid ' + originColor(o), fontSize: '8.5px', padding: '0 4px', lineHeight: '13px', letterSpacing: '.03em' }"
              >{{ originLabel(o) }}</span>
            </span>
          </div>
        </router-link>
        <div v-if="!filteredActors.length" style="padding:14px;color:var(--t-faint);font-size:12px">no actors</div>
      </div>
    </div>

    <!-- detail -->
    <div style="background:var(--t-line);overflow:auto;min-height:0">
      <div v-if="forbidden" style="background:var(--t-pane);padding:40px;text-align:center;color:var(--t-dim)">
        You need the <code>ce.cloudengineer</code> role to view the console.
      </div>
      <div v-else-if="error" style="background:var(--t-pane);padding:40px;text-align:center;color:var(--t-red)">{{ error }}</div>
      <div v-else-if="!currentId" style="background:var(--t-pane);padding:40px;text-align:center;color:var(--t-faint)">
        Select an actor to inspect.
      </div>
      <div v-else-if="loading" style="background:var(--t-pane);padding:40px;text-align:center;color:var(--t-faint)">loading…</div>

      <div v-else-if="detail" style="display:flex;flex-direction:column;gap:1px;background:var(--t-line);min-height:100%">
        <!-- identity + risk -->
        <div class="term-split" style="flex:none;display:grid;grid-template-columns:1fr 320px;gap:1px;background:var(--t-line)">
          <div style="background:var(--t-pane);padding:16px">
            <div class="term-toolbar" style="display:flex;align-items:center;gap:10px">
              <span style="font-size:18px;font-weight:700;color:var(--t-text)">{{ detail.identity.display_name ?? detail.identity.id }}</span>
              <span
                :style="{ fontSize: '10px', padding: '2px 6px', border: '1px solid var(--t-line2)', color: detail.identity.kind === 'unresolved' ? 'var(--t-faint)' : 'var(--t-dim)' }"
              >{{ detail.identity.kind }}</span>
              <span style="flex:1"></span>
              <router-link
                v-if="currentId"
                :to="queryLink"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-accent);font-family:inherit;font-size:11px;padding:3px 8px;cursor:pointer;text-decoration:none"
              >query →</router-link>
              <router-link
                v-if="currentId"
                :to="graphLink"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-accent);font-family:inherit;font-size:11px;padding:3px 8px;cursor:pointer;text-decoration:none;margin-left:6px"
              >graph →</router-link>
            </div>
            <div style="margin-top:10px;display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:12px;color:var(--t-dim)">
              <span style="color:var(--t-faint)">id</span><span class="term-break" style="color:var(--t-text)">{{ detail.identity.id }}</span>
              <span style="color:var(--t-faint)">email</span><span class="term-break">{{ detail.identity.email ?? '—' }}</span>
              <span style="color:var(--t-faint)">team</span><span>{{ detail.identity.team ?? '—' }}</span>
              <span style="color:var(--t-faint)">sources</span><span>{{ (detail.identity.sources.filter(Boolean) as string[]).join(', ') || '—' }}</span>
              <template v-if="detail.identity_context.sources.length">
                <span style="color:var(--t-faint)">identity src<CacheBadge kind="identity_context" /></span><span class="term-break" style="color:var(--t-text)">{{ detail.identity_context.sources.join(', ') }}</span>
              </template>
              <template v-if="detail.identity_context.roles.length">
                <span style="color:var(--t-faint)">assumed roles</span>
                <span style="display:flex;flex-direction:column;gap:2px">
                  <span v-for="r in detail.identity_context.roles.slice(0, 6)" :key="r" style="color:var(--t-text);word-break:break-all;font-size:11px">{{ r }}</span>
                  <span v-if="detail.identity_context.roles.length > 6" style="color:var(--t-faint);font-size:11px">+{{ detail.identity_context.roles.length - 6 }} more</span>
                </span>
              </template>
              <span style="color:var(--t-faint)">first seen</span><span>{{ detail.identity.first_seen ? formatDateTime(detail.identity.first_seen) : '—' }}</span>
              <span style="color:var(--t-faint)">last active<CacheBadge kind="siem" /></span><span>{{ detail.identity.last_active ? relAge(detail.identity.last_active) : '—' }}</span>
            </div>
          </div>

          <!-- risk gauge -->
          <div style="background:var(--t-pane);padding:16px">
            <div style="color:var(--t-faint);font-size:11px;letter-spacing:.06em">RISK<CacheBadge kind="siem" /></div>
            <div style="display:flex;align-items:baseline;gap:10px;margin-top:4px">
              <span :style="{ fontSize: '40px', fontWeight: 700, color: riskColor(detail.risk?.score ?? 0) }">{{ detail.risk?.score ?? 0 }}</span>
              <span :style="{ fontSize: '12px', color: riskColor(detail.risk?.score ?? 0), textTransform: 'uppercase', letterSpacing: '.06em' }">{{ detail.risk?.label ?? 'low' }}</span>
            </div>
            <div v-if="components.length" style="margin-top:10px;display:flex;flex-direction:column;gap:3px">
              <div v-for="c in components" :key="c.name" style="display:flex;align-items:center;gap:8px;font-size:11px">
                <span style="flex:none;width:118px;color:var(--t-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ c.name }}</span>
                <span :style="{ color: c.contribution > 0 ? 'var(--t-amber)' : 'var(--t-line2)', letterSpacing: '.5px' }">{{ bar(c.contribution, compMax, 12) }}</span>
                <span style="flex:1"></span>
                <span style="color:var(--t-faint)">+{{ c.contribution.toFixed(0) }}</span>
              </div>
            </div>
            <div v-else style="margin-top:10px;color:var(--t-faint);font-size:11px">no score computed yet</div>
          </div>
        </div>

        <!-- stat strip -->
        <div class="term-tilegrid" style="flex:none;display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--t-line)">
          <div v-for="s in [
            { k: 'events/24h', v: detail.stats.events_24h, cls: 'entity_stats' as const },
            { k: 'events/7d', v: detail.stats.events_7d, cls: 'entity_stats' as const },
            { k: 'failed/7d', v: detail.stats.failed_7d, cls: 'entity_stats' as const },
            { k: 'sessions', v: detail.stats.sessions, cls: 'siem' as const },
            { k: 'priv grants', v: detail.stats.privileged_grants, cls: 'siem' as const },
          ]" :key="s.k" style="background:var(--t-pane);padding:10px 14px">
            <div style="color:var(--t-faint);font-size:10.5px;letter-spacing:.04em">{{ s.k }}<CacheBadge :kind="s.cls" /></div>
            <div :style="{ fontSize: '22px', fontWeight: 700, marginTop: '2px', color: (s.k === 'failed/7d' || s.k === 'priv grants') && s.v > 0 ? 'var(--t-amber)' : 'var(--t-text)' }">{{ s.v }}</div>
          </div>
        </div>

        <!-- sessions + grants -->
        <div class="term-split" style="flex:none;display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--t-line)">
          <div style="background:var(--t-pane)">
            <div style="padding:8px 14px;border-bottom:1px solid var(--t-line);font-weight:600;letter-spacing:.08em;font-size:11.5px"><span style="color:var(--t-accent)">▌</span> SESSIONS<CacheBadge kind="siem" /></div>
            <div style="overflow:auto;max-height:240px">
              <div v-for="s in detail.sessions" :key="s.id" style="display:flex;align-items:center;gap:8px;padding:5px 14px;border-bottom:1px solid var(--t-line);font-size:11.5px">
                <span class="term-rowcell" :style="{ color: s.status === 'flagged' ? 'var(--t-red)' : s.status === 'active' ? 'var(--t-accent)' : 'var(--t-dim)', flex: 'none', width: '54px', fontSize: '10px' }">{{ s.status }}</span>
                <span class="term-rowcell" style="flex:none;width:96px;color:var(--t-text);overflow:hidden;text-overflow:ellipsis">{{ s.device ?? '—' }}</span>
                <span class="term-rowcell" style="flex:none;width:96px;color:var(--t-dim);overflow:hidden;text-overflow:ellipsis">{{ s.source_ip ?? '—' }}</span>
                <span style="flex:1;color:var(--t-faint);overflow:hidden;text-overflow:ellipsis">{{ s.location ?? '—' }}</span>
                <span style="flex:none;color:var(--t-faint)">{{ relAge(s.last_seen_at) }}</span>
              </div>
              <div v-if="!detail.sessions.length" style="padding:14px;color:var(--t-faint);font-size:11.5px">no sessions (AWS-only in v1)</div>
            </div>
          </div>
          <div style="background:var(--t-pane)">
            <div style="padding:8px 14px;border-bottom:1px solid var(--t-line);font-weight:600;letter-spacing:.08em;font-size:11.5px"><span style="color:var(--t-amber)">▌</span> GRANTS<CacheBadge kind="siem" /></div>
            <div style="overflow:auto;max-height:240px">
              <div v-for="g in detail.grants" :key="g.id" style="display:flex;align-items:center;gap:8px;padding:5px 14px;border-bottom:1px solid var(--t-line);font-size:11.5px">
                <span v-if="g.privileged" style="color:var(--t-red);flex:none;width:38px;font-size:9px;font-weight:700">PRIV</span>
                <span v-else style="color:var(--t-faint);flex:none;width:38px;font-size:9px">—</span>
                <span style="flex:none;width:40px;color:var(--t-dim)">{{ g.system }}</span>
                <span style="flex:1;color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ g.role }}</span>
                <span style="flex:none;color:var(--t-faint)">{{ g.granted_at ? relAge(g.granted_at) : '—' }}</span>
              </div>
              <div v-if="!detail.grants.length" style="padding:14px;color:var(--t-faint);font-size:11.5px">no grants</div>
            </div>
          </div>
        </div>

        <!-- anomalies (statistical signals feeding this actor's risk) -->
        <div v-if="detail.anomalies.length" style="flex:none;background:var(--t-pane)">
          <div style="padding:8px 14px;border-bottom:1px solid var(--t-line);font-weight:600;letter-spacing:.08em;font-size:11.5px">
            <span style="color:var(--t-amber)">◆</span> ANOMALIES<CacheBadge kind="siem" />
            <span style="color:var(--t-faint);font-weight:400;margin-left:8px">statistical · soft signal</span>
          </div>
          <div style="overflow:auto;max-height:200px">
            <div v-for="n in detail.anomalies" :key="n.id" style="display:flex;align-items:center;gap:10px;padding:5px 14px;border-bottom:1px solid var(--t-line);font-size:11.5px">
              <span :style="{ color: n.severity === 'medium' ? 'var(--t-amber)' : 'var(--t-dim)', flex: 'none', width: '116px', fontSize: '10px', letterSpacing: '.03em' }">{{ n.kind }}</span>
              <span style="flex:1;color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ n.detail ?? n.title }}</span>
              <span style="flex:none;color:var(--t-faint)">{{ relAge(n.event_time) }}</span>
            </div>
          </div>
        </div>

        <!-- activity (grows to fill the remaining pane height) -->
        <div style="flex:1 1 0;min-height:300px;min-width:0;display:flex;flex-direction:column;background:var(--t-pane)">
          <div class="term-toolbar" style="display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid var(--t-line);font-size:11.5px;flex:none">
            <span style="font-weight:600;letter-spacing:.08em"><span style="color:var(--t-accent)">▌</span> ACTIVITY</span>
            <span style="color:var(--t-faint)">{{ actPageStart }}–{{ actPageEnd }} of {{ activityTotal.toLocaleString() }}<CacheBadge kind="entity_stats" /></span>
            <span style="flex:1"></span>
            <template v-if="activityTotal > ACTIVITY_PAGE">
              <button
                type="button"
                :disabled="!actCanPrev"
                :style="{ opacity: actCanPrev ? 1 : 0.4, cursor: actCanPrev ? 'pointer' : 'default' }"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 9px"
                @click="prevActivity"
              >← prev</button>
              <button
                type="button"
                :disabled="!actCanNext"
                :style="{ opacity: actCanNext ? 1 : 0.4, cursor: actCanNext ? 'pointer' : 'default' }"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 9px"
                @click="nextActivity"
              >next →</button>
            </template>
          </div>
          <div style="flex:1;min-height:0;min-width:0;display:flex">
            <ConsoleTable
              :key="activityColumnsKey"
              :columns="activityColumns"
              :rows="activityRows"
              :row-key="(e: SsuMgmtEvent) => e.source + e.uid"
              :storage-key="ACTIVITY_STORAGE_KEY"
              :loading="activityLoading"
              enable-custom-columns
              :on-add-custom="addActivityCol"
              :on-remove-custom="removeActivityCol"
              empty-text="no recent activity"
              @row-click="(e: SsuMgmtEvent) => (selectedEvent = e)"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- activity event detail modal (opened by clicking an activity row) -->
    <div
      v-if="selectedEvent"
      style="position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:24px"
      @click.self="selectedEvent = null"
    >
      <div
        class="term"
        style="width:min(760px,100%);max-height:80vh;overflow:auto;background:var(--t-pane);border:1px solid var(--t-line2)"
      >
        <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--t-line)">
          <span :style="{ color: sourceColor(selectedEvent.source) }">{{ selectedEvent.source }}</span>
          <span style="color:var(--t-text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ selectedEvent.action }}</span>
          <span style="flex:1"></span>
          <button
            type="button"
            style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer"
            @click="selectedEvent = null"
          >[esc]</button>
        </div>
        <div style="padding:14px 16px;display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:12px">
          <span style="color:var(--t-faint)">uid</span><span style="color:var(--t-text);word-break:break-all">{{ selectedEvent.uid }}</span>
          <span style="color:var(--t-faint)">ts</span><span style="color:var(--t-text)">{{ formatDateTime(selectedEvent.ts) }}</span>
          <span style="color:var(--t-faint)">actor</span><span style="color:var(--t-text)">{{ selectedEvent.actor ?? '—' }}</span>
          <span style="color:var(--t-faint)">resource</span><span style="color:var(--t-text);word-break:break-all">{{ selectedEvent.resource ?? '—' }}</span>
          <span style="color:var(--t-faint)">source_ip</span><span style="color:var(--t-text)">{{ selectedEvent.source_ip ?? '—' }}</span>
          <span style="color:var(--t-faint)">level</span><span style="color:var(--t-text)">{{ selectedEvent.level }}</span>
          <span style="color:var(--t-faint)">status</span><span :style="{ color: statusColor(selectedEvent.status) }">{{ selectedEvent.status }}</span>
        </div>
        <div style="padding:0 16px 16px">
          <div style="color:var(--t-faint);font-size:10.5px;letter-spacing:.06em;margin-bottom:6px">RAW</div>
          <pre style="margin:0;padding:12px;background:var(--t-inset);border:1px solid var(--t-line);overflow:auto;font-size:11.5px;color:var(--t-dim);white-space:pre-wrap;word-break:break-word">{{ rawText(selectedEvent) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>
