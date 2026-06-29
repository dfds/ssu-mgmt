<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useRoute, useRouter, type LocationQueryRaw } from 'vue-router';
import type { Alert, Anomaly } from '../ssumgmt/api';
import { sourceColor, relAge } from '../ssumgmt/format';
import { useAlertsFeed, ALERT_FILTERS, type AlertFilter, type TriageAction } from '../ssumgmt/useAlertsFeed';
import { useAnomaliesFeed, ANOMALY_KINDS, ANOMALY_KIND_KEYS, ANOMALY_RANGES, ANOMALY_RANGE_KEYS, DEFAULT_ANOMALY_RANGE } from '../ssumgmt/useAnomaliesFeed';
import { FEED_COLUMNS, alertToFeedRow, anomalyToFeedRow, type FeedRow, type FeedType } from '../ssumgmt/feedColumns';
import AlertDetailModal from '../ssumgmt/AlertDetailModal.vue';
import AnomalyDetailModal from '../ssumgmt/AnomalyDetailModal.vue';
import ConsoleTable from '../components/ConsoleTable.vue';

const route = useRoute();
const router = useRouter();

const STORAGE_KEY = 'ssumgmt-alerts';
const TYPES: { key: FeedType; label: string }[] = [
  { key: 'alert', label: 'alerts' },
  { key: 'anomaly', label: 'anomalies' },
];

const type = ref<FeedType>('alert');

// Both feeds are instantiated up-front; only the active one is shown/loaded.
const alertsFeed = useAlertsFeed({ pageSize: 50, initialFilter: 'all' });
const anomaliesFeed = useAnomaliesFeed({ pageSize: 50 });

// --- active-feed projection -------------------------------------------------
const rows = computed<FeedRow[]>(() =>
  type.value === 'alert'
    ? alertsFeed.rows.value.map(alertToFeedRow)
    : anomaliesFeed.rows.value.map(anomalyToFeedRow),
);
const total = computed(() => (type.value === 'alert' ? alertsFeed.total.value : anomaliesFeed.total.value));
const pageStart = computed(() => (type.value === 'alert' ? alertsFeed.pageStart.value : anomaliesFeed.pageStart.value));
const pageEnd = computed(() => (type.value === 'alert' ? alertsFeed.pageEnd.value : anomaliesFeed.pageEnd.value));
const canPrev = computed(() => (type.value === 'alert' ? alertsFeed.canPrev.value : anomaliesFeed.canPrev.value));
const canNext = computed(() => (type.value === 'alert' ? alertsFeed.canNext.value : anomaliesFeed.canNext.value));
const paginated = computed(() => (type.value === 'alert' ? alertsFeed.paginated.value : true));
const loading = computed(() => (type.value === 'alert' ? alertsFeed.loading.value : anomaliesFeed.loading.value));
const error = computed(() => (type.value === 'alert' ? alertsFeed.error.value : anomaliesFeed.error.value));
const forbidden = computed(() => (type.value === 'alert' ? alertsFeed.forbidden.value : anomaliesFeed.forbidden.value));
const capped = computed(() => type.value === 'anomaly' && anomaliesFeed.capped.value);

function prev(): void {
  (type.value === 'alert' ? alertsFeed : anomaliesFeed).prev();
}
function next(): void {
  (type.value === 'alert' ? alertsFeed : anomaliesFeed).next();
}
function loadActive(): void {
  if (type.value === 'alert') void alertsFeed.load();
  else void anomaliesFeed.load();
}
function setType(t: FeedType): void {
  if (t === type.value) return;
  type.value = t;
  loadActive();
}

// FeedRow cast helper for the slots (slot props are untyped).
function fr(row: unknown): FeedRow {
  return row as FeedRow;
}

// --- URL state persistence --------------------------------------------------
const FILTER_KEYS = ALERT_FILTERS.map((f) => f.key);

function currentQuery(): LocationQueryRaw {
  const q: LocationQueryRaw = {};
  if (type.value !== 'alert') q.type = type.value;
  if (type.value === 'alert') {
    q.filter = alertsFeed.filter.value;
    if (alertsFeed.offset.value > 0) q.offset = String(alertsFeed.offset.value);
  } else {
    if (anomaliesFeed.kind.value) q.kind = anomaliesFeed.kind.value;
    if (anomaliesFeed.range.value !== DEFAULT_ANOMALY_RANGE) q.range = anomaliesFeed.range.value;
    if (anomaliesFeed.offset.value > 0) q.offset = String(anomaliesFeed.offset.value);
  }
  return q;
}

function routeMatchesState(): boolean {
  const t = (route.query.type as string) === 'anomaly' ? 'anomaly' : 'alert';
  if (t !== type.value) return false;
  const off = Number(route.query.offset) || 0;
  if (type.value === 'alert') {
    return ((route.query.filter as string) ?? '') === alertsFeed.filter.value && off === (alertsFeed.offset.value || 0);
  }
  return (
    ((route.query.kind as string) ?? '') === anomaliesFeed.kind.value &&
    ((route.query.range as string) || DEFAULT_ANOMALY_RANGE) === anomaliesFeed.range.value &&
    off === (anomaliesFeed.offset.value || 0)
  );
}

function readFromRoute(): void {
  type.value = (route.query.type as string) === 'anomaly' ? 'anomaly' : 'alert';
  if (type.value === 'alert') {
    const f = route.query.filter as AlertFilter | undefined;
    alertsFeed.filter.value = f && FILTER_KEYS.includes(f) ? f : 'all';
    alertsFeed.offset.value = Number(route.query.offset) || 0;
  } else {
    const k = (route.query.kind as string) ?? '';
    anomaliesFeed.kind.value = ANOMALY_KIND_KEYS.includes(k) ? k : '';
    const r = (route.query.range as string) ?? '';
    anomaliesFeed.range.value = ANOMALY_RANGE_KEYS.includes(r) ? r : DEFAULT_ANOMALY_RANGE;
    anomaliesFeed.offset.value = Number(route.query.offset) || 0;
  }
}

// Mirror state → URL across both feeds' relevant refs; skip when already in sync.
watch(
  [
    type,
    () => alertsFeed.filter.value,
    () => alertsFeed.offset.value,
    () => anomaliesFeed.kind.value,
    () => anomaliesFeed.range.value,
    () => anomaliesFeed.offset.value,
  ],
  () => {
    if (routeMatchesState()) return;
    void router.replace({ query: currentQuery() }).catch(() => {});
  },
);

// React to external URL changes (back/forward).
watch(
  () => route.query,
  () => {
    if (routeMatchesState()) return;
    readFromRoute();
    loadActive();
  },
);

// --- detail modals ----------------------------------------------------------
const selectedAlert = ref<Alert | null>(null);
const selectedAnomaly = ref<Anomaly | null>(null);

function onRowClick(row: FeedRow): void {
  if (row.type === 'alert') selectedAlert.value = row.alert ?? null;
  else selectedAnomaly.value = row.anomaly ?? null;
}

function triage(a: Alert, action: TriageAction): void {
  void alertsFeed.triage(a, action);
}

function statusColorOf(status: string): string {
  return status === 'open' ? 'var(--t-amber)' : status === 'acked' ? 'var(--t-blue)' : 'var(--t-dim)';
}

function onKey(e: KeyboardEvent): void {
  if (e.key !== 'Escape') return;
  if (selectedAlert.value) selectedAlert.value = null;
  else if (selectedAnomaly.value) selectedAnomaly.value = null;
}

onMounted(() => {
  readFromRoute();
  loadActive();
  window.addEventListener('keydown', onKey);
});

onUnmounted(() => window.removeEventListener('keydown', onKey));
</script>

<template>
  <div class="term term-view-root" style="height:100%;display:flex;flex-direction:column;background:var(--t-pane);min-height:0;min-width:0">
    <div v-if="forbidden" style="padding:40px;text-align:center;color:var(--t-dim)">
      You need the <code>ce.cloudengineer</code> role to view alerts.
    </div>
    <template v-else>
      <!-- header: type toggle + per-type filters + pagination -->
      <div style="display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid var(--t-line);flex:none;font-size:11.5px;flex-wrap:wrap">
        <span style="color:var(--t-red)">▌</span>
        <span style="font-weight:600;letter-spacing:.08em">ALERTS</span>

        <!-- type toggle: alerts | anomalies -->
        <span class="term-btngroup" style="display:flex;gap:3px">
          <button
            v-for="t in TYPES"
            :key="t.key"
            type="button"
            @click="setType(t.key)"
            :style="{
              background: 'none',
              border: '1px solid ' + (t.key === type ? 'var(--t-accent)' : 'var(--t-line2)'),
              color: t.key === type ? 'var(--t-accent)' : 'var(--t-dim)',
              fontFamily: 'inherit',
              fontSize: '10.5px',
              lineHeight: 1.4,
              padding: '1px 9px',
              cursor: 'pointer',
            }"
          >{{ t.label }}</button>
        </span>

        <span style="width:1px;height:14px;background:var(--t-line2)"></span>

        <!-- alert status filters -->
        <span v-if="type === 'alert'" class="term-btngroup" style="display:flex;gap:3px">
          <button
            v-for="f in ALERT_FILTERS"
            :key="f.key"
            type="button"
            @click="alertsFeed.setFilter(f.key)"
            :style="{
              background: 'none',
              border: '1px solid ' + (f.key === alertsFeed.filter.value ? 'var(--t-accent)' : 'var(--t-line2)'),
              color: f.key === alertsFeed.filter.value ? 'var(--t-accent)' : 'var(--t-dim)',
              fontFamily: 'inherit',
              fontSize: '10.5px',
              lineHeight: 1.4,
              padding: '1px 7px',
              cursor: 'pointer',
            }"
          >{{ f.label }}</button>
        </span>

        <!-- anomaly kind + range filters -->
        <template v-else>
          <select
            :value="anomaliesFeed.kind.value"
            @change="anomaliesFeed.setKind(($event.target as HTMLSelectElement).value)"
            style="background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:3px 6px;outline:none"
          >
            <option v-for="k in ANOMALY_KINDS" :key="k.key" :value="k.key">{{ k.label }}</option>
          </select>
          <span class="term-btngroup" style="display:flex;gap:3px">
            <button
              v-for="r in ANOMALY_RANGES"
              :key="r.key"
              type="button"
              @click="anomaliesFeed.setRange(r.key)"
              :style="{
                background: 'none',
                border: '1px solid ' + (r.key === anomaliesFeed.range.value ? 'var(--t-accent)' : 'var(--t-line2)'),
                color: r.key === anomaliesFeed.range.value ? 'var(--t-accent)' : 'var(--t-dim)',
                fontFamily: 'inherit',
                fontSize: '10.5px',
                lineHeight: 1.4,
                padding: '1px 7px',
                cursor: 'pointer',
              }"
            >{{ r.label }}</button>
          </span>
        </template>

        <span style="flex:1"></span>
        <template v-if="paginated">
          <span style="color:var(--t-faint)">{{ pageStart }}–{{ pageEnd }} of {{ total.toLocaleString() }}<span v-if="capped"> (capped)</span></span>
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
        </template>
        <span v-else style="color:var(--t-faint)">live · {{ total }} shown</span>
      </div>

      <div v-if="error && !forbidden" style="padding:10px 14px;color:var(--t-red);font-size:12px;flex:none">{{ error }}</div>

      <!-- table -->
      <div class="term-pane-scroll" style="flex:1;min-height:0;min-width:0;display:flex">
        <ConsoleTable
          :columns="FEED_COLUMNS"
          :rows="rows"
          :row-key="(r: FeedRow) => r.key"
          :storage-key="STORAGE_KEY"
          :loading="loading"
          :empty-text="type === 'alert' ? 'no alerts' : 'no anomalies'"
          @row-click="(r: FeedRow) => onRowClick(r)"
        >
          <template #cell-type="{ row }">
            <span :style="{ color: fr(row).type === 'anomaly' ? 'var(--t-blue)' : 'var(--t-amber)', fontSize: '10.5px', letterSpacing: '.04em' }">{{ fr(row).type }}</span>
          </template>

          <template #cell-title="{ row }">
            <div v-if="fr(row).type === 'alert'" style="line-height:1.35">
              <div style="color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ fr(row).alert!.title }}</div>
              <div style="color:var(--t-faint);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                <span :style="{ color: sourceColor(fr(row).alert!.source) }">{{ fr(row).alert!.source }}</span>
                <span style="color:var(--t-dim)"> · {{ fr(row).alert!.rule_id }}</span>
                <span v-if="fr(row).alert!.actor_id"> · <router-link
                  :to="{ name: 'console-inspect', params: { id: fr(row).alert!.actor_id! } }"
                  style="color:var(--t-dim);text-decoration:none"
                  @click.stop
                >{{ fr(row).alert!.actor_id }}</router-link></span>
                <span v-if="fr(row).alert!.event_count > 1"> · ×{{ fr(row).alert!.event_count }}</span>
                · {{ relAge(fr(row).alert!.last_seen) }}
              </div>
            </div>
            <div v-else style="line-height:1.35">
              <div style="color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ fr(row).anomaly!.title }}</div>
              <div style="color:var(--t-faint);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                <span style="color:var(--t-blue)">{{ fr(row).anomaly!.kind }}</span>
                <span v-if="fr(row).anomaly!.detail" style="color:var(--t-dim)"> · {{ fr(row).anomaly!.detail }}</span>
                <span v-if="fr(row).anomaly!.actor_id"> · <router-link
                  :to="{ name: 'console-inspect', params: { id: fr(row).anomaly!.actor_id! } }"
                  style="color:var(--t-dim);text-decoration:none"
                  @click.stop
                >{{ fr(row).anomaly!.actor_id }}</router-link></span>
                · {{ relAge(fr(row).anomaly!.event_time) }}
              </div>
            </div>
          </template>

          <template #cell-status="{ row }">
            <span v-if="fr(row).type === 'alert'" :style="{ fontSize: '10px', color: statusColorOf(fr(row).alert!.status) }">{{ fr(row).alert!.status }}</span>
            <span v-else style="font-size:10px;color:var(--t-faint)">{{ fr(row).anomaly!.kind }}</span>
          </template>

          <template #cell-actions="{ row }">
            <span v-if="fr(row).type === 'alert'" style="display:inline-flex;gap:6px;justify-content:flex-end">
              <button
                v-if="fr(row).alert!.status === 'open'"
                type="button"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(fr(row).alert!, 'ack')"
              >ack</button>
              <button
                v-if="fr(row).alert!.status === 'acked'"
                type="button"
                title="revert to open"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(fr(row).alert!, 'unack')"
              >unack</button>
              <button
                v-if="fr(row).alert!.status !== 'resolved'"
                type="button"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(fr(row).alert!, 'resolve')"
              >resolve</button>
              <button
                v-if="fr(row).alert!.status === 'resolved'"
                type="button"
                title="revert resolve"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(fr(row).alert!, 'unresolve')"
              >unresolve</button>
            </span>
            <span v-else style="color:var(--t-faint);font-size:10px">read-only</span>
          </template>
        </ConsoleTable>
      </div>
    </template>

    <AlertDetailModal
      v-if="selectedAlert"
      :alert="selectedAlert"
      @close="selectedAlert = null"
      @triage="(action) => triage(selectedAlert!, action)"
    />
    <AnomalyDetailModal
      v-if="selectedAnomaly"
      :anomaly="selectedAnomaly"
      @close="selectedAnomaly = null"
    />
  </div>
</template>
