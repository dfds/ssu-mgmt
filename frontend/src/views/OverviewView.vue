<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  fetchTimeline,
  fetchIngestHealth,
  fetchKpis,
  fetchOverviewAlerts,
  fetchActorsByRisk,
  fetchAnomalies,
  DEFERRED_SOURCES,
  type TimelineResult,
  type IngestWatermark,
  type Kpis,
  type Alert,
  type ActorRisk,
  type Anomaly,
} from '../ssumgmt/api';
import { ForbiddenError } from '../api';
import { sourceColor, formatTime, formatDateTime, severityColor, riskColor, relAge, originColor, originLabel } from '../ssumgmt/format';
import { useConsoleStream } from '../ssumgmt/useConsoleStream';
import { useAlertsFeed, ALERT_FILTERS } from '../ssumgmt/useAlertsFeed';
import { useIsMobile } from '../composables/useIsMobile';
import AlertDetailModal from '../ssumgmt/AlertDetailModal.vue';
import CacheBadge from '../components/CacheBadge.vue';

const isMobile = useIsMobile();

const { ingest, kpis, alerts } = useConsoleStream();

// REST-only refs (out of the live-stream scope): timeline, top actors, anomalies.
const timeline = ref<TimelineResult | null>(null);
const actors = ref<ActorRisk[]>([]);
const anomalies = ref<Anomaly[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const forbidden = ref(false);

const WINDOWS = [
  { key: '24h', label: '24h', ms: 24 * 3_600_000, bucket: 'hour' as const },
  { key: '7d', label: '7d', ms: 7 * 86_400_000, bucket: 'hour' as const },
  { key: '14d', label: '14d', ms: 14 * 86_400_000, bucket: 'day' as const },
  { key: '30d', label: '30d', ms: 30 * 86_400_000, bucket: 'day' as const },
  { key: '60d', label: '60d', ms: 60 * 86_400_000, bucket: 'day' as const },
  { key: '90d', label: '90d', ms: 90 * 86_400_000, bucket: 'day' as const },
];
const WINDOW_STORE_KEY = 'ssumgmt.overview.window';
const windowKey = ref(localStorage.getItem(WINDOW_STORE_KEY) ?? '24h');
const activeWindow = computed(() => WINDOWS.find((w) => w.key === windowKey.value) ?? WINDOWS[0]);
const bucketShort = computed(() => (activeWindow.value.bucket === 'day' ? 'd' : 'h'));
// The timeline is served from the hourly/daily rollup matviews for day buckets and
// for hour windows wider than the backend's 48h ROLLUP_HOUR_THRESHOLD (i.e. 7d+);
// the 24h window counts live. Mirror that so the cached badge only shows when stale.
const timelineCached = computed(
  () => activeWindow.value.bucket === 'day' || activeWindow.value.ms > 48 * 3_600_000,
);
const timelineLoading = ref(false);

const nowTick = ref(Date.now());
let ticker: ReturnType<typeof setInterval> | undefined;

let refreshTimer: ReturnType<typeof setTimeout> | undefined;
watch(ingest, () => {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => void loadTimeline({ silent: true }), 800);
});

onMounted(() => {
  load();
  loadTimeline();
  ticker = setInterval(() => (nowTick.value = Date.now()), 1000);
  window.addEventListener('keydown', onKey);
});

onUnmounted(() => {
  if (ticker) clearInterval(ticker);
  if (refreshTimer) clearTimeout(refreshTimer);
  window.removeEventListener('keydown', onKey);
});

async function load(): Promise<void> {
  loading.value = true;
  error.value = null;
  forbidden.value = false;
  try {
    const [ih, k, al, ar] = await Promise.all([
      fetchIngestHealth().catch(() => [] as IngestWatermark[]),
      fetchKpis(),
      fetchOverviewAlerts({ limit: 12 }),
      fetchActorsByRisk(8),
    ]);
    actors.value = ar;
    if (!ingest.value.length) ingest.value = ih;
    if (!kpis.value) kpis.value = k;
    if (!alerts.value.length) alerts.value = al;
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
    else error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

async function loadTimeline(opts: { silent?: boolean } = {}): Promise<void> {
  const w = activeWindow.value;
  const reqKey = w.key;
  const from = new Date(Date.now() - w.ms).toISOString();
  if (!opts.silent) timelineLoading.value = true;
  try {
    const [tl, an] = await Promise.all([
      fetchTimeline({ bucket: w.bucket, from }),
      fetchAnomalies({ from, limit: 500 }).catch(() => [] as Anomaly[]),
    ]);
    // Drop a stale response if the user switched windows while this was in flight.
    if (windowKey.value !== reqKey) return;
    timeline.value = tl;
    anomalies.value = an;
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
    else if (!opts.silent) error.value = e instanceof Error ? e.message : String(e);
  } finally {
    if (!opts.silent) timelineLoading.value = false;
  }
}

function setWindow(key: string): void {
  if (key === windowKey.value) return;
  windowKey.value = key;
  localStorage.setItem(WINDOW_STORE_KEY, key);
  void loadTimeline();
}

// Per-source ingest watermark, keyed by source for the SOURCES panel.
const ingestBySource = computed(() => {
  const m = new Map<string, IngestWatermark>();
  for (const w of ingest.value) m.set(w.source, w);
  return m;
});

const STALE_MS = 30 * 60_000;

function freshness(source: string): { label: string; color: string; title: string } {
  if (source === 'selfservice')
    return { label: 'live', color: 'var(--t-accent)', title: 'self-service Kafka stream (continuous)' };
  const w = ingestBySource.value.get(source);
  if (!w || !w.last_run_at)
    return { label: 'no data', color: 'var(--t-faint)', title: 'no ingest run recorded yet' };
  const age = nowTick.value - new Date(w.last_run_at).getTime();
  if (w.last_run_error && age <= STALE_MS)
    return { label: 'stalled', color: 'var(--t-red)', title: `errored ${relAge(w.last_run_at)} — ${w.last_run_error}` };
  if (w.last_run_error)
    return {
      label: `stale ${relAge(w.last_run_at)}`,
      color: 'var(--t-amber)',
      title: `no completed run in ${relAge(w.last_run_at)} — last recorded attempt errored: ${w.last_run_error}`,
    };
  if (age > STALE_MS)
    return {
      label: `stale ${relAge(w.last_run_at)}`,
      color: 'var(--t-amber)',
      title: `last ran ${relAge(w.last_run_at)} — ingest loop may be stopped or disabled`,
    };
  return { label: relAge(w.last_run_at), color: 'var(--t-dim)', title: `last successful ingest ${relAge(w.last_run_at)}` };
}

const bars = computed(() => {
  const tl = timeline.value;
  if (!tl) return [] as { ts: string; total: number }[];
  const byBucket = new Map<string, number>();
  for (const r of tl.rows) byBucket.set(r.bucket, (byBucket.get(r.bucket) ?? 0) + r.count);
  return [...byBucket.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([ts, total]) => ({ ts, total }));
});

const peak = computed(() => bars.value.reduce((m, b) => Math.max(m, b.total), 0));
const eventsInWindow = computed(() => bars.value.reduce((s, b) => s + b.total, 0));

const bucketMs = computed(() => (activeWindow.value.bucket === 'day' ? 86_400_000 : 3_600_000));

const anomaliesByBucket = computed(() => {
  const size = bucketMs.value;
  const m = new Map<number, number>();
  for (const a of anomalies.value) {
    const t = new Date(a.event_time).getTime();
    if (!Number.isNaN(t)) {
      const k = Math.floor(t / size) * size;
      m.set(k, (m.get(k) ?? 0) + 1);
    }
  }
  return m;
});

function anomaliesAt(ts: string): number {
  const size = bucketMs.value;
  const k = Math.floor(new Date(ts).getTime() / size) * size;
  return anomaliesByBucket.value.get(k) ?? 0;
}

type TipLine = { text: string; color: string };
const tip = ref<{ lines: TipLine[]; x: number; y: number } | null>(null);
const tipEl = ref<HTMLElement | null>(null);
const tipW = ref(180);
const tipH = ref(64);
watch(tip, async (v) => {
  if (!v) return;
  await nextTick();
  if (tipEl.value) {
    tipW.value = tipEl.value.offsetWidth;
    tipH.value = tipEl.value.offsetHeight;
  }
});
function showTip(lines: TipLine[], e: MouseEvent) {
  tip.value = { lines, x: e.clientX, y: e.clientY };
}
function moveTip(e: MouseEvent) {
  if (tip.value) {
    tip.value.x = e.clientX;
    tip.value.y = e.clientY;
  }
}
function hideTip() {
  tip.value = null;
}
// Timeline bar / anomaly-marker tooltip: date-time, event total, optional anomaly line.
function showBar(b: { ts: string; total: number }, e: MouseEvent) {
  const n = anomaliesAt(b.ts);
  const lines: TipLine[] = [
    { text: formatDateTime(b.ts), color: 'var(--t-text)' },
    { text: `${b.total.toLocaleString()} events`, color: 'var(--t-dim)' },
  ];
  if (n > 0) lines.push({ text: `${n} ${n === 1 ? 'anomaly' : 'anomalies'} · click for detail`, color: 'var(--t-amber)' });
  showTip(lines, e);
}
function clickBar(b: { ts: string }) {
  if (anomaliesAt(b.ts) > 0) openAnomalies(b.ts);
}
const hoverStyle = computed(() => {
  const h = tip.value;
  if (!h) return {};
  const left = Math.min(h.x + 12, window.innerWidth - tipW.value - 8);
  const top = Math.min(h.y + 14, window.innerHeight - tipH.value - 8);
  return {
    position: 'fixed' as const,
    left: Math.max(8, left) + 'px',
    top: Math.max(8, top) + 'px',
    zIndex: 200,
    pointerEvents: 'none' as const,
    background: 'var(--t-node)',
    border: '1px solid var(--t-line2)',
    borderRadius: '3px',
    padding: '5px 9px',
    fontSize: '11px',
    lineHeight: 1.45,
    maxWidth: '320px',
    boxShadow: '0 4px 14px rgba(0,0,0,0.28)',
    fontVariantNumeric: 'tabular-nums',
  };
});

const EVENT_SOURCES = ['selfservice', 'cloudtrail', 'github'];

const sources = computed(() => {
  const counts = new Map<string, number>();
  const tl = timeline.value;
  if (tl) for (const r of tl.rows) counts.set(r.source, (counts.get(r.source) ?? 0) + r.count);

  const ids = new Set<string>(['selfservice']);
  for (const w of ingest.value) if (EVENT_SOURCES.includes(w.source)) ids.add(w.source);
  for (const s of counts.keys()) ids.add(s);

  return [...ids]
    .map((source) => ({ source, count: tl ? (counts.get(source) ?? 0) : null }))
    .sort((a, b) => (b.count ?? -1) - (a.count ?? -1) || a.source.localeCompare(b.source));
});

const sourceMax = computed(() => sources.value.reduce((m, s) => Math.max(m, s.count ?? 0), 0));

function bar(count: number, max: number, width = 14): { full: string; empty: string } {
  const n = max > 0 ? Math.round((count / max) * width) : 0;
  return { full: '█'.repeat(n), empty: '░'.repeat(width - n) };
}

const {
  filter: alertFilter,
  rows: displayedAlerts,
  total: alertTotal,
  pageStart,
  pageEnd,
  canPrev,
  canNext,
  paginated,
  loading: alertsLoading,
  setFilter: setAlertFilter,
  prev: alertsPrev,
  next: alertsNext,
  triage,
} = useAlertsFeed({ pageSize: 10 });

const visibleAlerts = computed(() =>
  isMobile.value && !paginated.value ? displayedAlerts.value.slice(0, 5) : displayedAlerts.value,
);

const alertEmptyLabel = computed(() =>
  alertFilter.value === 'live' ? 'open' : alertFilter.value === 'all' ? '' : alertFilter.value,
);

const guarddutyLabel = computed(() => {
  const k = kpis.value;
  if (!k) return '·';
  return k.guardduty === null ? 'no data' : String(k.guardduty);
});

const showAnomalies = ref(false);
const anomalyBucket = ref<number | null>(null);

const anomaliesShown = computed(() => {
  const size = bucketMs.value;
  const list = [...anomalies.value].sort(
    (a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime(),
  );
  if (anomalyBucket.value === null) return list;
  return list.filter((a) => Math.floor(new Date(a.event_time).getTime() / size) * size === anomalyBucket.value);
});

function openAnomalies(bucketTs?: string): void {
  anomalyBucket.value =
    bucketTs === undefined ? null : Math.floor(new Date(bucketTs).getTime() / bucketMs.value) * bucketMs.value;
  showAnomalies.value = true;
}

const selectedAlert = ref<Alert | null>(null);

function onKey(e: KeyboardEvent): void {
  if (e.key !== 'Escape') return;
  if (selectedAlert.value) selectedAlert.value = null;
  else if (showAnomalies.value) showAnomalies.value = false;
}
</script>

<template>
  <div
    class="term-view-root"
    style="height:100%;overflow:hidden;background:var(--t-line);display:grid;gap:1px;grid-template-rows:auto auto minmax(0,1fr);padding:0"
  >
    <div v-if="forbidden" style="background:var(--t-pane);padding:40px;text-align:center;color:var(--t-dim)">
      You need the <code>ce.cloudengineer</code> role to view the console.
    </div>
    <div v-else-if="error" style="background:var(--t-pane);padding:40px;text-align:center;color:var(--t-red)">
      {{ error }}
    </div>
    <template v-else>
      <!-- KPI row -->
      <div class="term-tilegrid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--t-line)">
        <div style="background:var(--t-pane);padding:12px 16px">
          <div style="color:var(--t-faint);font-size:11px;letter-spacing:.04em">failed_auth/24h</div>
          <div
            :style="{ color: (kpis?.failed_auth_24h ?? 0) > 0 ? 'var(--t-amber)' : 'var(--t-accent)', fontSize: '30px', fontWeight: 700, marginTop: '4px' }"
          >{{ loading ? '·' : (kpis?.failed_auth_24h ?? 0).toLocaleString() }}</div>
          <div style="color:var(--t-dim);font-size:11.5px;margin-top:7px">{{ eventsInWindow.toLocaleString() }} events/{{ activeWindow.label }}</div>
        </div>
        <div style="background:var(--t-pane);padding:12px 16px">
          <div style="color:var(--t-faint);font-size:11px;letter-spacing:.04em">deactivated/24h</div>
          <div style="color:var(--t-text);font-size:30px;font-weight:700;margin-top:4px">
            {{ loading ? '·' : (kpis?.deactivated_24h ?? 0) }}
          </div>
          <div style="color:var(--t-dim);font-size:11.5px;margin-top:7px">IAM user/login removals</div>
        </div>
        <div style="background:var(--t-pane);padding:12px 16px">
          <div style="color:var(--t-faint);font-size:11px;letter-spacing:.04em">guardduty<CacheBadge kind="guardduty" /></div>
          <div
            :style="{ color: kpis?.guardduty === null ? 'var(--t-faint)' : 'var(--t-red)', fontSize: '30px', fontWeight: 700, marginTop: '4px' }"
          >{{ loading ? '·' : guarddutyLabel }}</div>
          <div style="color:var(--t-dim);font-size:11.5px;margin-top:7px">
            {{ kpis?.guardduty === null ? 'detector not connected' : 'open findings' }}
          </div>
        </div>
        <div
          :style="{ background: 'var(--t-pane)', padding: '12px 16px', cursor: anomalies.length ? 'pointer' : 'default' }"
          :title="anomalies.length ? 'view anomalies' : ''"
          @click="anomalies.length && openAnomalies()"
        >
          <div style="color:var(--t-faint);font-size:11px;letter-spacing:.04em">anomalies/24h<CacheBadge kind="siem" /></div>
          <div
            :style="{ color: (kpis?.anomalies ?? 0) > 0 ? 'var(--t-amber)' : 'var(--t-accent)', fontSize: '30px', fontWeight: 700, marginTop: '4px' }"
          >{{ loading ? '·' : (kpis?.anomalies ?? 0) }}</div>
          <div style="color:var(--t-dim);font-size:11.5px;margin-top:7px">
            statistical · <span :style="anomalies.length ? 'color:var(--t-amber);text-decoration:underline' : ''">{{ anomalies.length }} in {{ activeWindow.label }}</span>
          </div>
        </div>
      </div>

      <!-- timeline -->
      <div style="background:var(--t-pane)">
        <div class="term-toolbar" style="display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid var(--t-line)">
          <span style="color:var(--t-accent)">▌</span>
          <span style="font-weight:600;letter-spacing:.08em;font-size:11.5px">EVENT&nbsp;TIMELINE<CacheBadge v-if="timelineCached" kind="timeline" /></span>
          <span style="color:var(--t-faint);font-size:11px">by {{ activeWindow.bucket }} · {{ activeWindow.label }}</span>
          <span style="flex:1"></span>
          <span v-if="anomalies.length" style="color:var(--t-amber);font-size:11px">◆ anomaly</span>
          <span class="term-btngroup" style="display:flex;gap:3px">
            <button
              v-for="w in WINDOWS"
              :key="w.key"
              type="button"
              :disabled="timelineLoading"
              @click="setWindow(w.key)"
              :style="{
                background: 'none',
                border: '1px solid ' + (w.key === windowKey ? 'var(--t-accent)' : 'var(--t-line2)'),
                color: w.key === windowKey ? 'var(--t-accent)' : 'var(--t-dim)',
                fontFamily: 'inherit',
                fontSize: '10.5px',
                lineHeight: 1.4,
                padding: '1px 6px',
                cursor: timelineLoading ? 'default' : 'pointer',
              }"
            >{{ w.label }}</button>
          </span>
          <span style="color:var(--t-faint);font-size:11px">pk {{ peak }}/{{ bucketShort }} · {{ eventsInWindow.toLocaleString() }} total</span>
        </div>
        <!-- anomaly marker strip, aligned 1:1 with the bars below -->
        <div v-if="bars.length" style="padding:4px 14px 0;display:flex;align-items:flex-end;gap:3px;height:14px">
          <div
            v-for="b in bars"
            :key="'m' + b.ts"
            style="flex:1;min-width:4px;text-align:center;line-height:1"
          >
            <span
              v-if="anomaliesAt(b.ts) > 0"
              style="color:var(--t-amber);font-size:9px;cursor:pointer"
              @mouseenter="showBar(b, $event)"
              @mousemove="moveTip"
              @mouseleave="hideTip"
              @click="openAnomalies(b.ts)"
            >◆</span>
          </div>
        </div>
        <div :style="{ padding: bars.length ? '0 14px 14px' : '14px', height: '100px', display: 'flex', alignItems: 'flex-end', gap: '3px' }">
          <div
            v-for="b in bars"
            :key="b.ts"
            @mouseenter="showBar(b, $event)"
            @mousemove="moveTip"
            @mouseleave="hideTip"
            @click="clickBar(b)"
            :style="{
              flex: '1',
              minWidth: '4px',
              height: peak > 0 ? Math.max(2, (b.total / peak) * 100) + '%' : '2px',
              background: anomaliesAt(b.ts) > 0 ? 'var(--t-amber)' : 'var(--t-accent)',
              opacity: b.total > 0 ? 1 : 0.25,
              cursor: anomaliesAt(b.ts) > 0 ? 'pointer' : 'default',
            }"
          ></div>
          <div v-if="!bars.length" style="color:var(--t-faint);font-size:11.5px">no events in window</div>
        </div>
      </div>

      <!-- bottom: alerts | sources + top actors -->
      <div class="term-split" style="display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:1px;background:var(--t-line);min-height:0">
        <!-- alerts feed -->
        <div style="background:var(--t-pane);display:flex;flex-direction:column;min-height:0">
          <div class="term-toolbar" style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--t-line);flex:none">
            <span style="color:var(--t-red)">▌</span>
            <span style="font-weight:600;letter-spacing:.08em;font-size:11.5px">ALERTS<CacheBadge kind="siem" /></span>
            <span class="term-btngroup" style="display:flex;gap:3px">
              <button
                v-for="f in ALERT_FILTERS"
                :key="f.key"
                type="button"
                @click="setAlertFilter(f.key)"
                :style="{
                  background: 'none',
                  border: '1px solid ' + (f.key === alertFilter ? 'var(--t-accent)' : 'var(--t-line2)'),
                  color: f.key === alertFilter ? 'var(--t-accent)' : 'var(--t-dim)',
                  fontFamily: 'inherit',
                  fontSize: '10.5px',
                  lineHeight: 1.4,
                  padding: '1px 6px',
                  cursor: 'pointer',
                }"
              >{{ f.label }}</button>
            </span>
            <span style="flex:1"></span>
            <span style="color:var(--t-faint);font-size:11px">{{ kpis?.open_alerts ?? 0 }} open</span>
            <router-link
              :to="{ name: 'console-alerts' }"
              title="open the full alerts page"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10.5px;padding:1px 7px;cursor:pointer;text-decoration:none"
            >view all →</router-link>
          </div>
          <div style="overflow:auto;min-height:0">
            <div
              v-for="a in visibleAlerts"
              :key="a.id"
              style="display:flex;align-items:center;gap:10px;padding:7px 14px;border-bottom:1px solid var(--t-line);font-size:12px;cursor:pointer"
              title="view alert detail"
              @click="selectedAlert = a"
            >
              <span :style="{ color: severityColor(a.severity), flex: 'none', width: '64px', fontWeight: 700, fontSize: '10.5px', letterSpacing: '.04em' }">{{ a.severity.toUpperCase() }}</span>
              <div style="flex:1;min-width:0">
                <div style="color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ a.title }}</div>
                <div style="color:var(--t-faint);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  <span :style="{ color: sourceColor(a.source) }">{{ a.source }}</span>
                  <span v-if="a.actor_id"> · <router-link :to="{ name: 'console-inspect', params: { id: a.actor_id } }" style="color:var(--t-dim);text-decoration:none" @click.stop>{{ a.actor_id }}</router-link></span>
                  <span v-if="a.event_count > 1"> · ×{{ a.event_count }}</span>
                  · {{ relAge(a.last_seen) }}
                </div>
              </div>
              <span
                :style="{ flex: 'none', width: '52px', textAlign: 'center', fontSize: '10px', color: a.status === 'open' ? 'var(--t-amber)' : a.status === 'acked' ? 'var(--t-blue)' : 'var(--t-dim)' }"
              >{{ a.status }}</span>
              <button
                v-if="a.status === 'open'"
                type="button"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(a, 'ack')"
              >ack</button>
              <button
                v-if="a.status === 'acked'"
                type="button"
                title="revert to open"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(a, 'unack')"
              >unack</button>
              <button
                v-if="a.status !== 'resolved'"
                type="button"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(a, 'resolve')"
              >resolve</button>
              <button
                v-if="a.status === 'resolved'"
                type="button"
                title="revert resolve"
                style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 6px;cursor:pointer"
                @click.stop="triage(a, 'unresolve')"
              >unresolve</button>
            </div>
            <div v-if="!loading && !alertsLoading && !displayedAlerts.length" style="padding:20px 14px;color:var(--t-faint);font-size:12px">no{{ alertEmptyLabel ? ' ' + alertEmptyLabel : '' }} alerts</div>
            <div v-if="loading || alertsLoading" style="padding:20px 14px;color:var(--t-faint);font-size:12px">loading…</div>
          </div>
          <!-- pagination — only for the non-live (paged) filters -->
          <div
            v-if="paginated"
            style="display:flex;align-items:center;gap:10px;padding:6px 14px;border-top:1px solid var(--t-line);flex:none;font-size:11px"
          >
            <span style="color:var(--t-faint)">{{ pageStart }}–{{ pageEnd }} of {{ alertTotal.toLocaleString() }}</span>
            <span style="flex:1"></span>
            <button
              type="button"
              :disabled="!canPrev"
              :style="{ opacity: canPrev ? 1 : 0.4, cursor: canPrev ? 'pointer' : 'default' }"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10.5px;padding:1px 8px"
              @click="alertsPrev"
            >← prev</button>
            <button
              type="button"
              :disabled="!canNext"
              :style="{ opacity: canNext ? 1 : 0.4, cursor: canNext ? 'pointer' : 'default' }"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10.5px;padding:1px 8px"
              @click="alertsNext"
            >next →</button>
          </div>
        </div>

        <!-- right column: sources + top actors -->
        <div class="term-order-first" style="display:grid;grid-template-columns:minmax(0,1fr);grid-template-rows:auto minmax(0,1fr);gap:1px;background:var(--t-line);min-height:0;min-width:0">
          <div style="background:var(--t-pane)">
            <div style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--t-line)">
              <span style="color:var(--t-accent)">▌</span>
              <span style="font-weight:600;letter-spacing:.08em;font-size:11.5px">SOURCES<CacheBadge kind="timeline" /></span>
              <span style="flex:1"></span>
              <span style="color:var(--t-faint);font-size:11px">ingest · events/{{ activeWindow.label }}</span>
            </div>
            <div style="padding:6px 0">
              <div
                v-for="s in sources"
                :key="s.source"
                style="display:flex;align-items:center;gap:10px;padding:5px 14px;font-size:12px"
              >
                <span style="color:var(--t-text);flex:none;width:88px;overflow:hidden;text-overflow:ellipsis">{{ s.source }}</span>
                <span style="letter-spacing:.5px;flex:none">
                  <span :style="{ color: sourceColor(s.source) }">{{ bar(s.count ?? 0, sourceMax).full }}</span><span style="color:var(--t-line2)">{{ bar(s.count ?? 0, sourceMax).empty }}</span>
                </span>
                <span style="flex:1"></span>
                <span
                  :style="{ color: freshness(s.source).color, flex: 'none', width: '92px', textAlign: 'right', fontSize: '11px', cursor: 'help' }"
                  @mouseenter="showTip([{ text: freshness(s.source).title, color: 'var(--t-dim)' }], $event)"
                  @mousemove="moveTip"
                  @mouseleave="hideTip"
                >{{ freshness(s.source).label }}</span>
                <span style="color:var(--t-dim);flex:none;min-width:56px;text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums">{{ s.count === null ? '···' : s.count.toLocaleString() }}</span>
              </div>
              <div v-if="!sources.length" style="padding:14px;color:var(--t-faint);font-size:12px">no sources</div>
              <div
                v-for="d in DEFERRED_SOURCES"
                :key="d.source"
                style="display:flex;align-items:center;gap:10px;padding:5px 14px;font-size:12px;opacity:.55;cursor:help"
                @mouseenter="showTip([{ text: d.note, color: 'var(--t-dim)' }], $event)"
                @mousemove="moveTip"
                @mouseleave="hideTip"
              >
                <span style="color:var(--t-faint);flex:none;width:88px;overflow:hidden;text-overflow:ellipsis">{{ d.label }}</span>
                <span style="letter-spacing:.5px;flex:none;color:var(--t-line2)">░░░░░░░░░░░░░░</span>
                <span style="flex:1"></span>
                <span style="color:var(--t-faint);flex:none;text-align:right;font-size:10px;border:1px solid var(--t-line2);padding:0 5px">TODO</span>
              </div>
            </div>
          </div>

          <!-- top actors by risk -->
          <div style="background:var(--t-pane);display:flex;flex-direction:column;min-height:0">
            <div style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--t-line);flex:none">
              <span style="color:var(--t-amber)">▌</span>
              <span style="font-weight:600;letter-spacing:.08em;font-size:11.5px">TOP&nbsp;ACTORS · RISK<CacheBadge kind="siem" /></span>
              <span style="flex:1"></span>
              <span style="color:var(--t-faint);font-size:11px">{{ kpis?.actors_tracked ?? 0 }} tracked</span>
            </div>
            <div style="overflow:auto;min-height:0">
              <router-link
                v-for="a in actors"
                :key="a.id"
                :to="{ name: 'console-inspect', params: { id: a.id } }"
                style="display:flex;align-items:center;gap:10px;padding:6px 14px;border-bottom:1px solid var(--t-line);font-size:12px;cursor:pointer;text-decoration:none"
              >
                <span :style="{ color: riskColor(a.score), flex: 'none', width: '28px', fontWeight: 700, textAlign: 'right' }">{{ a.score }}</span>
                <span style="letter-spacing:.5px;flex:none">
                  <span :style="{ color: riskColor(a.score) }">{{ bar(a.score, 100, 8).full }}</span><span style="color:var(--t-line2)">{{ bar(a.score, 100, 8).empty }}</span>
                </span>
                <span style="flex:1;min-width:0;color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ a.display_name ?? a.id }}</span>
                <span v-if="(a.origins ?? []).length" style="flex:none;display:flex;gap:3px">
                  <span
                    v-for="o in a.origins"
                    :key="o"
                    :style="{ color: originColor(o), border: '1px solid ' + originColor(o), fontSize: '8.5px', padding: '0 4px', lineHeight: '13px', letterSpacing: '.03em' }"
                  >{{ originLabel(o) }}</span>
                </span>
                <span :style="{ flex: 'none', fontSize: '10px', color: a.kind === 'unresolved' ? 'var(--t-faint)' : 'var(--t-dim)' }">{{ a.kind }}</span>
              </router-link>
              <div v-if="!loading && !actors.length" style="padding:14px;color:var(--t-faint);font-size:12px">no scored actors yet</div>
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- anomalies detail modal (opened from the KPI tile or a timeline ◆ marker) -->
    <div
      v-if="showAnomalies"
      style="position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:24px"
      @click.self="showAnomalies = false"
    >
      <div
        class="term"
        style="width:min(720px,100%);max-height:80vh;display:flex;flex-direction:column;background:var(--t-pane);border:1px solid var(--t-line2)"
      >
        <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--t-line);flex:none">
          <span style="color:var(--t-amber)">◆</span>
          <span style="color:var(--t-text);font-weight:600;letter-spacing:.06em">ANOMALIES</span>
          <span style="color:var(--t-faint);font-size:11px">
            {{ anomaliesShown.length }}{{ anomalyBucket === null ? ` in ${activeWindow.label}` : ' in bucket' }} · statistical soft signal
          </span>
          <span style="flex:1"></span>
          <button
            v-if="anomalyBucket !== null"
            type="button"
            style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer"
            @click="anomalyBucket = null"
          >show all</button>
          <button
            type="button"
            style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer"
            @click="showAnomalies = false"
          >[esc]</button>
        </div>
        <div style="overflow:auto;min-height:0">
          <div
            v-for="n in anomaliesShown"
            :key="n.id"
            style="padding:10px 16px;border-bottom:1px solid var(--t-line);font-size:12px"
          >
            <div style="display:flex;align-items:center;gap:10px">
              <span :style="{ color: severityColor(n.severity), flex: 'none', fontSize: '10px', fontWeight: 700, letterSpacing: '.04em', width: '60px' }">{{ n.severity.toUpperCase() }}</span>
              <span style="flex:none;color:var(--t-amber);font-size:10.5px;letter-spacing:.03em">{{ n.kind }}</span>
              <span style="flex:1"></span>
              <span style="flex:none;color:var(--t-faint);font-size:11px" :title="formatTime(n.event_time)">{{ relAge(n.event_time) }}</span>
            </div>
            <div style="color:var(--t-text);margin-top:5px">{{ n.detail ?? n.title }}</div>
            <div style="display:flex;align-items:center;gap:14px;margin-top:6px;color:var(--t-dim);font-size:11px">
              <span v-if="n.actor_id">
                actor
                <router-link :to="{ name: 'console-inspect', params: { id: n.actor_id } }" style="color:var(--t-accent);text-decoration:none" @click="showAnomalies = false">{{ n.actor_id }}</router-link>
              </span>
              <span v-if="n.baseline !== null || n.observed !== null">
                baseline <span style="color:var(--t-text)">{{ n.baseline ?? '—' }}</span>
                → observed <span style="color:var(--t-text)">{{ n.observed ?? '—' }}</span>
              </span>
              <span>score <span style="color:var(--t-text)">{{ n.score }}</span></span>
            </div>
          </div>
          <div v-if="!anomaliesShown.length" style="padding:20px 16px;color:var(--t-faint);font-size:12px">no anomalies in this window</div>
        </div>
      </div>
    </div>

    <!-- alert detail modal (opened by clicking an alert row in the feed) -->
    <AlertDetailModal
      v-if="selectedAlert"
      :alert="selectedAlert"
      @close="selectedAlert = null"
      @triage="(action) => triage(selectedAlert!, action)"
    />

    <Teleport to="body">
      <Transition name="ssu-tip">
        <div v-if="tip" ref="tipEl" class="term" :style="hoverStyle">
          <div v-for="(ln, i) in tip.lines" :key="i" :style="{ color: ln.color }">{{ ln.text }}</div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<style>
.ssu-tip-enter-active,
.ssu-tip-leave-active {
  transition: opacity 0.09s ease;
}
.ssu-tip-enter-from,
.ssu-tip-leave-to {
  opacity: 0;
}
</style>
