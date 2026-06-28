<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { fetchGraph, type GraphResult, type GraphNode } from '../ssumgmt/api';
import { ForbiddenError } from '../api';
import { sourceColor, riskColor } from '../ssumgmt/format';
import CacheBadge from '../components/CacheBadge.vue';

const route = useRoute();
const router = useRouter();

type Mode = 'surface' | 'investigate' | 'entity';
const mode = ref<Mode>((route.query.actor ? 'entity' : 'surface') as Mode);
const actor = ref<string>((route.query.actor as string | undefined) ?? '');
const graph = ref<GraphResult | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
const forbidden = ref(false);

const W = 1000;
const H_MIN = 620;
// Vertical room each node needs: circle (≤18) + label below (+12, ~11px tall).
const ROW_GAP = 34;

onMounted(load);
watch(mode, load);

async function load(): Promise<void> {
  if (mode.value === 'entity' && !actor.value.trim()) {
    graph.value = null;
    return;
  }
  loading.value = true;
  error.value = null;
  forbidden.value = false;
  try {
    graph.value = await fetchGraph({ mode: mode.value, actor: actor.value.trim() || undefined });
  } catch (e) {
    if (e instanceof ForbiddenError) forbidden.value = true;
    else error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

const layout = computed(() => {
  const g = graph.value;
  const pos = new Map<string, { x: number; y: number; n: GraphNode }>();
  if (!g) return { pos, H: H_MIN };
  const order = ['source', 'ip', 'actor'];
  const byType = new Map<string, GraphNode[]>();
  for (const n of g.nodes) {
    if (!byType.has(n.type)) byType.set(n.type, []);
    byType.get(n.type)!.push(n);
  }
  const cols = order.filter((t) => byType.has(t));
  const maxCount = cols.reduce((m, t) => Math.max(m, byType.get(t)!.length), 1);
  const H = Math.max(H_MIN, maxCount * ROW_GAP + 30);
  const colW = W / (cols.length + 1);
  cols.forEach((t, ci) => {
    const list = byType.get(t)!;
    const x = colW * (ci + 1);
    const gap = H / (list.length + 1);
    list.forEach((n, i) => pos.set(n.id, { x, y: gap * (i + 1), n }));
  });
  return { pos, H };
});
const positioned = computed(() => layout.value.pos);
const viewH = computed(() => layout.value.H);

const edges = computed(() => {
  const g = graph.value;
  const pos = positioned.value;
  if (!g) return [] as { x1: number; y1: number; x2: number; y2: number; w: number; failure: boolean }[];
  const out = [];
  const maxW = g.edges.reduce((m, e) => Math.max(m, e.weight), 1);
  for (const e of g.edges) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    out.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, w: 0.5 + (e.weight / maxW) * 3, failure: e.failure });
  }
  return out;
});

// Hovered node → in-SVG tooltip (scales with the viewBox, so no pixel maths).
const hovered = ref<{ n: GraphNode; x: number; y: number } | null>(null);

function isFocal(n: GraphNode): boolean {
  return mode.value === 'entity' && n.id === `actor:${actor.value.trim()}`;
}

function nodeColor(n: GraphNode): string {
  if (n.type === 'actor') return riskColor(n.risk);
  if (n.type === 'source') return sourceColor(n.label);
  return 'var(--t-dim)';
}

function tooltipLines(n: GraphNode): string[] {
  if (n.type === 'actor') return [n.label, `risk ${n.risk}`, 'click → inspect'];
  if (n.type === 'source') return [`source: ${n.label}`];
  return [`ip: ${n.label}`];
}

function nodeRadius(n: GraphNode): number {
  if (n.type === 'source') return 14;
  if (n.type === 'ip') return 8;
  return 9 + (n.risk / 100) * 9;
}

function actorHref(n: GraphNode): string {
  return router.resolve({ name: 'console-inspect', params: { id: n.id.replace(/^actor:/, '') } }).href;
}

function onNode(n: GraphNode, ev?: MouseEvent): void {
  if (n.type !== 'actor') return;
  // Let modified/middle clicks fall through to the native href (new tab).
  if (ev && (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.button === 1)) return;
  ev?.preventDefault();
  void router.push({ name: 'console-inspect', params: { id: n.id.replace(/^actor:/, '') } });
}

function applyActor(): void {
  void load();
}
</script>

<template>
  <div class="term-view-root" style="height:100%;display:flex;flex-direction:column;background:var(--t-pane);overflow:hidden">
    <!-- controls -->
    <div class="term-toolbar" style="display:flex;align-items:center;gap:12px;padding:8px 14px;border-bottom:1px solid var(--t-line);flex:none">
      <span style="color:var(--t-accent)">▌</span>
      <span style="font-weight:600;letter-spacing:.08em;font-size:11.5px">GRAPH<CacheBadge kind="siem" /></span>
      <div style="display:flex;gap:1px;background:var(--t-line);border:1px solid var(--t-line2)">
        <button
          v-for="m in (['surface','investigate','entity'] as Mode[])"
          :key="m"
          type="button"
          :style="{ background: mode === m ? 'var(--t-bg)' : 'var(--t-pane)', color: mode === m ? 'var(--t-text)' : 'var(--t-dim)', border: 'none', fontFamily: 'inherit', fontSize: '11px', padding: '3px 10px', cursor: 'pointer' }"
          @click="mode = m"
        >{{ m }}</button>
      </div>
      <input
        v-if="mode !== 'surface'"
        v-model="actor"
        :placeholder="mode === 'entity' ? 'actor id (required)…' : 'actor filter…'"
        class="term-input-fluid"
        style="background:var(--t-bg);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:12px;padding:4px 8px;outline:none;width:280px"
        @keyup.enter="applyActor"
      />
      <button
        v-if="mode !== 'surface'"
        type="button"
        style="background:none;border:1px solid var(--t-line2);color:var(--t-accent);font-family:inherit;font-size:11px;padding:3px 9px;cursor:pointer"
        @click="applyActor"
      >go</button>
      <span style="flex:1"></span>
      <span v-if="graph" style="color:var(--t-faint);font-size:11px">
        showing {{ graph.shownOf.shown }} of {{ graph.shownOf.total }} actors · {{ graph.nodes.length }} nodes · {{ graph.edges.length }} edges
      </span>
    </div>

    <!-- canvas -->
    <div style="flex:1;min-height:0;position:relative;overflow-y:auto;overflow-x:hidden">
      <div v-if="forbidden" style="padding:40px;text-align:center;color:var(--t-dim)">
        You need the <code>ce.cloudengineer</code> role to view the console.
      </div>
      <div v-else-if="error" style="padding:40px;text-align:center;color:var(--t-red)">{{ error }}</div>
      <div v-else-if="loading" style="padding:40px;text-align:center;color:var(--t-faint)">loading…</div>
      <div v-else-if="mode === 'entity' && !actor.trim()" style="padding:40px;text-align:center;color:var(--t-faint)">
        Enter an actor id to render its 1–2-hop neighbourhood.
      </div>
      <div v-else-if="graph && !graph.nodes.length" style="padding:40px;text-align:center;color:var(--t-faint)">
        No graph data in window.
      </div>
      <svg
        v-else-if="graph"
        :viewBox="`0 0 ${W} ${viewH}`"
        preserveAspectRatio="xMidYMid meet"
        style="width:100%;height:auto;display:block"
      >
        <line
          v-for="(e, i) in edges"
          :key="'e' + i"
          :x1="e.x1" :y1="e.y1" :x2="e.x2" :y2="e.y2"
          :stroke="e.failure ? 'var(--t-red)' : 'var(--t-line2)'"
          :stroke-width="e.w"
          :opacity="e.failure ? 0.6 : 0.4"
        />
        <template v-for="[id, p] in positioned" :key="id">
          <a
            v-if="p.n.type === 'actor'"
            :href="actorHref(p.n)"
            style="cursor:pointer"
            @click="onNode(p.n, $event)"
            @mouseenter="hovered = { n: p.n, x: p.x, y: p.y }"
            @mouseleave="hovered = null"
          >
            <circle
              v-if="isFocal(p.n)"
              :cx="p.x" :cy="p.y" :r="nodeRadius(p.n) + 5"
              fill="none" stroke="var(--t-accent)" stroke-width="2" opacity="0.8"
            />
            <circle :cx="p.x" :cy="p.y" :r="nodeRadius(p.n)" :fill="nodeColor(p.n)" :opacity="0.9" />
            <text
              :x="p.x"
              :y="p.y + nodeRadius(p.n) + 12"
              text-anchor="middle"
              fill="var(--t-text)"
              font-size="11"
              font-family="inherit"
            >{{ p.n.label.length > 22 ? p.n.label.slice(0, 21) + '…' : p.n.label }}</text>
          </a>
          <g
            v-else
            @mouseenter="hovered = { n: p.n, x: p.x, y: p.y }"
            @mouseleave="hovered = null"
          >
            <circle :cx="p.x" :cy="p.y" :r="nodeRadius(p.n)" :fill="nodeColor(p.n)" :opacity="0.7" />
            <text
              :x="p.x"
              :y="p.y + nodeRadius(p.n) + 12"
              text-anchor="middle"
              fill="var(--t-dim)"
              font-size="11"
              font-family="inherit"
            >{{ p.n.label.length > 22 ? p.n.label.slice(0, 21) + '…' : p.n.label }}</text>
          </g>
        </template>

        <!-- hover tooltip (rendered last so it sits above nodes/edges) -->
        <g v-if="hovered" :transform="`translate(${Math.min(hovered.x + 14, W - 180)}, ${Math.max(hovered.y - 14, 8)})`" style="pointer-events:none">
          <rect :width="172" :height="16 + tooltipLines(hovered.n).length * 14" fill="var(--t-bg)" stroke="var(--t-line2)" rx="3" opacity="0.97" />
          <text
            v-for="(ln, i) in tooltipLines(hovered.n)"
            :key="i"
            :x="8" :y="18 + i * 14"
            :fill="i === 0 ? 'var(--t-text)' : 'var(--t-dim)'"
            font-size="11" font-family="inherit"
          >{{ ln.length > 26 ? ln.slice(0, 25) + '…' : ln }}</text>
        </g>
      </svg>
    </div>

    <!-- legend -->
    <div class="term-toolbar" style="display:flex;align-items:center;gap:18px;padding:6px 14px;border-top:1px solid var(--t-line);flex:none;font-size:11px;color:var(--t-faint)">
      <span><span style="color:var(--t-amber)">●</span> actor (size/colour = risk)</span>
      <span><span style="color:var(--t-accent)">●</span> source</span>
      <span><span style="color:var(--t-dim)">●</span> ip</span>
      <span><span style="color:var(--t-red)">—</span> failure edge</span>
      <span style="flex:1"></span>
      <span>click an actor → inspect</span>
    </div>
  </div>
</template>
