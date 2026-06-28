<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { fetchCacheMeta, type CacheClass, type CacheClassMeta } from '../ssumgmt/api';
import { fmtCacheInterval } from '../ssumgmt/format';

const props = defineProps<{ kind: CacheClass }>();

const CLASS_LABEL: Record<CacheClass, string> = {
  siem: 'SIEM-derived',
  entity_stats: 'activity counts',
  identity_context: 'identity context',
  timeline: 'timeline rollup',
  guardduty: 'GuardDuty findings',
};

const meta = ref<CacheClassMeta | null>(null);
onMounted(async () => {
  try {
    const m = await fetchCacheMeta();
    meta.value = m.caches[props.kind] ?? null;
  } catch {
    meta.value = null;
  }
});

const lines = computed(() => {
  const out = [`Cached · ${CLASS_LABEL[props.kind]}`];
  if (meta.value) {
    out.push(`refreshed ~every ${fmtCacheInterval(meta.value.refresh_secs)}`);
    out.push(`may trail live by up to ~${fmtCacheInterval(meta.value.max_stale_secs)}`);
  } else {
    out.push('not a live figure');
  }
  return out;
});

const tip = ref<{ x: number; y: number } | null>(null);
function show(e: MouseEvent) {
  tip.value = { x: e.clientX, y: e.clientY };
}
function hide() {
  tip.value = null;
}
const tipStyle = computed(() => {
  const t = tip.value;
  if (!t) return {};
  return {
    position: 'fixed' as const,
    left: Math.max(8, Math.min(t.x + 12, window.innerWidth - 248)) + 'px',
    top: Math.max(8, Math.min(t.y + 14, window.innerHeight - 80)) + 'px',
    zIndex: 200,
    pointerEvents: 'none' as const,
    background: 'var(--t-node)',
    border: '1px solid var(--t-line2)',
    borderRadius: '3px',
    padding: '5px 9px',
    fontSize: '11px',
    lineHeight: 1.45,
    maxWidth: '240px',
    boxShadow: '0 4px 14px rgba(0,0,0,0.28)',
  };
});
</script>

<template>
  <span
    role="img"
    aria-label="cached value"
    style="
      display: inline-flex;
      align-items: center;
      vertical-align: middle;
      color: var(--t-faint);
      cursor: help;
      margin-left: 4px;
      user-select: none;
    "
    @mouseenter="show"
    @mousemove="show"
    @mouseleave="hide"
  >
    <svg
      width="1em"
      height="1em"
      viewBox="0 0 24 24"
      aria-hidden="true"
      style="display: block"
    >
      <path
        fill="currentColor"
        d="M9 8h2v6H9zm4-7H7v2h6zm4.03 6.39A8.96 8.96 0 0 1 19 13c0 4.97-4 9-9 9a9 9 0 0 1 0-18c2.12 0 4.07.74 5.62 2l1.42-1.44c.51.44.96.9 1.41 1.41zM17 13c0-3.87-3.13-7-7-7s-7 3.13-7 7s3.13 7 7 7s7-3.13 7-7m4-6v6h2V7zm0 10h2v-2h-2z"
      />
    </svg>
  </span>
  <Teleport to="body">
    <div v-if="tip" class="term" :style="tipStyle">
      <div
        v-for="(ln, i) in lines"
        :key="i"
        :style="{ color: i === 0 ? 'var(--t-text)' : 'var(--t-dim)' }"
      >
        {{ ln }}
      </div>
    </div>
  </Teleport>
</template>
