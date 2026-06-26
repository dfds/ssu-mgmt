<script setup lang="ts">
import type { Anomaly } from './api';
import { formatDateTime, severityColor, relAge } from './format';

const props = defineProps<{ anomaly: Anomaly }>();
const emit = defineEmits<{ close: [] }>();

function evidenceText(a: Anomaly): string {
  if (a.evidence == null) return '—';
  try {
    return JSON.stringify(a.evidence, null, 2);
  } catch {
    return String(a.evidence);
  }
}

function num(v: number | null): string {
  if (v == null) return '—';
  // Trim noisy float tails without lying about integers.
  return Number.isInteger(v) ? String(v) : v.toFixed(2);
}
</script>

<template>
  <div
    style="position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:24px"
    @click.self="emit('close')"
  >
    <div
      class="term"
      style="width:min(760px,100%);max-height:80vh;display:flex;flex-direction:column;background:var(--t-pane);border:1px solid var(--t-line2)"
    >
      <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--t-line);flex:none">
        <span :style="{ color: severityColor(props.anomaly.severity), fontWeight: 700, fontSize: '10.5px', letterSpacing: '.04em' }">{{ props.anomaly.severity.toUpperCase() }}</span>
        <span style="color:var(--t-blue)">anomaly</span>
        <span style="color:var(--t-text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ props.anomaly.title }}</span>
        <span style="flex:1"></span>
        <span style="flex:none;font-size:10px;color:var(--t-dim)">{{ props.anomaly.kind }}</span>
        <button
          type="button"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer"
          @click="emit('close')"
        >[esc]</button>
      </div>
      <div style="overflow:auto;min-height:0">
        <div v-if="props.anomaly.detail" style="padding:12px 16px;border-bottom:1px solid var(--t-line);color:var(--t-text);font-size:12px">{{ props.anomaly.detail }}</div>
        <div style="padding:14px 16px;display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:12px">
          <span style="color:var(--t-faint)">kind</span><span style="color:var(--t-text)">{{ props.anomaly.kind }}</span>
          <span style="color:var(--t-faint)">actor</span>
          <span>
            <router-link
              v-if="props.anomaly.actor_id"
              :to="{ name: 'console-inspect', params: { id: props.anomaly.actor_id } }"
              style="color:var(--t-accent);text-decoration:none"
              @click="emit('close')"
            >{{ props.anomaly.actor_id }}</router-link>
            <span v-else style="color:var(--t-text)">—</span>
          </span>
          <span style="color:var(--t-faint)">score</span><span style="color:var(--t-text)">{{ num(props.anomaly.score) }}</span>
          <span style="color:var(--t-faint)">baseline</span><span style="color:var(--t-text)">{{ num(props.anomaly.baseline) }}</span>
          <span style="color:var(--t-faint)">observed</span><span style="color:var(--t-text)">{{ num(props.anomaly.observed) }}</span>
          <span style="color:var(--t-faint)">event time</span><span style="color:var(--t-text)">{{ formatDateTime(props.anomaly.event_time) }} · {{ relAge(props.anomaly.event_time) }}</span>
          <span style="color:var(--t-faint)">detected</span><span style="color:var(--t-text)">{{ formatDateTime(props.anomaly.detected_at) }}</span>
          <span style="color:var(--t-faint)">fingerprint</span><span style="color:var(--t-dim);word-break:break-all">{{ props.anomaly.fingerprint }}</span>
        </div>
        <div style="padding:0 16px 16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
            <span style="color:var(--t-faint);font-size:10.5px;letter-spacing:.06em">EVIDENCE</span>
          </div>
          <pre style="margin:0;padding:12px;background:var(--t-inset);border:1px solid var(--t-line);overflow:auto;font-size:11.5px;color:var(--t-dim);white-space:pre-wrap;word-break:break-word">{{ evidenceText(props.anomaly) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>
