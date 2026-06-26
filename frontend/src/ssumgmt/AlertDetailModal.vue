<script setup lang="ts">
import type { Alert } from './api';
import type { TriageAction } from './useAlertsFeed';
import { formatDateTime, severityColor, sourceColor, relAge } from './format';

defineProps<{ alert: Alert }>();
const emit = defineEmits<{
  close: [];
  triage: [action: TriageAction];
}>();

function statusColorOf(status: string): string {
  return status === 'open' ? 'var(--t-amber)' : status === 'acked' ? 'var(--t-blue)' : 'var(--t-dim)';
}

function evidenceText(a: Alert): string {
  if (a.evidence == null) return '—';
  try {
    return JSON.stringify(a.evidence, null, 2);
  } catch {
    return String(a.evidence);
  }
}

// A triage action implicitly closes the modal (the row state changes underneath).
function triage(action: TriageAction): void {
  emit('triage', action);
  emit('close');
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
        <span :style="{ color: severityColor(alert.severity), fontWeight: 700, fontSize: '10.5px', letterSpacing: '.04em' }">{{ alert.severity.toUpperCase() }}</span>
        <span :style="{ color: sourceColor(alert.source) }">{{ alert.source }}</span>
        <span style="color:var(--t-text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ alert.title }}</span>
        <span style="flex:1"></span>
        <span :style="{ flex: 'none', fontSize: '10px', color: statusColorOf(alert.status) }">{{ alert.status }}</span>
        <button
          type="button"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer"
          @click="emit('close')"
        >[esc]</button>
      </div>
      <div style="overflow:auto;min-height:0">
        <div v-if="alert.description" style="padding:12px 16px;border-bottom:1px solid var(--t-line);color:var(--t-text);font-size:12px">{{ alert.description }}</div>
        <div style="padding:14px 16px;display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:12px">
          <span style="color:var(--t-faint)">rule</span><span style="color:var(--t-text)">{{ alert.rule_id }}</span>
          <span style="color:var(--t-faint)">actor</span>
          <span>
            <router-link
              v-if="alert.actor_id"
              :to="{ name: 'console-inspect', params: { id: alert.actor_id } }"
              style="color:var(--t-accent);text-decoration:none"
              @click="emit('close')"
            >{{ alert.actor_id }}</router-link>
            <span v-else style="color:var(--t-text)">—</span>
          </span>
          <span style="color:var(--t-faint)">events</span><span style="color:var(--t-text)">{{ alert.event_count }}</span>
          <span style="color:var(--t-faint)">first seen</span><span style="color:var(--t-text)">{{ formatDateTime(alert.first_seen) }}</span>
          <span style="color:var(--t-faint)">last seen</span><span style="color:var(--t-text)">{{ formatDateTime(alert.last_seen) }} · {{ relAge(alert.last_seen) }}</span>
          <template v-if="alert.acked_at">
            <span style="color:var(--t-faint)">acked</span><span style="color:var(--t-text)">{{ formatDateTime(alert.acked_at) }}<span v-if="alert.acked_by" style="color:var(--t-dim)"> · {{ alert.acked_by }}</span></span>
          </template>
          <template v-if="alert.resolved_at">
            <span style="color:var(--t-faint)">resolved</span><span style="color:var(--t-text)">{{ formatDateTime(alert.resolved_at) }}<span v-if="alert.resolved_by" style="color:var(--t-dim)"> · {{ alert.resolved_by }}</span></span>
          </template>
          <span style="color:var(--t-faint)">fingerprint</span><span style="color:var(--t-dim);word-break:break-all">{{ alert.fingerprint }}</span>
        </div>
        <div style="padding:0 16px 16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
            <span style="color:var(--t-faint);font-size:10.5px;letter-spacing:.06em">EVIDENCE</span>
            <span style="flex:1"></span>
            <button
              v-if="alert.status === 'open'"
              type="button"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 8px;cursor:pointer"
              @click="triage('ack')"
            >ack</button>
            <button
              v-if="alert.status === 'acked'"
              type="button"
              title="revert to open"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 8px;cursor:pointer"
              @click="triage('unack')"
            >unack</button>
            <button
              v-if="alert.status !== 'resolved'"
              type="button"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 8px;cursor:pointer"
              @click="triage('resolve')"
            >resolve</button>
            <button
              v-if="alert.status === 'resolved'"
              type="button"
              title="revert resolve"
              style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:10px;padding:2px 8px;cursor:pointer"
              @click="triage('unresolve')"
            >unresolve</button>
          </div>
          <pre style="margin:0;padding:12px;background:var(--t-inset);border:1px solid var(--t-line);overflow:auto;font-size:11.5px;color:var(--t-dim);white-space:pre-wrap;word-break:break-word">{{ evidenceText(alert) }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>
