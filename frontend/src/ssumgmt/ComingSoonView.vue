<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';

const route = useRoute();
const title = computed(() => (route.meta.title as string | undefined) ?? 'this view');
</script>

<template>
  <div style="height:100%;background:var(--t-pane);display:flex;align-items:center;justify-content:center">
    <div style="text-align:center;max-width:420px;padding:24px">
      <div style="color:var(--t-accent);font-size:11px;letter-spacing:.1em;margin-bottom:10px">
        ▌ COMING UP
      </div>
      <div style="color:var(--t-text);font-size:15px;font-weight:600;margin-bottom:8px">
        {{ title }}
      </div>
      <div style="color:var(--t-dim);font-size:12px;line-height:1.6">
        This view lands with the SIEM derivation work (actors, risk, alerts,
        sessions, graph). Until then, the <strong>status</strong> and
        <strong>query</strong> tabs are live over the self-service audit source.
      </div>
    </div>
  </div>
</template>
