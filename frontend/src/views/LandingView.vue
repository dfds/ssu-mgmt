<script setup lang="ts">
import { computed } from 'vue';
import { RouterLink } from 'vue-router';
import TopBar from '../components/TopBar.vue';
import { useAuth } from '../auth/useAuth';

const { roles } = useAuth();
const canAdmin = computed(() => roles.value.includes('ce.cloudengineer'));
</script>

<template>
  <div class="min-h-screen">
    <TopBar title="SSU Management" />
    <main class="px-[2%] py-10">
      <div class="max-w-4xl mx-auto">
        <h1 class="text-xl font-semibold text-[var(--color-text-primary)] mb-1">
          Self-service universe
        </h1>
        <p class="text-sm text-[var(--color-text-secondary)] mb-6">
          Inspect the activity captured from the SSU audit topic.
        </p>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <component
            :is="canAdmin ? RouterLink : 'div'"
            :to="canAdmin ? { name: 'audit-logs' } : undefined"
            class="group block bg-[var(--color-surface)] border border-[var(--color-border-card)] rounded-[8px] shadow-[var(--shadow-card)] p-5 transition-colors"
            :class="canAdmin
              ? 'hover:border-[var(--color-action)]'
              : 'opacity-50 cursor-not-allowed'"
            :aria-disabled="canAdmin ? undefined : 'true'"
          >
            <div class="text-base font-semibold text-[var(--color-text-primary)] mb-1">
              Audit logs
            </div>
            <p class="text-sm text-[var(--color-text-secondary)]">
              Browse, filter and export self-service audit records ingested from
              the cloudengineering.selfservice.audit topic.
            </p>
            <span
              v-if="canAdmin"
              class="inline-block mt-3 text-[13px] text-[var(--color-action)] group-hover:underline"
            >View audit logs →</span>
            <span
              v-else
              class="inline-block mt-3 text-[13px] text-[var(--color-text-muted)]"
            >Requires the ce.cloudengineer role</span>
          </component>
        </div>
      </div>
    </main>
  </div>
</template>
