<script setup lang="ts">
defineProps<{
  title?: string;
  rowCountLabel?: string;
  error?: string | null;
}>();
</script>

<template>
  <section
    class="bg-[var(--color-surface)] border border-[var(--color-border-card)] rounded-[8px] shadow-[var(--shadow-card)] overflow-hidden"
  >
    <header
      class="flex items-center gap-3 px-4 py-2.5 border-b border-[var(--color-border-divider)] flex-wrap"
    >
      <h2
        v-if="title"
        class="text-base font-semibold text-[var(--color-text-primary)] m-0"
      >{{ title }}</h2>
      <span
        v-if="rowCountLabel"
        class="text-sm text-[var(--color-text-secondary)]"
      >{{ rowCountLabel }}</span>
      <span class="flex-1"></span>
      <slot name="actions" />
    </header>
    <div
      v-if="error"
      class="px-4 py-2 text-sm text-[var(--color-error)] border-b border-[var(--color-border-divider)] bg-[var(--color-surface-muted)]"
    >
      {{ error }}
    </div>
    <slot />
  </section>
</template>
