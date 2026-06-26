<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import type { RouteLocationRaw } from 'vue-router';
import {
  getCoreRowModel,
  useVueTable,
  type ColumnDef,
  type ColumnOrderState,
  type ColumnSizingState,
  type Updater,
  type VisibilityState,
} from '@tanstack/vue-table';
import type { ConsoleColumn, CellFormat } from '../ssumgmt/tableColumns';
import { displayValue } from '../ssumgmt/tableColumns';
import { useColumnVisibility } from '../composables/useColumnVisibility';
import { useColumnSizing } from '../composables/useColumnSizing';
import { useColumnOrder } from '../composables/useColumnOrder';
import { useOverlayScrollbars } from 'overlayscrollbars-vue';
import 'overlayscrollbars/overlayscrollbars.css';
import {
  formatDateTime,
  formatTime,
  relAge,
  sourceColor,
  statusColor,
  riskColor,
  severityColor,
} from '../ssumgmt/format';

const props = withDefaults(
  defineProps<{
    columns: ConsoleColumn[];
    rows: any[];
    rowKey: (row: any) => string;
    storageKey: string;
    // Current server-side sort, for the sort-arrow indicator. Only columns whose
    // `serverSortKey` matches `serverSort.key` show an arrow.
    serverSort?: { key: string; dir: 'asc' | 'desc' } | null;
    // Show the "+ column" add-custom UI in the columns menu.
    enableCustomColumns?: boolean;
    // Add a custom column. Returns an error string (shown inline) or null on
    // success. Supplied by the host (wraps useCustomColumns.addColumn).
    onAddCustom?: (label: string, path: string) => string | null;
    // Remove a custom column by id.
    onRemoveCustom?: (id: string) => void;
    rowLink?: (row: any) => RouteLocationRaw | null | undefined;
    emptyText?: string;
    loading?: boolean;
  }>(),
  { enableCustomColumns: false, emptyText: 'no rows', loading: false },
);
const emit = defineEmits<{
  (e: 'row-click', row: any): void;
  (e: 'server-sort', key: string): void;
}>();

const tableColumns: ColumnDef<any, unknown>[] = props.columns.map((c) => ({
  id: c.id,
  header: c.header,
  accessorFn: c.accessor,
  size: c.size,
  ...(c.minSize ? { minSize: c.minSize } : {}),
}));

const columnIds: string[] = props.columns.map((c) => c.id);
const byId = new Map<string, ConsoleColumn>(props.columns.map((c) => [c.id, c]));
const formatById: Record<string, CellFormat> = {};
for (const c of props.columns) formatById[c.id] = c.format ?? 'text';

const defaultHidden = props.columns.filter((c) => c.defaultHidden).map((c) => c.id);
const { visibility, setVisibility, setColumn, showAll, hideAll } = useColumnVisibility(
  columnIds,
  props.storageKey,
  defaultHidden,
);
const visibleCount = computed(() => columnIds.filter((id) => visibility.value[id] !== false).length);

const { sizing: columnSizing, hasStored: hasStoredSizing, setSizing, clear: clearSizing } =
  useColumnSizing(columnIds, props.storageKey);
const { order: columnOrder, move: moveColumn, setOrder, clear: clearOrder } =
  useColumnOrder(columnIds, props.storageKey);
const tableContainerRef = ref<HTMLDivElement | null>(null);
// True once the layout is user-owned (a manual resize this session, or a
// restored one); gates the viewport-driven auto-fit.
let userResized = hasStoredSizing;

const [initOverlayScrollbars, getOverlayScrollbars] = useOverlayScrollbars({
  options: {
    scrollbars: { autoHide: 'never', theme: 'os-theme-term', clickScroll: true },
  },
  defer: false,
});

const columnsMenuOpen = ref(false);
const columnsMenuRef = ref<HTMLDivElement | null>(null);

// Drag-to-reorder state. `draggingId` is the grabbed column; `dragOverId` is the
// header currently under the cursor (drives the drop-indicator border).
const draggingId = ref<string | null>(null);
const dragOverId = ref<string | null>(null);

function onColDragStart(id: string, event: DragEvent): void {
  draggingId.value = id;
  if (event.dataTransfer) {
    event.dataTransfer.effectAllowed = 'move';
    // Firefox needs data set for a drag to start.
    event.dataTransfer.setData('text/plain', id);
  }
}
function onColDragOver(id: string): void {
  if (draggingId.value && draggingId.value !== id) dragOverId.value = id;
}
function onColDrop(id: string): void {
  if (draggingId.value) moveColumn(draggingId.value, id);
  draggingId.value = null;
  dragOverId.value = null;
}
function onColDragEnd(): void {
  draggingId.value = null;
  dragOverId.value = null;
}

// add-custom form
const newLabel = ref('');
const newPath = ref('');
const addError = ref<string | null>(null);

function submitCustom(): void {
  if (!props.onAddCustom) return;
  const err = props.onAddCustom(newLabel.value, newPath.value);
  if (err) {
    addError.value = err;
    return;
  }
  newLabel.value = '';
  newPath.value = '';
  addError.value = null;
}

function applyUpdater<T>(current: T, updater: Updater<T>): T {
  return typeof updater === 'function' ? (updater as (old: T) => T)(current) : updater;
}

function fitColumnsToContainer(): void {
  if (!tableContainerRef.value) return;
  const available = tableContainerRef.value.clientWidth;
  if (available <= 0) return;
  const accessors = tableColumns
    .map((c) => {
      const id = (c as { id?: string }).id ?? '';
      return { id, size: columnSizing.value[id] ?? (c as { size?: number }).size ?? 150 };
    })
    .filter((c) => c.id && visibility.value[c.id] !== false);
  const totalWeight = accessors.reduce((s, c) => s + c.size, 0);
  if (totalWeight <= 0) return;
  const sizing: ColumnSizingState = { ...columnSizing.value };
  for (const c of accessors) {
    const min = byId.get(c.id)?.minSize ?? 60;
    sizing[c.id] = Math.max(min, Math.floor((c.size / totalWeight) * available));
  }
  columnSizing.value = sizing;
}

function resetView(): void {
  clearSizing();
  clearOrder();
  userResized = false;
  fitColumnsToContainer();
}

let resizeObserver: ResizeObserver | null = null;

function onDocumentMousedown(event: MouseEvent): void {
  if (!columnsMenuOpen.value) return;
  const root = columnsMenuRef.value;
  if (root && event.target instanceof Node && root.contains(event.target)) return;
  columnsMenuOpen.value = false;
}

function onDocumentKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape' && columnsMenuOpen.value) columnsMenuOpen.value = false;
}

watch(
  visibility,
  () => {
    if (!userResized) fitColumnsToContainer();
  },
  { deep: true },
);

onMounted(() => {
  if (tableContainerRef.value) initOverlayScrollbars(tableContainerRef.value);
  if (!userResized) fitColumnsToContainer();
  resizeObserver = new ResizeObserver(() => {
    if (!userResized) fitColumnsToContainer();
  });
  if (tableContainerRef.value) resizeObserver.observe(tableContainerRef.value);
  document.addEventListener('mousedown', onDocumentMousedown);
  document.addEventListener('keydown', onDocumentKeydown);
});

onUnmounted(() => {
  getOverlayScrollbars()?.destroy();
  resizeObserver?.disconnect();
  resizeObserver = null;
  document.removeEventListener('mousedown', onDocumentMousedown);
  document.removeEventListener('keydown', onDocumentKeydown);
});

const table = useVueTable({
  get data() {
    return props.rows;
  },
  columns: tableColumns,
  state: {
    get columnSizing() {
      return columnSizing.value;
    },
    get columnVisibility() {
      return visibility.value;
    },
    get columnOrder() {
      return columnOrder.value;
    },
  },
  onColumnSizingChange: (updater) => {
    setSizing(applyUpdater(columnSizing.value, updater));
    userResized = true;
  },
  onColumnVisibilityChange: (updater) => {
    const next = applyUpdater<VisibilityState>(visibility.value, updater);
    setVisibility(next);
  },
  onColumnOrderChange: (updater) => {
    setOrder(applyUpdater<ColumnOrderState>(columnOrder.value, updater));
  },
  enableColumnResizing: true,
  columnResizeMode: 'onChange',
  defaultColumn: { minSize: 60, maxSize: 1000 },
  getRowId: (row) => props.rowKey(row),
  getCoreRowModel: getCoreRowModel(),
});

// Sort affordance helpers (server-driven). A column sorts only if it carries a
// serverSortKey; the arrow reflects the host's current serverSort.
function sortKeyOf(id: string): string | undefined {
  return byId.get(id)?.serverSortKey;
}
function sortArrow(id: string): string {
  const key = sortKeyOf(id);
  if (!key || !props.serverSort || props.serverSort.key !== key) return '';
  return props.serverSort.dir === 'asc' ? ' ▲' : ' ▼';
}
function isSortedCol(id: string): boolean {
  const key = sortKeyOf(id);
  return !!key && !!props.serverSort && props.serverSort.key === key;
}
function onHeaderClick(id: string): void {
  const key = sortKeyOf(id);
  if (key) emit('server-sort', key);
}

// Default cell text for a (format, value) pair. Views override rich cells via a
// `#cell-<id>` slot; this is the fallback for scalar columns.
function cellText(format: CellFormat, value: unknown): string {
  if (value == null || value === '') {
    if (format === 'datetime' || format === 'time' || format === 'relage') return '—';
    return '—';
  }
  switch (format) {
    case 'datetime':
      return formatDateTime(String(value));
    case 'time':
      return formatTime(String(value));
    case 'relage':
      return relAge(String(value));
    case 'severity':
      return String(value).toUpperCase();
    default:
      return displayValue(value);
  }
}

// Inline colour for coloured formats; undefined → inherit.
function cellColor(format: CellFormat, value: unknown): string | undefined {
  if (value == null || value === '') return 'var(--t-faint)';
  switch (format) {
    case 'source':
      return sourceColor(String(value));
    case 'status':
      return statusColor(String(value));
    case 'risk':
      return riskColor(Number(value) || 0);
    case 'severity':
      return severityColor(String(value));
    case 'datetime':
    case 'time':
    case 'relage':
    case 'ip':
      return 'var(--t-dim)';
    default:
      return 'var(--t-text)';
  }
}

const hasRows = computed(() => table.getRowModel().rows.length > 0);

// Row-as-link target (null ⇒ not navigable). The overlay anchor is hosted in the
// first visible cell; see `.ct-rowlink` + the per-cell style override below.
function rowTo(row: unknown): RouteLocationRaw | null {
  if (!props.rowLink) return null;
  return props.rowLink(row) ?? null;
}
</script>

<template>
  <div style="display:flex;flex-direction:column;min-height:0;min-width:0;height:100%;width:100%">
    <!-- toolbar: columns menu -->
    <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:5px 14px;border-bottom:1px solid var(--t-line);flex:none">
      <div ref="columnsMenuRef" style="position:relative">
        <button
          type="button"
          :aria-expanded="columnsMenuOpen"
          style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 9px;cursor:pointer"
          @click="columnsMenuOpen = !columnsMenuOpen"
        >
          columns ({{ visibleCount }}/{{ columnIds.length }}) <span style="color:var(--t-faint)">▾</span>
        </button>
        <div
          v-if="columnsMenuOpen"
          style="position:absolute;right:0;top:calc(100% + 4px);z-index:30;width:280px;background:var(--t-pane);border:1px solid var(--t-line2);box-shadow:0 8px 16px rgba(0,0,0,.25)"
          role="menu"
        >
          <div style="display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-bottom:1px solid var(--t-line)">
            <span style="color:var(--t-faint);font-size:10px;letter-spacing:.08em;text-transform:uppercase">visible columns</span>
            <span style="display:flex;gap:10px">
              <button type="button" style="background:none;border:none;color:var(--t-accent);font-family:inherit;font-size:10.5px;cursor:pointer;padding:0" @click="showAll">show all</button>
              <button type="button" style="background:none;border:none;color:var(--t-accent);font-family:inherit;font-size:10.5px;cursor:pointer;padding:0" @click="hideAll">hide all</button>
            </span>
          </div>
          <div style="max-height:48vh;overflow:auto;padding:4px 0">
            <div
              v-for="col in props.columns"
              :key="col.id"
              class="ct-menu-row"
              style="display:flex;align-items:center;gap:8px;padding:3px 10px;font-size:12px"
            >
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;flex:1;min-width:0">
                <input
                  type="checkbox"
                  :checked="visibility[col.id] !== false"
                  style="cursor:pointer;accent-color:var(--t-accent)"
                  @change="setColumn(col.id, ($event.target as HTMLInputElement).checked)"
                />
                <span style="color:var(--t-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ col.header || col.id }}</span>
                <span v-if="col.kind === 'custom'" style="color:var(--t-faint);font-size:10px">{{ col.path }}</span>
              </label>
              <button
                v-if="col.removable && props.onRemoveCustom"
                type="button"
                title="remove column"
                style="background:none;border:none;color:var(--t-faint);font-family:inherit;font-size:12px;cursor:pointer;padding:0 2px;flex:none"
                @click="props.onRemoveCustom(col.id)"
              >×</button>
            </div>
          </div>
          <!-- add custom column -->
          <div v-if="enableCustomColumns && props.onAddCustom" style="border-top:1px solid var(--t-line);padding:8px 10px">
            <div style="color:var(--t-faint);font-size:10px;letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px">add column</div>
            <form style="display:flex;flex-direction:column;gap:5px" @submit.prevent="submitCustom">
              <input
                v-model="newLabel"
                spellcheck="false"
                placeholder="label (optional)"
                style="background:var(--t-inset);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:11px;padding:3px 6px;outline:none"
              />
              <input
                v-model="newPath"
                spellcheck="false"
                placeholder="path e.g. userIdentity.arn"
                style="background:var(--t-inset);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:11px;padding:3px 6px;outline:none"
                @input="addError = null"
              />
              <div style="display:flex;align-items:center;gap:8px">
                <button type="submit" style="background:none;border:1px solid var(--t-accent-line);color:var(--t-accent);font-family:inherit;font-size:11px;padding:2px 10px;cursor:pointer">add</button>
                <span v-if="addError" style="color:var(--t-amber);font-size:10.5px">{{ addError }}</span>
              </div>
            </form>
          </div>
        </div>
      </div>
      <button
        type="button"
        title="reset column widths"
        style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 9px;cursor:pointer"
        @click="resetView"
      >reset</button>
    </div>

    <!-- table -->
    <div ref="tableContainerRef" style="overflow:auto;min-height:0;min-width:0;flex:1">
      <div class="ct-scroll-content">
      <table :style="{ width: '100%', minWidth: table.getTotalSize() + 'px', tableLayout: 'fixed', borderCollapse: 'separate', borderSpacing: '0', fontSize: '12px' }">
        <thead style="position:sticky;top:0;z-index:1">
          <tr>
            <th
              v-for="(header, hIdx) in table.getHeaderGroups()[0].headers"
              :key="header.id"
              :class="{
                'ct-th-dragover': dragOverId === header.column.id,
                'ct-th-dragging': draggingId === header.column.id,
              }"
              :style="{ width: header.getSize() + 'px', textAlign: byId.get(header.column.id)?.align === 'right' ? 'right' : 'left' }"
              style="position:relative;background:var(--t-pane);box-shadow:inset 0 -1px 0 var(--t-line);padding:6px 14px;font-weight:500;font-size:10.5px;letter-spacing:.06em;color:var(--t-faint);user-select:none;white-space:nowrap;text-transform:uppercase"
              @dragover.prevent="onColDragOver(header.column.id)"
              @drop.prevent="onColDrop(header.column.id)"
            >
              <span
                class="ct-th-label"
                :class="{ 'ct-sortable': !!sortKeyOf(header.column.id) }"
                :style="{ cursor: sortKeyOf(header.column.id) ? 'pointer' : 'grab', color: isSortedCol(header.column.id) ? 'var(--t-accent)' : undefined }"
                draggable="true"
                title="drag to reorder"
                @dragstart="onColDragStart(header.column.id, $event)"
                @dragend="onColDragEnd"
                @click="onHeaderClick(header.column.id)"
              >{{ header.column.columnDef.header }}{{ sortArrow(header.column.id) }}</span>
              <div
                class="ct-resize"
                :class="{
                  'ct-resize-active': header.column.getIsResizing(),
                  'ct-resize-edge': hIdx === table.getHeaderGroups()[0].headers.length - 1,
                }"
                @mousedown="header.getResizeHandler()?.($event)"
                @touchstart="header.getResizeHandler()?.($event)"
                @click.stop
              ></div>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in table.getRowModel().rows"
            :key="row.id"
            class="ct-row"
            :style="{ cursor: 'pointer', position: rowTo(row.original) ? 'relative' : undefined }"
            @click="emit('row-click', row.original)"
          >
            <td
              v-for="(cell, ci) in row.getVisibleCells()"
              :key="cell.id"
              :title="cellText(formatById[cell.column.id], cell.getValue())"
              :style="{
                textAlign: byId.get(cell.column.id)?.align === 'right' ? 'right' : 'left',
                color: cellColor(formatById[cell.column.id], cell.getValue()),
                ...(ci === 0 && rowTo(row.original) ? { position: 'static', overflow: 'visible' } : {}),
              }"
              style="padding:5px 14px;border-top:1px solid var(--t-line);overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
              :class="{ 'ct-mono': formatById[cell.column.id] === 'mono' }"
            >
              <RouterLink
                v-if="ci === 0 && rowTo(row.original)"
                :to="rowTo(row.original)!"
                class="ct-rowlink"
                aria-label="open"
                @click.stop
              />
              <slot :name="`cell-${cell.column.id}`" :row="row.original" :value="cell.getValue()">
                {{ cellText(formatById[cell.column.id], cell.getValue()) }}
              </slot>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="loading" style="padding:30px;text-align:center;color:var(--t-faint)">loading…</div>
      <div v-else-if="!hasRows" style="padding:30px;text-align:center;color:var(--t-faint)">{{ emptyText }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ct-sortable:hover {
  color: var(--t-text) !important;
}
.ct-row:hover {
  background: var(--t-inset);
}
.ct-mono {
  font-family: "JetBrains Mono", ui-monospace, monospace;
}
.ct-menu-row:hover {
  background: var(--t-inset);
}
.ct-th-label {
  display: inline-block;
}
.ct-th-label:active {
  cursor: grabbing;
}
/* dim the grabbed header while a reorder drag is in flight */
.ct-th-dragging {
  opacity: 0.45;
}
/* drop indicator: an accent rule on the header under the cursor */
.ct-th-dragover {
  box-shadow: inset 2px 0 0 var(--t-accent), inset 0 -1px 0 var(--t-line) !important;
}
.ct-resize {
  position: absolute;
  right: 0;
  top: 0;
  height: 100%;
  width: 9px;
  cursor: col-resize;
  user-select: none;
  touch-action: none;
}
.ct-resize::before {
  content: "";
  position: absolute;
  right: 0;
  top: 0;
  height: 100%;
  width: 2px;
  background: transparent;
}
.ct-resize:hover::before {
  background: var(--t-accent-line);
}
.ct-resize-active::before {
  background: var(--t-accent);
}
.ct-resize-edge {
  width: 22px;
}
.ct-rowlink {
  position: absolute;
  inset: 0;
  z-index: 1;
  /* transparent overlay — the cells render the visible content beneath it */
  display: block;
}
</style>
