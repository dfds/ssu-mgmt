import type { Alert, Anomaly } from './api';
import type { ConsoleColumn } from './tableColumns';

export type FeedType = 'alert' | 'anomaly';

// Common row shape over Alert | Anomaly. `raw` keeps the original record so the
// slots and the detail modals can read type-specific fields without a re-fetch.
export interface FeedRow {
  type: FeedType;
  // Stable key — alert and anomaly id-spaces overlap, so qualify by type.
  key: string;
  id: number;
  severity: string;
  title: string;
  actor_id: string | null;
  // Sort/age timestamp: last_seen for alerts, event_time for anomalies.
  ts: string;
  alert?: Alert;
  anomaly?: Anomaly;
}

export function alertToFeedRow(a: Alert): FeedRow {
  return {
    type: 'alert',
    key: `alert:${a.id}`,
    id: a.id,
    severity: a.severity,
    title: a.title,
    actor_id: a.actor_id,
    ts: a.last_seen,
    alert: a,
  };
}

export function anomalyToFeedRow(an: Anomaly): FeedRow {
  return {
    type: 'anomaly',
    key: `anomaly:${an.id}`,
    id: an.id,
    severity: an.severity,
    title: an.title,
    actor_id: an.actor_id,
    ts: an.event_time,
    anomaly: an,
  };
}

// The `status` accessor doubles as the show/hide tooltip text: alerts surface
// their triage status, anomalies their detector kind (rendered dim in the slot).
export const FEED_COLUMNS: ConsoleColumn<FeedRow>[] = [
  { id: 'type', header: 'TYPE', kind: 'normalized', size: 70, accessor: (r) => r.type, minSize: 56 },
  { id: 'severity', header: 'SEVERITY', kind: 'normalized', size: 80, accessor: (r) => r.severity, format: 'severity', minSize: 64 },
  { id: 'title', header: 'SIGNAL', kind: 'normalized', size: 460, accessor: (r) => r.title },
  { id: 'status', header: 'STATUS', kind: 'normalized', size: 120, accessor: (r) => (r.type === 'alert' ? r.alert!.status : r.anomaly!.kind), align: 'right', minSize: 80 },
  { id: 'actions', header: '', kind: 'normalized', size: 150, accessor: () => '', align: 'right', minSize: 120 },
];
