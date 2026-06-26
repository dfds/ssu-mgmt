import type { ActorListRow } from './api';
import type { ConsoleColumn } from './tableColumns';

export const ACTOR_COLUMNS: ConsoleColumn<ActorListRow>[] = [
  { id: 'risk', header: 'RISK', kind: 'normalized', size: 56, accessor: (a) => a.score, format: 'risk', serverSortKey: 'risk', align: 'right', minSize: 48 },
  { id: 'bar', header: '', kind: 'normalized', size: 90, accessor: (a) => a.score, minSize: 70 },
  { id: 'actor', header: 'ACTOR', kind: 'normalized', size: 260, accessor: (a) => a.display_name ?? a.id, serverSortKey: 'name' },
  { id: 'kind', header: 'KIND', kind: 'normalized', size: 90, accessor: (a) => a.kind, format: 'text' },
  { id: 'origins', header: 'ORIGINS', kind: 'normalized', size: 180, accessor: (a) => (a.origins ?? []).filter(Boolean).join(', ') },
  { id: 'team', header: 'TEAM', kind: 'normalized', size: 150, accessor: (a) => a.team, format: 'text' },
  { id: 'sources', header: 'SOURCES', kind: 'normalized', size: 150, accessor: (a) => (a.sources ?? []).filter(Boolean).join(', ') },
  { id: 'active', header: 'ACTIVE', kind: 'normalized', size: 90, accessor: (a) => a.last_active, format: 'relage', serverSortKey: 'recent', align: 'right' },
];
