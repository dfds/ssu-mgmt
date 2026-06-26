import type { SsuMgmtEvent } from './api';
import { type ConsoleColumn, rawPathAccessor } from './tableColumns';

// Normalized columns shown by default. `serverSortKey` is the OrderField.
const BASE: ConsoleColumn<SsuMgmtEvent>[] = [
  { id: 'source', header: 'SOURCE', kind: 'normalized', size: 90, accessor: (r) => r.source, format: 'source', serverSortKey: 'source' },
  { id: 'ts', header: 'TIME', kind: 'normalized', size: 150, accessor: (r) => r.ts, format: 'datetime', serverSortKey: 'ts' },
  { id: 'actor', header: 'ACTOR', kind: 'normalized', size: 190, accessor: (r) => r.actor, format: 'text', serverSortKey: 'actor' },
  { id: 'action', header: 'ACTION', kind: 'normalized', size: 200, accessor: (r) => r.action, format: 'text', serverSortKey: 'action' },
  { id: 'resource', header: 'RESOURCE', kind: 'normalized', size: 200, accessor: (r) => r.resource, format: 'text', serverSortKey: 'resource' },
  { id: 'ip', header: 'IP', kind: 'normalized', size: 120, accessor: (r) => r.source_ip, format: 'ip', serverSortKey: 'ip' },
  { id: 'status', header: 'STATUS', kind: 'normalized', size: 90, accessor: (r) => r.status, format: 'status', serverSortKey: 'status' },
];

// Optional normalized columns — server-sortable, hidden by default.
const OPTIONAL_NORMALIZED: ConsoleColumn<SsuMgmtEvent>[] = [
  { id: 'level', header: 'LEVEL', kind: 'normalized', size: 80, accessor: (r) => r.level, format: 'text', serverSortKey: 'level', defaultHidden: true },
  { id: 'role', header: 'ROLE', kind: 'normalized', size: 220, accessor: (r) => r.role, format: 'mono', serverSortKey: 'role', defaultHidden: true },
  { id: 'idsource', header: 'ID SRC', kind: 'normalized', size: 140, accessor: (r) => r.identity_source, format: 'text', serverSortKey: 'idsource', defaultHidden: true },
  { id: 'account', header: 'ACCOUNT', kind: 'normalized', size: 130, accessor: (r) => r.account_id, format: 'mono', serverSortKey: 'account', defaultHidden: true },
  { id: 'calleraccount', header: 'CALLER ACCT', kind: 'normalized', size: 130, accessor: (r) => r.caller_account_id, format: 'mono', serverSortKey: 'calleraccount', defaultHidden: true },
];

const RAW_DERIVED: { id: string; header: string; path: string; mono?: boolean }[] = [
  { id: 'raw:arn', header: 'ARN', path: 'userIdentity.arn', mono: true },
  { id: 'raw:identityType', header: 'IDENTITY TYPE', path: 'userIdentity.type' },
  { id: 'raw:userName', header: 'USERNAME', path: 'userIdentity.userName' },
  { id: 'raw:awsRegion', header: 'REGION', path: 'awsRegion' },
  { id: 'raw:userAgent', header: 'USER AGENT', path: 'userAgent' },
  { id: 'raw:errorCode', header: 'ERROR CODE', path: 'errorCode' },
];

const RAW_COLUMNS: ConsoleColumn<SsuMgmtEvent>[] = RAW_DERIVED.map((c) => ({
  id: c.id,
  header: c.header,
  kind: 'raw' as const,
  size: 200,
  accessor: rawPathAccessor<SsuMgmtEvent>(c.path),
  format: c.mono ? ('mono' as const) : ('text' as const),
  defaultHidden: true,
}));

// The full registry (custom columns are appended by the view).
export const QUERY_COLUMNS: ConsoleColumn<SsuMgmtEvent>[] = [
  ...BASE,
  ...OPTIONAL_NORMALIZED,
  ...RAW_COLUMNS,
];

export const ACTIVITY_COLUMNS: ConsoleColumn<SsuMgmtEvent>[] = QUERY_COLUMNS.map((c) => ({
  ...c,
  serverSortKey: undefined,
}));
