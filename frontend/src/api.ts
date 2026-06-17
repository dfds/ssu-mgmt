import { getAccessToken } from './auth/useAuth';

export class UnauthenticatedError extends Error {
  constructor(
    public kind: 'no-token' | 'rejected',
    message: string,
    public detail?: string,
  ) {
    super(message);
    this.name = 'UnauthenticatedError';
  }
}

// ForbiddenError is thrown when an endpoint returns 403 — the user is
// authenticated but lacks the required role (e.g. ce.cloudengineer).
export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = await getAccessToken();
  if (!token) {
    throw new UnauthenticatedError('no-token', 'session expired');
  }
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    let detail = '';
    try {
      const body = (await res.clone().json()) as { detail?: string };
      detail = body?.detail ?? '';
    } catch {
      /* response body not JSON — ignore */
    }
    throw new UnauthenticatedError(
      'rejected',
      detail ? `unauthenticated: ${detail}` : 'unauthenticated',
      detail || undefined,
    );
  }
  return res;
}

// ---------------------------------------------------------------------------
// Self-service audit log. Mirrors the audit_records_selfservice table; rows
// originate from the cloudengineering.selfservice.audit Kafka topic. Gated to
// ce.cloudengineer on the backend.
// ---------------------------------------------------------------------------

export interface AuditEntry {
  id: number;
  message_id: string;
  created_at: string;
  timestamp: string;
  type: string;
  principal: string;
  service: string;
  action: string;
  method: string;
  path: string;
  request_data?: unknown | null;
}

export interface AuditQueryResult {
  rows: AuditEntry[];
  total: number;
}

export type AuditRuleField =
  | 'principal'
  | 'service'
  | 'action'
  | 'method'
  | 'path'
  | 'type';

export type AuditRuleOp = 'contains' | 'not_contains' | 'equals' | 'not_equals';

export interface AuditRule {
  field: AuditRuleField;
  op: AuditRuleOp;
  value: string;
}

export interface AuditFilter {
  mode: 'rules' | 'query';
  rules: AuditRule[];
  match: 'all' | 'any';
  query?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export const PAGE_SIZE_DEFAULT = 50;

const AUDIT_RULE_FIELDS: ReadonlySet<AuditRuleField> = new Set<AuditRuleField>([
  'principal',
  'service',
  'action',
  'method',
  'path',
  'type',
]);

const AUDIT_RULE_OPS: ReadonlySet<AuditRuleOp> = new Set<AuditRuleOp>([
  'contains',
  'not_contains',
  'equals',
  'not_equals',
]);

export interface AuditFilterParamsOptions {
  omitDefaults?: boolean;
}

export function auditFilterToParams(
  filter: AuditFilter,
  opts: AuditFilterParamsOptions = {},
): URLSearchParams {
  const params = new URLSearchParams();
  // The backend only understands `rule=` params, never `q=`. AuditLogsView
  // calls switchToRules before submitting in query mode, so by the time we
  // reach this serializer filter.mode should be 'rules'. If it is not, drop
  // the query silently — better to fetch everything than 400.
  for (const r of filter.rules) {
    const value = r.value.trim();
    if (!value) continue;
    params.append('rule', `${r.field}:${r.op}:${value}`);
  }
  if (filter.match && filter.match !== 'all') params.set('match', filter.match);
  if (filter.from) params.set('from', filter.from);
  if (filter.to) params.set('to', filter.to);
  if (opts.omitDefaults) {
    if (filter.limit !== undefined && filter.limit !== PAGE_SIZE_DEFAULT) {
      params.set('limit', String(filter.limit));
    }
    if (filter.offset !== undefined && filter.offset !== 0) {
      params.set('offset', String(filter.offset));
    }
  } else {
    if (filter.limit !== undefined) params.set('limit', String(filter.limit));
    if (filter.offset !== undefined) params.set('offset', String(filter.offset));
  }
  return params;
}

function auditQueryString(filter: AuditFilter): string {
  const s = auditFilterToParams(filter).toString();
  return s ? `?${s}` : '';
}

// auditFilterFromParams reads a canonical URLSearchParams (the same shape
// auditFilterToParams emits) into a partial AuditFilter overlay. The caller
// merges this onto its defaults — keys absent from the URL stay at their
// default.
export function auditFilterFromParams(params: URLSearchParams): Partial<AuditFilter> {
  const overlay: Partial<AuditFilter> = {};

  const ruleStrings = params.getAll('rule');
  if (ruleStrings.length > 0) {
    const rules: AuditRule[] = [];
    for (const raw of ruleStrings) {
      const parts = raw.split(':');
      if (parts.length < 3) continue;
      const field = parts[0] as AuditRuleField;
      const op = parts[1] as AuditRuleOp;
      const value = parts.slice(2).join(':').trim();
      if (!AUDIT_RULE_FIELDS.has(field)) continue;
      if (!AUDIT_RULE_OPS.has(op)) continue;
      if (!value) continue;
      rules.push({ field, op, value });
    }
    if (rules.length > 0) {
      overlay.mode = 'rules';
      overlay.rules = rules;
      const match = params.get('match');
      overlay.match = match === 'any' ? 'any' : 'all';
      overlay.query = '';
    }
  }

  const from = params.get('from');
  if (from) overlay.from = from;
  const to = params.get('to');
  if (to) overlay.to = to;

  const limit = params.get('limit');
  if (limit) {
    const n = Number.parseInt(limit, 10);
    if (Number.isFinite(n) && n >= 0) overlay.limit = n;
  }
  const offset = params.get('offset');
  if (offset) {
    const n = Number.parseInt(offset, 10);
    if (Number.isFinite(n) && n >= 0) overlay.offset = n;
  }

  return overlay;
}

export async function fetchAuditLogs(filter: AuditFilter): Promise<AuditQueryResult> {
  const url = `/api/audit${auditQueryString(filter)}`;
  const res = await apiFetch(url);
  if (res.status === 403) {
    throw new ForbiddenError('You need the ce.cloudengineer role to view audit logs.');
  }
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  const data = (await res.json()) as Partial<AuditQueryResult>;
  return { rows: data.rows ?? [], total: data.total ?? 0 };
}

export async function fetchAuditLog(id: number): Promise<AuditEntry> {
  const url = `/api/audit/${id}`;
  const res = await apiFetch(url);
  if (res.status === 403) {
    throw new ForbiddenError('You need the ce.cloudengineer role to view audit logs.');
  }
  if (res.status === 404) throw new Error('Audit entry not found.');
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  return (await res.json()) as AuditEntry;
}

export function auditExportCsvUrl(filter: AuditFilter): string {
  return `/api/audit/export.csv${auditQueryString(filter)}`;
}
