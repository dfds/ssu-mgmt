import { apiFetch, ForbiddenError } from '../api';

// ---------------------------------------------------------------------------
// DTOs — mirror the backend SsuMgmtEvent / QueryResponse / TimelineResponse.
// ---------------------------------------------------------------------------

export interface SsuMgmtEvent {
  source: string;
  uid: string;
  ts: string;
  actor: string | null;
  action: string;
  resource: string | null;
  source_ip: string | null;
  level: string;
  status: string;
  raw: unknown | null;
  role: string | null;
  identity_source: string | null;
  account_id: string | null;
  caller_account_id: string | null;
}

export interface QueryResult {
  rows: SsuMgmtEvent[];
  total: number;
  total_capped?: boolean;
}

export interface TimelineBucket {
  bucket: string;
  source: string;
  count: number;
}

export interface TimelineResult {
  bucket: string;
  from: string;
  to: string;
  rows: TimelineBucket[];
}

// ---------------------------------------------------------------------------
// Query rules. The Query view supports the union-view dimensions; `ip` maps to
// the backend `source_ip` column.
// ---------------------------------------------------------------------------

export type EventField =
  | 'actor'
  | 'source'
  | 'action'
  | 'resource'
  | 'ip'
  | 'status'
  | 'level'
  | 'uid'
  | 'role'
  | 'idsource'
  | 'account'
  | 'calleraccount';

export const EVENT_FIELDS: readonly EventField[] = [
  'actor',
  'source',
  'action',
  'resource',
  'ip',
  'status',
  'level',
  'uid',
  'role',
  'idsource',
  'account',
  'calleraccount',
];

const FIELD_SET: ReadonlySet<string> = new Set(EVENT_FIELDS);

// Columns the result set can be ordered by: the normalized fields plus `ts`.
export type OrderField = EventField | 'ts';
export type OrderDir = 'asc' | 'desc';
export interface QueryOrder {
  field: OrderField;
  dir: OrderDir;
}
const ORDERABLE: ReadonlySet<string> = new Set<string>([...EVENT_FIELDS, 'ts']);

// ---------------------------------------------------------------------------
// Query AST — mirrors the backend `query_ast::Node` serde enum (tagged on
// `kind`). The query *text* is parsed here into this tree and sent to the
// backend as a single URL-encoded JSON `ast=` param; the server walks the
// typed tree (it never parses a query string).
// ---------------------------------------------------------------------------

export type BoolOp = 'and' | 'or';
export type AstOp = 'eq' | 'ne' | 'contains' | 'not_contains' | 'gt' | 'gte' | 'lt' | 'lte';
export type ValueType = 'text' | 'number';

export type QueryNode =
  | { kind: 'group'; op: BoolOp; children: QueryNode[] }
  | { kind: 'not'; child: QueryNode }
  | { kind: 'field'; field: EventField; op: AstOp; value: string }
  | { kind: 'ts'; op: AstOp; value: string }
  | { kind: 'json_path'; path: string[]; op: AstOp; value: string; value_type: ValueType }
  | { kind: 'raw'; value: string };

export interface FieldHelp {
  field: EventField;
  values?: readonly string[];
}

const FIELD_VALUES: Partial<Record<EventField, readonly string[]>> = {
  source: ['selfservice', 'cloudtrail', 'github', 'ssu-mgmt'],
  status: ['success', 'failure'],
};

export const QUERY_FIELD_HELP: readonly FieldHelp[] = EVENT_FIELDS.map((field) => ({
  field,
  values: FIELD_VALUES[field],
}));

// Example queries surfaced in the syntax help; clicking one fills + runs.
export const QUERY_EXAMPLES: readonly string[] = [
  'source=cloudtrail action:Console status=failure',
  '(source=cloudtrail -action:AssumeRole) AND (source=selfservice actor:john)',
  'actor:"john doe" OR idsource~oidc',
  'json.requestParameters.maxSessionDuration >= 1500',
  'json.responseElements.tags["dfds.cost.centre"] = "ti-cae"',
  'ts >= 2026-06-20 raw:ConsoleLogin',
  'source=cloudtrail status=failure order by actor asc',
  'source=cloudtrail account=123456789012',
];

export interface ParsedQuery {
  ast: QueryNode;
  errors: string[];
  // A trailing `order by <field> [asc|desc]` clause, lifted out of the text.
  order?: QueryOrder;
}

const EMPTY_AST: QueryNode = { kind: 'group', op: 'and', children: [] };

export function isEmptyAst(n: QueryNode | undefined): boolean {
  return !n || (n.kind === 'group' && n.children.length === 0);
}

// parseQuery turns the query text into a QueryNode tree. Grammar:
//   term      := [-|NOT] (group | predicate)
//   group     := '(' or ')'
//   or        := and (OR and)*
//   and       := term (AND? term)*        // bare space = implicit AND
//   predicate := lhs OP value             // OP glued or space-separated
// OP ∈ ':' '~' (substring) · '=' '!=' (exact) · '!~' (not-substring) ·
//      '>' '>=' '<' '<=' (compare, JSON paths + ts only).
// `raw:term` searches the raw payload; bare words (no field/op) are errors.
export function parseQuery(text: string): ParsedQuery {
  const errors: string[] = [];
  const { body, order } = extractOrder(text, errors);
  const toks = lex(body);
  if (toks.length === 0) return { ast: EMPTY_AST, errors, order };
  const p = new Parser(toks, errors);
  const node = p.parseOr();
  if (p.pos < toks.length) errors.push(`unexpected "${tokText(toks[p.pos])}"`);
  return { ast: node ?? EMPTY_AST, errors, order };
}

function extractOrder(text: string, errors: string[]): { body: string; order?: QueryOrder } {
  const m = text.match(/(?:^|\s)order\s+by\s+([a-z_]+)(?:\s+(asc|desc))?\s*$/i);
  if (!m) return { body: text };
  const field = m[1].toLowerCase();
  const body = text.slice(0, m.index);
  if (!ORDERABLE.has(field)) {
    errors.push(`cannot order by "${field}"`);
    return { body };
  }
  const dir: OrderDir = (m[2]?.toLowerCase() as OrderDir) ?? (field === 'ts' ? 'desc' : 'asc');
  return { body, order: { field: field as OrderField, dir } };
}

// --- lexer -----------------------------------------------------------------
type Tok = { kind: 'lparen' } | { kind: 'rparen' } | { kind: 'atom'; text: string };

function tokText(t: Tok): string {
  return t.kind === 'atom' ? t.text : t.kind === 'lparen' ? '(' : ')';
}

function lex(text: string): Tok[] {
  const out: Tok[] = [];
  let cur = '';
  let quote = false;
  let depth = 0; // bracket depth
  const flush = () => {
    if (cur) out.push({ kind: 'atom', text: cur });
    cur = '';
  };
  for (const c of text) {
    if (quote) {
      cur += c;
      if (c === '"') quote = false;
      continue;
    }
    if (c === '"') {
      quote = true;
      cur += c;
    } else if (c === '[') {
      depth++;
      cur += c;
    } else if (c === ']') {
      if (depth > 0) depth--;
      cur += c;
    } else if (depth === 0 && /\s/.test(c)) {
      flush();
    } else if (depth === 0 && c === '(') {
      flush();
      out.push({ kind: 'lparen' });
    } else if (depth === 0 && c === ')') {
      flush();
      out.push({ kind: 'rparen' });
    } else {
      cur += c;
    }
  }
  flush();
  return out;
}

// Operator spellings, longest-first so `>=` beats `>`.
const OPS: readonly string[] = ['>=', '<=', '!=', '!~', '>', '<', '=', '~', ':'];

function keywordOf(t: Tok): 'and' | 'or' | 'not' | null {
  if (t.kind !== 'atom') return null;
  const u = t.text.toUpperCase();
  return u === 'AND' ? 'and' : u === 'OR' ? 'or' : u === 'NOT' ? 'not' : null;
}

function isPureOp(t: Tok): boolean {
  return t.kind === 'atom' && OPS.includes(t.text);
}

class Parser {
  pos = 0;
  constructor(private toks: Tok[], private errors: string[]) {}

  private peek(): Tok | undefined {
    return this.toks[this.pos];
  }
  private next(): Tok | undefined {
    return this.toks[this.pos++];
  }

  parseOr(): QueryNode | null {
    const children: QueryNode[] = [];
    const first = this.parseAnd();
    if (first) children.push(first);
    while (this.peek() && keywordOf(this.peek()!) === 'or') {
      this.next();
      const n = this.parseAnd();
      if (n) children.push(n);
    }
    if (children.length === 0) return null;
    return children.length === 1 ? children[0] : { kind: 'group', op: 'or', children };
  }

  private parseAnd(): QueryNode | null {
    const children: QueryNode[] = [];
    const first = this.parseUnary();
    if (first) children.push(first);
    for (;;) {
      const t = this.peek();
      if (!t || t.kind === 'rparen') break;
      if (keywordOf(t) === 'or') break;
      if (keywordOf(t) === 'and') this.next(); // explicit AND
      const n = this.parseUnary();
      if (n) children.push(n);
      else if (!this.peek()) break;
    }
    if (children.length === 0) return null;
    return children.length === 1 ? children[0] : { kind: 'group', op: 'and', children };
  }

  private parseUnary(): QueryNode | null {
    const t = this.peek();
    if (!t) return null;
    if (keywordOf(t) === 'not') {
      this.next();
      const child = this.parseUnary();
      return child ? { kind: 'not', child } : null;
    }
    if (t.kind === 'atom' && t.text === '-') {
      this.next();
      const child = this.parseUnary();
      return child ? { kind: 'not', child } : null;
    }
    return this.parsePrimary();
  }

  private parsePrimary(): QueryNode | null {
    const t = this.peek();
    if (!t) return null;
    if (t.kind === 'lparen') {
      this.next();
      const inner = this.parseOr();
      if (this.peek()?.kind === 'rparen') this.next();
      else this.errors.push('missing closing )');
      return inner;
    }
    if (t.kind === 'rparen') {
      this.next();
      this.errors.push('unexpected )');
      return null;
    }
    return this.parsePredicate();
  }

  // Consumes either one glued atom (`actor:alice`) or three space-separated
  // atoms (`ts >= 2026-06-20`) and returns the predicate node.
  private parsePredicate(): QueryNode | null {
    const atom = this.next();
    if (!atom || atom.kind !== 'atom') return null;
    let text = atom.text;
    let negate = false;
    if (text.startsWith('-') && text.length > 1) {
      negate = true;
      text = text.slice(1);
    }

    let lhs: string;
    let opStr: string;
    let value: string;

    const found = findOp(text);
    if (found) {
      lhs = text.slice(0, found.index);
      opStr = found.op;
      value = text.slice(found.index + found.op.length);
      if (value === '') {
        // glued trailing op → value is the next atom: `field= value`
        const nv = this.peek();
        if (nv && nv.kind === 'atom' && !isPureOp(nv) && !keywordOf(nv)) {
          value = (this.next() as { text: string }).text;
        }
      }
    } else {
      // bare lhs; look for a space-separated operator + value
      const opTok = this.peek();
      if (opTok && isPureOp(opTok)) {
        this.next();
        opStr = (opTok as { text: string }).text;
        const vTok = this.peek();
        if (vTok && vTok.kind === 'atom' && !keywordOf(vTok)) {
          value = (this.next() as { text: string }).text;
        } else {
          this.errors.push(`missing value after "${text} ${opStr}"`);
          return null;
        }
        lhs = text;
      } else {
        this.errors.push(`bare term "${text}" — use field:value, json.path, ts, or raw:`);
        return null;
      }
    }

    lhs = lhs.trim();
    value = stripQuotes(value.trim());
    if (!lhs) {
      this.errors.push(`missing field before "${opStr}"`);
      return null;
    }
    if (!value) {
      this.errors.push(`empty value for "${lhs}"`);
      return null;
    }

    const node = buildPredicate(lhs, opStr, value, this.errors);
    if (!node) return null;
    return negate ? negateNode(node) : node;
  }
}

// Find the earliest operator occurrence in a glued atom (longest match wins at
// each position). Returns null if the atom has no operator.
function findOp(s: string): { index: number; op: string } | null {
  for (let i = 0; i < s.length; i++) {
    for (const op of OPS) {
      if (s.startsWith(op, i)) return { index: i, op };
    }
  }
  return null;
}

export function stripQuotes(v: string): string {
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1);
  return v;
}

const SUBSTRING_OPS = new Set([':', '~']);
const COMPARE_OPS = new Set(['>', '>=', '<', '<=']);

// Map an operator string to its base AstOp (before any leading-`-`/NOT negation).
function baseOp(op: string): AstOp | null {
  switch (op) {
    case ':':
    case '~':
      return 'contains';
    case '=':
      return 'eq';
    case '!=':
      return 'ne';
    case '!~':
      return 'not_contains';
    case '>':
      return 'gt';
    case '>=':
      return 'gte';
    case '<':
      return 'lt';
    case '<=':
      return 'lte';
    default:
      return null;
  }
}

function negateNode(node: QueryNode): QueryNode {
  if (node.kind === 'field' || node.kind === 'json_path' || node.kind === 'ts') {
    const flipped = flipOp(node.op);
    if (flipped) return { ...node, op: flipped };
  }
  return { kind: 'not', child: node };
}

function flipOp(op: AstOp): AstOp | null {
  switch (op) {
    case 'contains':
      return 'not_contains';
    case 'not_contains':
      return 'contains';
    case 'eq':
      return 'ne';
    case 'ne':
      return 'eq';
    default:
      return null; // comparisons → wrap in NOT instead
  }
}

function buildPredicate(lhs: string, opStr: string, value: string, errors: string[]): QueryNode | null {
  const op = baseOp(opStr);
  if (!op) {
    errors.push(`unknown operator "${opStr}"`);
    return null;
  }
  const lower = lhs.toLowerCase();

  // raw: free-text over the payload (substring only).
  if (lower === 'raw') {
    if (!SUBSTRING_OPS.has(opStr)) {
      errors.push('raw supports substring only (raw:term)');
      return null;
    }
    return { kind: 'raw', value };
  }

  // ts: timestamp comparison.
  if (lower === 'ts') {
    if (op === 'not_contains') {
      errors.push('ts does not support !~');
      return null;
    }
    const tsOp: AstOp = op === 'contains' ? 'eq' : op; // `ts:`/`ts~` mean equals
    return { kind: 'ts', op: tsOp, value };
  }

  // A normalized field (string column) — comparisons not allowed.
  if (FIELD_SET.has(lower)) {
    if (COMPARE_OPS.has(opStr)) {
      errors.push(`comparison operators are not allowed on field "${lower}"`);
      return null;
    }
    return { kind: 'field', field: lower as EventField, op, value };
  }

  const path = parsePath(lhs);
  if (path.length === 0 || path[0].toLowerCase() !== 'json') {
    errors.push(`unknown field "${lhs}" — prefix raw-payload paths with json. (e.g. json.requestParameters.roleName)`);
    return null;
  }
  path.shift(); // drop the `json` marker; the remainder is the path into `raw`
  if (path.length === 0) {
    errors.push('empty json path — write json.<key> (e.g. json.requestParameters.roleName)');
    return null;
  }
  const isCompare = COMPARE_OPS.has(opStr);
  const value_type: ValueType = isCompare ? 'number' : 'text';
  if (isCompare && !isNumeric(value)) {
    errors.push(`"${value}" is not a number`);
    return null;
  }
  return { kind: 'json_path', path, op, value, value_type };
}

function isNumeric(v: string): boolean {
  return /^-?[0-9]+(\.[0-9]+)?$/.test(v);
}

// Split a dotted/bracketed path into segments. `a.b["c.d"].e` → [a, b, c.d, e].
export function parsePath(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '.') {
      if (cur) out.push(cur);
      cur = '';
      i++;
    } else if (c === '[') {
      if (cur) out.push(cur);
      cur = '';
      const close = s.indexOf(']', i);
      const end = close === -1 ? s.length : close;
      out.push(stripQuotes(s.slice(i + 1, end)));
      i = end + 1;
      if (s[i] === '.') i++;
    } else {
      cur += c;
      i++;
    }
  }
  if (cur) out.push(cur);
  return out.filter((seg) => seg.length > 0);
}

export interface EventQueryParams {
  ast?: QueryNode;
  status?: string;
  source?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
  // Max rows the count scans before reporting "N+". Defaults server-side to
  // 10000; 0 (or negative) requests a true, unbounded count.
  countCap?: number;
  // Result ordering. Omitted → server default (ts desc).
  orderBy?: OrderField;
  orderDir?: OrderDir;
  // When false, the server skips the count query and returns total = null.
  // Used for pure pagination, where the count is unchanged between pages.
  count?: boolean;
}

export function eventParams(p: EventQueryParams): URLSearchParams {
  const params = new URLSearchParams();
  if (!isEmptyAst(p.ast)) params.set('ast', JSON.stringify(p.ast));
  if (p.status) params.set('status', p.status);
  if (p.source) params.set('source', p.source);
  if (p.from) params.set('from', p.from);
  if (p.to) params.set('to', p.to);
  if (p.limit !== undefined) params.set('limit', String(p.limit));
  if (p.offset !== undefined) params.set('offset', String(p.offset));
  if (p.countCap !== undefined) params.set('count_cap', String(p.countCap));
  if (p.orderBy) params.set('order_by', p.orderBy);
  if (p.orderDir) params.set('order_dir', p.orderDir);
  // Explicit (not truthy) — `false` is the meaningful value that skips the count.
  if (p.count !== undefined) params.set('count', String(p.count));
  return params;
}

function qs(params: URLSearchParams): string {
  const s = params.toString();
  return s ? `?${s}` : '';
}

const ROLE_MSG = 'You need the ce.cloudengineer role to view the console.';

/** Query result plus the decoded JSON payload size (bytes), for the exec readout. */
export interface EventsResult extends Omit<QueryResult, 'total'> {
  total: number | null;
  bytes: number;
}

export async function fetchEvents(p: EventQueryParams): Promise<EventsResult> {
  const url = `/api/query${qs(eventParams(p))}`;
  const res = await apiFetch(url);
  if (res.status === 403) throw new ForbiddenError(ROLE_MSG);
  if (!res.ok) {
    // Surface the backend's 400 message (e.g. "bad ast: …") rather than a bare code.
    const body = await res.text().catch(() => '');
    throw new Error(body || `GET ${url}: ${res.status}`);
  }
  const text = await res.text();
  const bytes = new Blob([text]).size;
  const data = JSON.parse(text) as Partial<QueryResult>;
  return {
    rows: data.rows ?? [],
    // null (count skipped) passes through; a real count is a number.
    total: data.total ?? null,
    total_capped: data.total_capped ?? false,
    bytes,
  };
}

export function eventsExportCsvUrl(p: EventQueryParams): string {
  return `/api/query/export.csv${qs(eventParams(p))}`;
}

export interface TimelineParams {
  bucket?: 'minute' | 'hour' | 'day';
  from?: string;
  to?: string;
}

export async function fetchTimeline(p: TimelineParams = {}): Promise<TimelineResult> {
  const params = new URLSearchParams();
  if (p.bucket) params.set('bucket', p.bucket);
  if (p.from) params.set('from', p.from);
  if (p.to) params.set('to', p.to);
  const url = `/api/overview/timeline${qs(params)}`;
  const res = await apiFetch(url);
  if (res.status === 403) throw new ForbiddenError(ROLE_MSG);
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  return (await res.json()) as TimelineResult;
}

// ---------------------------------------------------------------------------
// Ingest health — one row per source from `ingest_watermarks`. Surfaced as
// per-source freshness/stall indicators. Sources
// with no row yet (e.g. ingester disabled) simply don't appear.
// ---------------------------------------------------------------------------

export interface IngestWatermark {
  source: string;
  last_object_key: string | null;
  last_event_at: string | null;
  objects_scanned: number;
  events_applied: number;
  last_run_at: string | null;
  last_run_error: string | null;
}

export async function fetchIngestHealth(): Promise<IngestWatermark[]> {
  const url = '/api/overview/ingest-health';
  const res = await apiFetch(url);
  if (res.status === 403) throw new ForbiddenError(ROLE_MSG);
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  return (await res.json()) as IngestWatermark[];
}

// ---------------------------------------------------------------------------
// SIEM derivation DTOs + clients (Overview KPIs/alerts/actors-by-risk,
// Entity, Graph, alert triage). All read endpoints are gated to ce.cloudengineer.
// ---------------------------------------------------------------------------

export interface Kpis {
  failed_auth_24h: number;
  deactivated_24h: number;
  guardduty: number | null;
  // `null` only if the field is ever degraded; normally a count.
  anomalies: number | null;
  critical_alerts: number;
  open_alerts: number;
  actors_tracked: number;
  high_risk_actors: number;
  active_sessions: number;
}

// Statistical anomaly (soft signal feeding risk + timeline markers).
export interface Anomaly {
  id: number;
  fingerprint: string;
  kind: string;
  actor_id: string | null;
  severity: string;
  score: number;
  baseline: number | null;
  observed: number | null;
  title: string;
  detail: string | null;
  evidence: unknown;
  event_time: string;
  detected_at: string;
  updated_at: string;
}

export interface Alert {
  id: number;
  fingerprint: string;
  rule_id: string;
  severity: string;
  title: string;
  description: string | null;
  actor_id: string | null;
  source: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  status: string;
  evidence: unknown;
  acked_by: string | null;
  acked_at: string | null;
  resolved_by: string | null;
  resolved_at: string | null;
  updated_at: string;
}

export interface SourceStat {
  source: string;
  total: number;
  failures: number;
}

export interface ActorRisk {
  id: string;
  display_name: string | null;
  email: string | null;
  team: string | null;
  kind: string;
  // Identity-origin badges (kubernetes/azure-ad/aws/github/selfservice/unknown)
  // and the event feeds the actor was seen through.
  origins: string[];
  sources: string[];
  score: number;
  label: string;
  last_active: string | null;
}

export interface RiskComponent {
  raw: number;
  weight: number;
  normalized: number;
  contribution: number;
}

export interface RiskScore {
  actor_id: string;
  score: number;
  label: string;
  components: Record<string, RiskComponent>;
  computed_at: string;
}

export interface Actor {
  id: string;
  email: string | null;
  display_name: string | null;
  team: string | null;
  kind: string;
  first_seen: string | null;
  last_active: string | null;
  sources: (string | null)[];
  created_at: string;
  updated_at: string;
}

export interface SessionRow {
  id: number;
  session_key: string;
  actor_id: string | null;
  source: string;
  device: string | null;
  source_ip: string | null;
  location: string | null;
  started_at: string;
  last_seen_at: string;
  event_count: number;
  status: string;
  flag_reason: string | null;
}

export interface GrantRow {
  id: number;
  grant_key: string;
  actor_id: string | null;
  system: string;
  role: string;
  scope: string | null;
  severity: string;
  privileged: boolean;
  granted_at: string | null;
  granted_by: string | null;
  source_event: string | null;
  revoked_at: string | null;
  updated_at: string;
}

export interface EntityStats {
  events_24h: number;
  events_7d: number;
  failed_7d: number;
  sessions: number;
  privileged_grants: number;
}

export interface IdentityContext {
  // CloudTrail provenance for the actor: identity sources (oidc:<provider>,
  // aws-sso, iamuser, …) and the IAM roles it has assumed, most-frequent first.
  sources: string[];
  roles: string[];
}

export interface EntityDetail {
  identity: Actor;
  risk: RiskScore | null;
  stats: EntityStats;
  identity_context: IdentityContext;
  sessions: SessionRow[];
  grants: GrantRow[];
  anomalies: Anomaly[];
  activity: SsuMgmtEvent[];
  activity_total: number;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  risk: number;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: string;
  weight: number;
  failure: boolean;
}

export interface GraphResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  shownOf: { shown: number; total: number };
  mode: string;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await apiFetch(url);
  if (res.status === 403) throw new ForbiddenError(ROLE_MSG);
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  return (await res.json()) as T;
}

export function fetchKpis(): Promise<Kpis> {
  return getJson<Kpis>('/api/overview/kpis');
}

export function fetchSourceStats(): Promise<SourceStat[]> {
  return getJson<SourceStat[]>('/api/overview/sources');
}

export interface DeferredSource {
  source: string;
  label: string;
  note: string;
}

export const DEFERRED_SOURCES: readonly DeferredSource[] = [
  { source: 'azure', label: 'Azure AD', note: 'sign-in & audit logs — deferred (TODO)' },
  { source: '1password', label: '1Password', note: 'vault access events — deferred (TODO)' },
];

export interface AnomaliesQuery {
  kind?: string;
  from?: string;
  to?: string;
  limit?: number;
}

export function fetchAnomalies(p: AnomaliesQuery = {}): Promise<Anomaly[]> {
  const params = new URLSearchParams();
  if (p.kind) params.set('kind', p.kind);
  if (p.from) params.set('from', p.from);
  if (p.to) params.set('to', p.to);
  if (p.limit !== undefined) params.set('limit', String(p.limit));
  return getJson<Anomaly[]>(`/api/overview/anomalies${qs(params)}`);
}

export function fetchActorsByRisk(limit = 10): Promise<ActorRisk[]> {
  return getJson<ActorRisk[]>(`/api/overview/actors-by-risk?limit=${limit}`);
}

// ---------------------------------------------------------------------------
// Actor discovery — the paginated/filterable table over the `actors` spine
// (/api/actors). Distinct from actors-by-risk (top-N rollup): this browses every
// actor with substring search + kind/origin facets + sort + offset pagination.
// ---------------------------------------------------------------------------

export interface ActorListRow {
  id: string;
  display_name: string | null;
  email: string | null;
  team: string | null;
  kind: string;
  origins: string[];
  sources: string[];
  // Nullable — actors with no derived risk row still appear (LEFT JOIN).
  score: number | null;
  label: string | null;
  first_seen: string | null;
  last_active: string | null;
}

export interface ActorsPage {
  rows: ActorListRow[];
  total: number;
}

export interface ActorsQuery {
  q?: string;
  kind?: string;
  origin?: string;
  sort?: 'risk' | 'recent' | 'name';
  limit?: number;
  offset?: number;
}

export function fetchActors(p: ActorsQuery = {}): Promise<ActorsPage> {
  const params = new URLSearchParams();
  if (p.q) params.set('q', p.q);
  if (p.kind) params.set('kind', p.kind);
  if (p.origin) params.set('origin', p.origin);
  if (p.sort) params.set('sort', p.sort);
  if (p.limit !== undefined) params.set('limit', String(p.limit));
  if (p.offset !== undefined) params.set('offset', String(p.offset));
  return getJson<ActorsPage>(`/api/actors${qs(params)}`);
}

/** The origin taxonomy, in display order — drives the Actors/inspect filter dropdowns. */
export const ACTOR_ORIGINS: readonly string[] = [
  'kubernetes',
  'azure-ad',
  'aws',
  'github',
  'selfservice',
  'unknown',
];

export interface AlertsQuery {
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

/** Paginated alerts page: the requested rows plus the total under the same facets. */
export interface AlertsPage {
  rows: Alert[];
  total: number;
}

function alertParams(p: AlertsQuery): URLSearchParams {
  const params = new URLSearchParams();
  if (p.severity) params.set('severity', p.severity);
  if (p.status) params.set('status', p.status);
  if (p.limit !== undefined) params.set('limit', String(p.limit));
  if (p.offset !== undefined) params.set('offset', String(p.offset));
  return params;
}

/** Full paginated envelope — used by the alerts feed/page pagination. */
export function fetchAlertsPage(p: AlertsQuery = {}): Promise<AlertsPage> {
  return getJson<AlertsPage>(`/api/overview/alerts${qs(alertParams(p))}`);
}

/** Rows-only convenience (the live seed) — unwraps the paginated envelope. */
export function fetchOverviewAlerts(p: AlertsQuery = {}): Promise<Alert[]> {
  return fetchAlertsPage(p).then((r) => r.rows);
}

export function fetchEntity(id: string): Promise<EntityDetail> {
  return getJson<EntityDetail>(`/api/entity/${encodeURIComponent(id)}`);
}

/** Paginated activity for one actor — the same `{ rows, total }` envelope as the query view. */
export function fetchEntityActivity(id: string, p: { limit?: number; offset?: number } = {}): Promise<QueryResult> {
  const params = new URLSearchParams();
  if (p.limit !== undefined) params.set('limit', String(p.limit));
  if (p.offset !== undefined) params.set('offset', String(p.offset));
  return getJson<QueryResult>(`/api/entity/${encodeURIComponent(id)}/activity${qs(params)}`);
}

export function fetchEntityTimeline(id: string, p: TimelineParams = {}): Promise<TimelineBucket[]> {
  const params = new URLSearchParams();
  if (p.bucket) params.set('bucket', p.bucket);
  if (p.from) params.set('from', p.from);
  if (p.to) params.set('to', p.to);
  return getJson<TimelineBucket[]>(`/api/entity/${encodeURIComponent(id)}/timeline${qs(params)}`);
}

export interface GraphQuery {
  mode?: 'surface' | 'investigate' | 'entity';
  actor?: string;
}

export function fetchGraph(p: GraphQuery = {}): Promise<GraphResult> {
  const params = new URLSearchParams();
  if (p.mode) params.set('mode', p.mode);
  if (p.actor) params.set('actor', p.actor);
  return getJson<GraphResult>(`/api/graph${qs(params)}`);
}

async function postTriage(url: string): Promise<void> {
  const res = await apiFetch(url, { method: 'POST' });
  if (res.status === 403) throw new ForbiddenError(ROLE_MSG);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(body || `POST ${url}: ${res.status}`);
  }
}

export function ackAlert(id: number): Promise<void> {
  return postTriage(`/api/alerts/${id}/ack`);
}

export function resolveAlert(id: number): Promise<void> {
  return postTriage(`/api/alerts/${id}/resolve`);
}

export function unackAlert(id: number): Promise<void> {
  return postTriage(`/api/alerts/${id}/unack`);
}

export function unresolveAlert(id: number): Promise<void> {
  return postTriage(`/api/alerts/${id}/unresolve`);
}
