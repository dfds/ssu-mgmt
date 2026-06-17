// KQL-lite parser and rules<->query translator. Powers the live UI preview and
// the rule-row ↔ query-text translation in AuditLogsView.vue. The server-side
// audit endpoint accepts the projected `rule` parameters only — we always run
// queryToRules before submit.

import type { AuditRule, AuditRuleField, AuditRuleOp } from '../api';

export const MAX_INPUT_LEN = 4096;
export const MAX_DEPTH = 10;
export const MAX_CLAUSES = 50;

export type Node = BoolNode | NotNode | Clause;

export interface BoolNode {
  kind: 'bool';
  op: 'AND' | 'OR';
  children: Node[];
}

export interface NotNode {
  kind: 'not';
  child: Node;
}

export interface Clause {
  kind: 'clause';
  field: string;
  rawValue: string;
  quoted: boolean;
}

export interface ParseError {
  offset: number;
  message: string;
}

export type ParseResult = { ast: Node } | { error: ParseError };

const ALLOWED_FIELDS: ReadonlySet<AuditRuleField> = new Set<AuditRuleField>([
  'principal',
  'service',
  'action',
  'method',
  'path',
  'type',
]);

function isSpace(c: string): boolean {
  return c === ' ' || c === '\t' || c === '\n' || c === '\r';
}

function isWordStart(c: string): boolean {
  return /^[A-Za-z_]$/.test(c);
}

function isWordPart(c: string): boolean {
  return /^[A-Za-z0-9_]$/.test(c);
}

class Parser {
  pos = 0;
  constructor(public src: string) {}

  eof(): boolean { return this.pos >= this.src.length; }
  peek(): string { return this.eof() ? '' : this.src[this.pos]; }

  skipSpace(): void {
    while (!this.eof() && isSpace(this.src[this.pos])) this.pos++;
  }

  kwAt(): '' | 'AND' | 'OR' | 'NOT' {
    const rem = this.src.slice(this.pos);
    for (const kw of ['AND', 'OR', 'NOT'] as const) {
      if (rem.length < kw.length) continue;
      if (rem.slice(0, kw.length).toUpperCase() !== kw) continue;
      if (rem.length === kw.length) return kw;
      const next = rem[kw.length];
      if (isSpace(next) || next === '(' || next === ')') return kw;
    }
    return '';
  }

  parseOr(): Node {
    let left = this.parseAnd();
    let children: Node[] | null = null;
    for (;;) {
      this.skipSpace();
      if (this.kwAt() !== 'OR') break;
      this.pos += 2;
      this.skipSpace();
      const right = this.parseAnd();
      if (!children) children = [left];
      children.push(right);
    }
    if (children) return { kind: 'bool', op: 'OR', children };
    return left;
  }

  parseAnd(): Node {
    let left = this.parseNot();
    let children: Node[] | null = null;
    for (;;) {
      this.skipSpace();
      if (this.eof() || this.src[this.pos] === ')') break;
      const kw = this.kwAt();
      if (kw === 'OR') break;
      if (kw === 'AND') {
        this.pos += 3;
        this.skipSpace();
      }
      const right = this.parseNot();
      if (!children) children = [left];
      children.push(right);
    }
    if (children) return { kind: 'bool', op: 'AND', children };
    return left;
  }

  parseNot(): Node {
    this.skipSpace();
    if (this.kwAt() === 'NOT') {
      this.pos += 3;
      this.skipSpace();
      return { kind: 'not', child: this.parseNot() };
    }
    if (!this.eof() && this.src[this.pos] === '-') {
      const next = this.pos + 1;
      if (next < this.src.length) {
        const c = this.src[next];
        if (isWordStart(c) || c === '(') {
          this.pos++;
          return { kind: 'not', child: this.parseNot() };
        }
      }
    }
    return this.parseTerm();
  }

  parseTerm(): Node {
    this.skipSpace();
    if (this.eof()) throw makeErr(this.pos, 'expected term, got end of input');
    if (this.src[this.pos] === '(') {
      this.pos++;
      this.skipSpace();
      const n = this.parseOr();
      this.skipSpace();
      if (this.eof() || this.src[this.pos] !== ')') throw makeErr(this.pos, "missing ')'");
      this.pos++;
      return n;
    }
    return this.parseClause();
  }

  parseClause(): Node {
    const fieldStart = this.pos;
    const field = this.readWord();
    if (!field) throw makeErr(this.pos, 'expected field name');
    const u = field.toUpperCase();
    if (u === 'AND' || u === 'OR' || u === 'NOT') {
      throw makeErr(fieldStart, `unexpected keyword "${field}"`);
    }
    if (this.eof() || this.src[this.pos] !== ':') {
      throw makeErr(this.pos, `expected ':' after field "${field}"`);
    }
    this.pos++;
    return this.parseValue(field);
  }

  parseValue(field: string): Clause {
    if (this.eof()) throw makeErr(this.pos, "expected value after ':'");
    if (this.src[this.pos] === '"') return this.parseQuoted(field);
    const start = this.pos;
    while (!this.eof()) {
      const c = this.src[this.pos];
      if (isSpace(c) || c === '(' || c === ')') break;
      this.pos++;
    }
    if (start === this.pos) throw makeErr(this.pos, 'empty value');
    return { kind: 'clause', field, rawValue: this.src.slice(start, this.pos), quoted: false };
  }

  parseQuoted(field: string): Clause {
    this.pos++;
    let out = '';
    for (;;) {
      if (this.eof()) throw makeErr(this.pos, 'unterminated string');
      const c = this.src[this.pos];
      if (c === '\\') {
        if (this.pos + 1 >= this.src.length) throw makeErr(this.pos, 'unterminated escape');
        out += this.src[this.pos + 1];
        this.pos += 2;
        continue;
      }
      if (c === '"') {
        this.pos++;
        return { kind: 'clause', field, rawValue: out, quoted: true };
      }
      out += c;
      this.pos++;
    }
  }

  readWord(): string {
    const start = this.pos;
    while (!this.eof() && isWordPart(this.src[this.pos])) this.pos++;
    return this.src.slice(start, this.pos);
  }
}

function makeErr(offset: number, message: string): ParseError {
  return { offset, message };
}

function isParseError(e: unknown): e is ParseError {
  return !!e && typeof e === 'object' && 'offset' in e && 'message' in e;
}

export function parse(src: string): ParseResult {
  if (src.length > MAX_INPUT_LEN) {
    return { error: { offset: MAX_INPUT_LEN, message: `query exceeds ${MAX_INPUT_LEN} bytes` } };
  }
  const p = new Parser(src);
  p.skipSpace();
  if (p.eof()) return { error: { offset: p.pos, message: 'empty query' } };
  try {
    const ast = p.parseOr();
    p.skipSpace();
    if (!p.eof()) {
      return { error: { offset: p.pos, message: `unexpected "${p.src[p.pos]}"` } };
    }
    const v = validate(ast);
    if (v) return { error: { offset: 0, message: v } };
    return { ast };
  } catch (e) {
    if (isParseError(e)) return { error: e };
    return { error: { offset: 0, message: String(e) } };
  }
}

function validate(n: Node): string | null {
  let clauses = 0;
  function walk(n: Node, depth: number): string | null {
    if (depth > MAX_DEPTH) return `expression too deeply nested (max ${MAX_DEPTH})`;
    if (n.kind === 'bool') {
      if (!n.children.length) return `empty ${n.op} node`;
      for (const c of n.children) {
        const e = walk(c, depth + 1);
        if (e) return e;
      }
      return null;
    }
    if (n.kind === 'not') {
      return walk(n.child, depth + 1);
    }
    // clause
    clauses++;
    if (clauses > MAX_CLAUSES) return `too many clauses (max ${MAX_CLAUSES})`;
    if (!ALLOWED_FIELDS.has(n.field as AuditRuleField)) return `unknown field "${n.field}"`;
    return null;
  }
  return walk(n, 0);
}

export function countClauses(n: Node): number {
  if (n.kind === 'clause') return 1;
  if (n.kind === 'not') return countClauses(n.child);
  return n.children.reduce((acc, c) => acc + countClauses(c), 0);
}

// ---------- format ----------

const PREC_OR = 1;
const PREC_AND = 2;
const PREC_NOT = 3;

function nodePrec(n: Node): number {
  if (n.kind === 'bool') return n.op === 'OR' ? PREC_OR : PREC_AND;
  if (n.kind === 'not') return PREC_NOT;
  return 4;
}

export function format(n: Node | null): string {
  if (!n) return '';
  return formatNode(n, 0);
}

function formatNode(n: Node, parentPrec: number): string {
  if (n.kind === 'bool') {
    const p = nodePrec(n);
    const inner = n.children.map((c) => formatNode(c, p)).join(` ${n.op} `);
    return p < parentPrec ? `(${inner})` : inner;
  }
  if (n.kind === 'not') {
    return `NOT ${formatNode(n.child, PREC_NOT)}`;
  }
  return `${n.field}:${formatValue(n.rawValue, n.quoted)}`;
}

function formatValue(v: string, quoted: boolean): string {
  if (quoted || needsQuote(v)) {
    let out = '"';
    for (const c of v) {
      if (c === '"' || c === '\\') out += '\\';
      out += c;
    }
    return out + '"';
  }
  return v;
}

function needsQuote(v: string): boolean {
  if (!v) return true;
  for (const c of v) {
    if (isSpace(c) || c === '(' || c === ')' || c === '"' || c === ':') return true;
  }
  const u = v.toUpperCase();
  return u === 'AND' || u === 'OR' || u === 'NOT';
}

// ---------- translate ----------

export function rulesToQuery(rules: AuditRule[], match: 'all' | 'any'): string {
  const positives: Clause[] = [];
  const negatives: Clause[] = [];
  for (const r of rules) {
    if (!r.value.trim()) continue;
    const c: Clause = {
      kind: 'clause',
      field: r.field,
      rawValue: r.value,
      quoted: r.op === 'equals' || r.op === 'not_equals',
    };
    if (r.op === 'not_contains' || r.op === 'not_equals') negatives.push(c);
    else positives.push(c);
  }
  if (positives.length === 0 && negatives.length === 0) return '';

  const wrapNegs = (neg: Clause[]): NotNode[] =>
    neg.map((c) => ({ kind: 'not', child: c }));

  const posIsOr = match === 'any' && positives.length > 1;
  if (posIsOr) {
    const posNode: BoolNode = { kind: 'bool', op: 'OR', children: positives };
    if (negatives.length === 0) return format(posNode);
    const ast: BoolNode = { kind: 'bool', op: 'AND', children: [posNode, ...wrapNegs(negatives)] };
    return format(ast);
  }
  const flat: Node[] = [...positives, ...wrapNegs(negatives)];
  if (flat.length === 1) return format(flat[0]);
  return format({ kind: 'bool', op: 'AND', children: flat });
}

export interface QueryToRulesResult {
  rules: AuditRule[];
  match: 'all' | 'any';
  complex: boolean;
}

export function queryToRules(ast: Node): QueryToRulesResult {
  const out = toRules(ast);
  if (!out) return { rules: [], match: 'all', complex: true };
  return { rules: out.rules, match: out.match, complex: false };
}

function toRules(n: Node): { rules: AuditRule[]; match: 'all' | 'any' } | null {
  if (n.kind === 'clause') {
    const r = clauseToRule(n, false);
    return r ? { rules: [r], match: 'all' } : null;
  }
  if (n.kind === 'not') {
    if (n.child.kind !== 'clause') return null;
    const r = clauseToRule(n.child, true);
    return r ? { rules: [r], match: 'all' } : null;
  }
  // bool
  if (n.op === 'OR') {
    return flatOrToRules(n);
  }
  // AND
  let positives: AuditRule[] = [];
  const negatives: AuditRule[] = [];
  let match: 'all' | 'any' = 'all';
  let sawOr = false;
  for (const c of n.children) {
    if (c.kind === 'clause') {
      if (sawOr) return null;
      const r = clauseToRule(c, false);
      if (!r) return null;
      positives.push(r);
    } else if (c.kind === 'not') {
      if (c.child.kind !== 'clause') return null;
      const r = clauseToRule(c.child, true);
      if (!r) return null;
      negatives.push(r);
    } else {
      // bool child
      if (c.op !== 'OR' || sawOr || positives.length > 0) return null;
      const inner = flatOrToRules(c);
      if (!inner) return null;
      positives = inner.rules;
      sawOr = true;
      match = 'any';
    }
  }
  return { rules: [...positives, ...negatives], match };
}

function flatOrToRules(n: BoolNode): { rules: AuditRule[]; match: 'all' | 'any' } | null {
  const rules: AuditRule[] = [];
  for (const c of n.children) {
    if (c.kind !== 'clause') return null;
    const r = clauseToRule(c, false);
    if (!r) return null;
    rules.push(r);
  }
  return { rules, match: 'any' };
}

function clauseToRule(c: Clause, negate: boolean): AuditRule | null {
  const raw = c.rawValue;
  let op: AuditRuleOp;
  let value: string;
  if (c.quoted) {
    op = 'equals';
    value = raw;
  } else if (raw.includes('*')) {
    if (
      raw.length >= 2 &&
      raw.startsWith('*') &&
      raw.endsWith('*') &&
      !raw.slice(1, -1).includes('*')
    ) {
      op = 'contains';
      value = raw.slice(1, -1);
    } else {
      return null;
    }
  } else {
    if (c.field === 'method' || c.field === 'service' || c.field === 'type') op = 'equals';
    else op = 'contains';
    value = raw;
  }
  if (negate) {
    if (op === 'contains') op = 'not_contains';
    else if (op === 'equals') op = 'not_equals';
  }
  return { field: c.field as AuditRuleField, op, value };
}
