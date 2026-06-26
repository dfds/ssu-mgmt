// Shared formatting + terminal color mapping for the ssu-mgmt console.

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString([], {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

const SOURCE_COLORS: Record<string, string> = {
  selfservice: 'var(--t-accent)',
  cloudtrail: 'var(--t-amber)',
  github: 'var(--t-blue)',
  azure: 'var(--t-purple)',
  '1password': 'var(--t-red)',
  guardduty: 'var(--t-red)',
};

export function sourceColor(source: string): string {
  return SOURCE_COLORS[source] ?? 'var(--t-dim)';
}

const ORIGIN_COLORS: Record<string, string> = {
  kubernetes: 'var(--t-blue)',
  'azure-ad': 'var(--t-purple)',
  aws: 'var(--t-amber)',
  github: 'var(--t-accent)',
  selfservice: 'var(--t-dim)',
  unknown: 'var(--t-faint)',
};

const ORIGIN_LABELS: Record<string, string> = {
  kubernetes: 'k8s',
  'azure-ad': 'azure',
  aws: 'aws',
  github: 'github',
  selfservice: 'ssu',
  unknown: 'unknown',
};

export function originColor(origin: string): string {
  return ORIGIN_COLORS[origin] ?? 'var(--t-faint)';
}

export function originLabel(origin: string): string {
  return ORIGIN_LABELS[origin] ?? origin;
}

export function levelColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'error':
    case 'err':
      return 'var(--t-red)';
    case 'warn':
    case 'warning':
      return 'var(--t-amber)';
    default:
      return 'var(--t-dim)';
  }
}

export function statusColor(status: string): string {
  return status.toLowerCase() === 'failure' ? 'var(--t-red)' : 'var(--t-accent)';
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'var(--t-red)';
    case 'high':
      return 'var(--t-amber)';
    case 'medium':
      return 'var(--t-blue)';
    default:
      return 'var(--t-dim)';
  }
}

// Map a 0–100 risk score to a label colour (matches the backend thresholds:
// critical≥80 / high≥60 / medium≥30 / else low).
export function riskColor(score: number): string {
  if (score >= 80) return 'var(--t-red)';
  if (score >= 60) return 'var(--t-amber)';
  if (score >= 30) return 'var(--t-blue)';
  return 'var(--t-dim)';
}

// Elapsed query time. Sub-second in ms, otherwise seconds with one decimal.
export function formatMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

// Human-readable byte size for the response-size readout.
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function relAge(iso: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return iso;
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
