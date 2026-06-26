import { ref } from 'vue';
import { getAccessToken } from '../auth/useAuth';
import type { IngestWatermark, Kpis, Alert } from './api';

const ingest = ref<IngestWatermark[]>([]);
const kpis = ref<Kpis | null>(null);
const alerts = ref<Alert[]>([]);
const connected = ref(false);

interface ProgressMessage {
  type: 'ingest_health' | 'kpis' | 'alerts';
  payload: unknown;
}

const AUTH_CLOSE_CODES = new Set([1008, 4401]);

const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;

let socket: WebSocket | null = null;
let refCount = 0;
let backoff = BACKOFF_MIN_MS;
let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
let stopped = false;

function applyMessage(msg: ProgressMessage): void {
  switch (msg.type) {
    case 'ingest_health':
      ingest.value = msg.payload as IngestWatermark[];
      break;
    case 'kpis':
      kpis.value = msg.payload as Kpis;
      break;
    case 'alerts':
      alerts.value = msg.payload as Alert[];
      break;
  }
}

async function open(): Promise<void> {
  if (stopped || socket) return;

  const token = await getAccessToken();
  // A renew between scheduling and opening could have stopped us.
  if (stopped) return;

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/api/progress/ws`;
  // Token rides in the subprotocol, never the URL (query strings get logged).
  // When auth is off (dev), there's no token → connect without a subprotocol.
  const ws = token ? new WebSocket(url, ['bearer', token]) : new WebSocket(url);
  socket = ws;

  ws.onopen = () => {
    connected.value = true;
    backoff = BACKOFF_MIN_MS; // reset on a healthy connection
  };

  ws.onmessage = (ev) => {
    try {
      applyMessage(JSON.parse(ev.data as string) as ProgressMessage);
    } catch {
      /* ignore malformed frame */
    }
  };

  ws.onerror = () => {
    // `onclose` always follows; let it own the reconnect decision.
  };

  ws.onclose = (ev) => {
    connected.value = false;
    socket = null;
    if (stopped) return;
    if (AUTH_CLOSE_CODES.has(ev.code)) {
      void getAccessToken().finally(() => {
        if (!stopped) void open();
      });
      return;
    }
    scheduleReconnect();
  };
}

function scheduleReconnect(): void {
  if (stopped || reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = undefined;
    backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
    void open();
  }, backoff);
}

/** Open the shared stream (ref-counted — only the first caller dials). */
export function connect(): void {
  refCount += 1;
  if (refCount > 1) return;
  stopped = false;
  void open();
}

/** Release a reference; the socket closes once the last consumer disconnects. */
export function disconnect(): void {
  refCount = Math.max(0, refCount - 1);
  if (refCount > 0) return;
  stopped = true;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  }
  if (socket) {
    socket.onclose = null; // suppress the reconnect path on an intentional close
    socket.close();
    socket = null;
  }
  connected.value = false;
}

export function useConsoleStream() {
  return { ingest, kpis, alerts, connected, connect, disconnect };
}
