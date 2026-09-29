import { useEffect, useRef, useState } from 'react';

const BASE = '';
const MAX_ROWS = 3000;

async function j(res) {
  if (!res.ok) {
    let msg = res.statusText;
    try { const b = await res.json(); msg = b.detail || JSON.stringify(b); } catch (e) { /* ignore */ }
    throw new Error(msg);
  }
  return res.json();
}

export const liveApi = {
  sources: () => fetch(`${BASE}/api/live/sources`).then(j),
  status: () => fetch(`${BASE}/api/live/status`).then(j),
  start: (body) => fetch(`${BASE}/api/live/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then(j),
  stop: () => fetch(`${BASE}/api/live/stop`, { method: 'POST' }).then(j),
  reset: () => fetch(`${BASE}/api/live/reset`, { method: 'POST' }).then(j),
  profile: (p) => fetch(`${BASE}/api/live/profile?profile=${p}`, { method: 'POST' }).then(j),
  packet: (n) => fetch(`${BASE}/api/live/packet/${n}`).then(j),
  save: (name, analyze, profile) => fetch(`${BASE}/api/live/save?analyze=${analyze}&profile=${profile}${name ? `&name=${encodeURIComponent(name)}` : ''}`, { method: 'POST' }).then(j),
  upload: (file) => { const fd = new FormData(); fd.append('file', file); return fetch(`${BASE}/api/live/upload`, { method: 'POST', body: fd }).then(j); },
};

export function wsUrl(path) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}${path}`;
}

/** Live stream hook: keeps packet rows in a ref (cheap), everything else in state. Reconnects automatically. */
export function useLiveStream() {
  const rowsRef = useRef([]);
  const [tick, setTick] = useState(0);            // bumps when rows change
  const [connected, setConnected] = useState(false);
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [dropped, setDropped] = useState(0);

  useEffect(() => {
    let ws; let closed = false; let retry = 1000; let timer;
    const apply = (e) => {
      switch (e.type) {
        case 'hello':
          rowsRef.current = e.rows || [];
          setStatus(e.status); setStats(e.stats); setSnapshot(e.snapshot); setAlerts((e.alerts || []).slice().reverse());
          setTick((t) => t + 1);
          break;
        case 'packets': {
          const cur = rowsRef.current;
          const next = cur.length + e.rows.length > MAX_ROWS ? cur.slice(cur.length + e.rows.length - MAX_ROWS) : cur.slice();
          for (const r of e.rows) next.push(r);
          rowsRef.current = next;
          if (e.dropped) setDropped((d) => d + e.dropped);
          setTick((t) => t + 1);
          break;
        }
        case 'stats': setStats(e); setStatus((s) => ({ ...(s || {}), running: e.running, packets: e.packets, source: e.source || (s && s.source) })); break;
        case 'snapshot': setSnapshot(e.snapshot); break;
        case 'alert': setAlerts((a) => [e.alert, ...a].slice(0, 300)); break;
        case 'status': setStatus(e); break;
        case 'reset': rowsRef.current = []; setAlerts([]); setSnapshot(null); setStats(null); setDropped(0); setTick((t) => t + 1); break;
        default: break;
      }
    };
    const connect = () => {
      if (closed) return;
      ws = new WebSocket(wsUrl('/ws/live'));
      ws.onopen = () => { setConnected(true); retry = 1000; };
      ws.onmessage = (m) => {
        const e = JSON.parse(m.data);
        if (e.type === 'batch') e.events.forEach(apply); else apply(e);
      };
      ws.onclose = () => { setConnected(false); if (!closed) { timer = setTimeout(connect, retry); retry = Math.min(retry * 2, 8000); } };
      ws.onerror = () => { try { ws.close(); } catch (x) { /* ignore */ } };
    };
    connect();
    return () => { closed = true; clearTimeout(timer); try { ws && ws.close(); } catch (x) { /* ignore */ } };
  }, []);

  return { rowsRef, tick, connected, status, stats, snapshot, alerts, dropped, setStatus, setSnapshot };
}

export const fmtRate = (bps) => (bps >= 1e9 ? `${(bps / 1e9).toFixed(2)} Gb/s` : bps >= 1e6 ? `${(bps / 1e6).toFixed(2)} Mb/s` : bps >= 1e3 ? `${(bps / 1e3).toFixed(1)} kb/s` : `${Math.round(bps)} b/s`);
export const fmtNum = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(2)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}k` : `${n}`);
export const fmtClock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
