import React, { useEffect, useMemo, useRef, useState } from 'react';
import { liveApi, useLiveStream, fmtRate, fmtNum, fmtClock } from '../live.js';
import { gradeColor, fmtBytes } from '../api.js';
import { Gauge, Sev, Tier, TierBar, DomainBars } from './Widgets.jsx';

const SPEEDS = [0.5, 1, 2, 5, 10, 20, 60];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ------------------------------------------------------------------------------------------------ small charts
function RateChart({ buckets, height = 110 }) {
  const w = 600;
  const now = Math.floor(Date.now() / 1000);
  const span = 90;
  const byT = new Map((buckets || []).map((b) => [b.t, b]));
  const cols = [];
  for (let t = now - span + 1; t <= now; t++) cols.push(byT.get(t) || { t, pkts: 0, bytes: 0, ike: 0, esp: 0, ah: 0, other: 0 });
  const maxP = Math.max(1, ...cols.map((c) => c.pkts));
  const maxB = Math.max(1, ...cols.map((c) => c.bytes * 8));
  const bw = w / span;
  const colors = { ike: '#0070C0', esp: '#2E7D32', ah: '#7030A0', other: '#B0BEC5' };
  const line = cols.map((c, i) => `${i === 0 ? 'M' : 'L'}${(i + 0.5) * bw},${height - 4 - ((height - 14) * c.bytes * 8) / maxB}`).join(' ');
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${height}`} width="100%" height={height} preserveAspectRatio="none" className="chart">
        {cols.map((c, i) => {
          let y = height - 4;
          return ['other', 'ah', 'esp', 'ike'].map((k) => {
            const h = ((height - 14) * c[k]) / maxP;
            y -= h;
            return <rect key={k} x={i * bw + 0.5} y={y} width={Math.max(0.5, bw - 1)} height={h} fill={colors[k]} />;
          });
        })}
        <path d={line} stroke="#EF6C00" strokeWidth="1.5" fill="none" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="legend" style={{ justifyContent: 'space-between' }}>
        <span><i style={{ background: colors.ike }} />IKE <i style={{ background: colors.esp, marginLeft: 8 }} />ESP <i style={{ background: colors.ah, marginLeft: 8 }} />AH <i style={{ background: colors.other, marginLeft: 8 }} />other <i style={{ background: '#EF6C00', marginLeft: 8, borderRadius: 5, height: 3 }} />bit/s</span>
        <span>last {span} s · peak {fmtNum(maxP)} pkt/s · {fmtRate(maxB)}</span>
      </div>
    </div>
  );
}

function Donut({ counts }) {
  const parts = [['ike', 'IKE', '#0070C0'], ['esp', 'ESP', '#2E7D32'], ['ah', 'AH', '#7030A0'], ['keepalive', 'NAT-KA', '#90A4AE'], ['other', 'other', '#CFD8DC']];
  const total = parts.reduce((s, [k]) => s + (counts?.[k] || 0), 0) || 1;
  let acc = 0;
  const r = 34, c = 2 * Math.PI * r;
  return (
    <div className="row" style={{ gap: 14 }}>
      <svg width="90" height="90" viewBox="0 0 90 90">
        <circle cx="45" cy="45" r={r} fill="none" stroke="#eef3f8" strokeWidth="12" />
        {parts.map(([k, , col]) => {
          const v = counts?.[k] || 0; const f = v / total; const dash = `${f * c} ${c}`; const off = -acc * c; acc += f;
          return v ? <circle key={k} cx="45" cy="45" r={r} fill="none" stroke={col} strokeWidth="12" strokeDasharray={dash} strokeDashoffset={off} transform="rotate(-90 45 45)" /> : null;
        })}
        <text x="45" y="49" textAnchor="middle" fontSize="13" fontWeight="700" fill="#1F4E79">{fmtNum(counts?.total || 0)}</text>
      </svg>
      <div className="small">
        {parts.map(([k, l, col]) => <div key={k}><i className="sw" style={{ background: col }} />{l}: <b>{fmtNum(counts?.[k] || 0)}</b> <span className="muted">({Math.round((100 * (counts?.[k] || 0)) / total)}%)</span></div>)}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ source controls
function SourcePanel({ status, profile, setProfile, profiles, onChanged, busy, setBusy, setError, navigate }) {
  const [src, setSrc] = useState(null);
  const [kind, setKind] = useState('sample');
  const [sample, setSample] = useState('');
  const [iface, setIface] = useState('');
  const [capture, setCapture] = useState('');
  const [speed, setSpeed] = useState(5);
  const [loop, setLoop] = useState(false);
  const [saveMsg, setSaveMsg] = useState(null);
  const running = !!status?.running;
  const refresh = () => liveApi.sources().then((s) => {
    setSrc(s);
    if (!sample && s.samples.length) setSample(s.samples.find((x) => x.name.startsWith('enterprise'))?.name || s.samples[0].name);
    if (!iface && s.interfaces.length) setIface((s.interfaces.find((i) => i.name !== 'lo') || s.interfaces[0]).name);
    if (!capture && s.captures.length) setCapture(s.captures[s.captures.length - 1].name);
  }).catch((e) => setError(e.message));
  useEffect(() => { refresh(); }, []);
  useEffect(() => { if (!running) refresh(); }, [running]);
  // reflect the source that is actually running (e.g. a session opened by an agent connecting)
  useEffect(() => {
    const k = status?.source?.kind;
    if (running && k) setKind(k === 'replay' ? ((src?.samples || []).some((x) => x.name === status.source.file) ? 'sample' : 'capture') : k);
  }, [running, status?.source?.kind]);

  const act = async (fn) => { setBusy(true); setError(null); try { const r = await fn(); onChanged(r); } catch (e) { setError(e.message); } finally { setBusy(false); } };
  const start = () => act(() => liveApi.start({
    source: kind === 'capture' ? 'replay' : kind, sample: kind === 'sample' ? sample : undefined, path: kind === 'capture' ? capture : undefined,
    iface: kind === 'interface' ? iface : undefined, speed, loop, profile,
  }));
  const upload = async (file) => {
    if (!file) return;
    setBusy(true); setError(null);
    try { const r = await liveApi.upload(file); await refresh(); setKind('capture'); setCapture(r.name); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const save = () => act(async () => {
    const r = await liveApi.save(null, true, profile);
    setSaveMsg(r);
    return null;
  });
  const agentCmd = `sudo python -m ipsec_xray.live.agent --server ${window.location.origin} --iface ${iface || 'eth0'} --ipsec-only`;
  const seg = (k, label, title) => <button key={k} className={`seg ${kind === k ? 'on' : ''}`} title={title} onClick={() => setKind(k)} disabled={running}>{label}</button>;
  return (
    <div className="card live-src">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0 }}>Live capture</h2>
        <div className="segs">
          {seg('sample', 'Demo replay', 'Replay a built-in sample capture with its real timing')}
          {seg('interface', 'Interface', 'Sniff a network interface of this server (needs CAP_NET_RAW)')}
          {seg('agent', 'Remote agent', 'A small agent on another machine streams its packets here')}
          {seg('capture', 'Pcap file', 'Replay an uploaded or previously saved capture')}
        </div>
      </div>
      <div className="row mt" style={{ gap: 10 }}>
        {kind === 'sample' && (
          <select value={sample} onChange={(e) => setSample(e.target.value)} disabled={running} style={{ maxWidth: 360 }}>
            {(src?.samples || []).map((s) => <option key={s.name} value={s.name}>{s.name} — expected {s.expected_grade.join('/')}</option>)}
          </select>
        )}
        {kind === 'interface' && (
          <>
            <select value={iface} onChange={(e) => setIface(e.target.value)} disabled={running}>
              {(src?.interfaces || []).map((i) => <option key={i.name} value={i.name}>{i.name} ({i.state})</option>)}
            </select>
            <span className={`small ${src?.can_sniff ? 'ok' : 'bad'}`}>{src?.can_sniff ? 'raw capture available' : `not permitted here: ${src?.sniff_note || ''}`}</span>
          </>
        )}
        {kind === 'capture' && (
          <>
            <select value={capture} onChange={(e) => setCapture(e.target.value)} disabled={running} style={{ maxWidth: 300 }}>
              {(src?.captures || []).map((c) => <option key={c.name} value={c.name}>{c.name} ({fmtBytes(c.size)})</option>)}
              {!(src?.captures || []).length && <option value="">no captures yet — upload one</option>}
            </select>
            <label className="btn" style={{ cursor: 'pointer' }}>Upload pcap<input type="file" accept=".pcap,.pcapng,.cap" style={{ display: 'none' }} onChange={(e) => upload(e.target.files[0])} disabled={running} /></label>
          </>
        )}
        {(kind === 'sample' || kind === 'capture') && (
          <>
            <label className="small muted">speed <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} disabled={running}>{SPEEDS.map((s) => <option key={s} value={s}>{s}×</option>)}</select></label>
            <label className="small muted" title="Re-injects the same SPIs and sequence numbers - replay findings are expected"><input type="checkbox" checked={loop} onChange={(e) => setLoop(e.target.checked)} disabled={running} /> loop</label>
          </>
        )}
        <label className="small muted">profile <select value={profile} onChange={(e) => { setProfile(e.target.value); if (running) liveApi.profile(e.target.value).catch(() => {}); }}>
          {Object.entries(profiles).map(([k, v]) => <option key={k} value={k}>{v.label || k}</option>)}
        </select></label>
        <span style={{ flex: 1 }} />
        {!running && <button className="btn primary" onClick={start} disabled={busy || (kind === 'interface' && !src?.can_sniff)}>▶ Start</button>}
        {running && <button className="btn danger" onClick={() => act(liveApi.stop)} disabled={busy}>■ Stop</button>}
        <button className="btn" onClick={() => act(liveApi.reset)} disabled={busy || running} title="Clear packets, alerts and the live assessment">Reset</button>
        <button className="btn" onClick={save} disabled={busy || !status?.packets} title="Write everything captured so far to a pcap and run the full offline analysis + reports">Save &amp; full report</button>
      </div>
      {kind === 'agent' && (
        <div className="agentbox mt">
          <div className="small"><b>On the machine that sees the VPN traffic</b> (Linux/macOS/Windows with Python + scapy; root/Npcap for capture) run:</div>
          <div className="row" style={{ gap: 8 }}>
            <code className="cmd">{agentCmd}</code>
            <button className="btn" onClick={() => navigator.clipboard?.writeText(agentCmd)}>copy</button>
          </div>
          <div className="small muted">
            The agent only forwards raw frames; parsing, inference and scoring stay on this server, so a phone or any browser can watch. Replace <code>--iface</code> with the interface carrying IKE/ESP traffic (or use <code>--pcap file --speed 5</code> to stream a capture from a remote host).
            {src?.agents?.length ? <span className="ok"> Connected agents: {src.agents.map((a) => `${a.name} (${a.iface}, ${fmtNum(a.frames)} frames)`).join(', ')}.</span> : <span> No agent connected yet — press Start to open a session that waits for one, or the session opens itself when the agent connects.</span>}
          </div>
        </div>
      )}
      {saveMsg && (
        <div className="truth mt row" style={{ justifyContent: 'space-between' }}>
          <span>Saved <b>{saveMsg.file}</b> ({saveMsg.frames} frames, {fmtBytes(saveMsg.size)}) — full assessment: <b style={{ color: gradeColor(saveMsg.grade) }}>{saveMsg.grade} {saveMsg.score}</b></span>
          <span className="row" style={{ gap: 8 }}>
            <button className="btn primary" onClick={() => navigate(`/result/${saveMsg.result_id}`)}>Open full report</button>
            <button className="btn" onClick={() => setSaveMsg(null)}>×</button>
          </span>
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ packet list
const ROW_CLASS = { ike: 'r-ike', esp: 'r-esp', ah: 'r-ah', ka: 'r-ka', warn: 'r-warn', bad: 'r-bad', other: '' };

function PacketDetail({ n, onClose }) {
  const [d, setD] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => { setD(null); setErr(null); liveApi.packet(n).then(setD).catch((e) => setErr(e.message)); }, [n]);
  return (
    <div className="pdetail">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <b>Frame #{n}</b>
        <button className="btn" onClick={onClose}>close</button>
      </div>
      {err && <div className="bad small">{err}</div>}
      {!d && !err && <span className="spinner" />}
      {d && (
        <div className="pdetail-body">
          <div className="ptree">
            {d.tree.map((node, i) => (
              <details key={i} open={i < 6}>
                <summary>{node.name}</summary>
                <div className="pfields">
                  {Object.entries(node.fields).map(([k, v]) => <div key={k}><span className="k">{k}</span><span className="v">{v === null || v === undefined ? '-' : typeof v === 'object' ? JSON.stringify(v) : String(v)}</span></div>)}
                </div>
              </details>
            ))}
          </div>
          <pre className="hex">{d.hex.join('\n')}</pre>
        </div>
      )}
    </div>
  );
}

function PacketList({ rowsRef, tick, running, dropped }) {
  const [filter, setFilter] = useState('');
  const [quick, setQuick] = useState('all');
  const [paused, setPaused] = useState(false);
  const [sel, setSel] = useState(null);
  const frozen = useRef(null);
  const box = useRef(null);
  useEffect(() => { if (paused) frozen.current = rowsRef.current.slice(); else frozen.current = null; }, [paused]);
  const rows = paused && frozen.current ? frozen.current : rowsRef.current;
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    let out = rows;
    if (quick !== 'all') out = out.filter((r) => (quick === 'ike' ? r.c === 'ike' || r.c === 'warn' || r.c === 'bad' : quick === 'esp' ? r.c === 'esp' : quick === 'ah' ? r.c === 'ah' : r.c === 'other' || r.c === 'ka'));
    if (f) {
      const terms = f.split(/\s+/);
      out = out.filter((r) => { const s = `${r.proto} ${r.src} ${r.dst} ${r.info} ${r.len}`.toLowerCase(); return terms.every((t) => (t.startsWith('!') ? !s.includes(t.slice(1)) : s.includes(t))); });
    }
    return out.slice(-400);
  }, [rows, tick, filter, quick, paused]);
  useEffect(() => { if (!paused && box.current) box.current.scrollTop = box.current.scrollHeight; }, [tick, paused, quick, filter]);
  const chip = (k, l) => <button key={k} className={`chip-btn ${quick === k ? 'on' : ''}`} onClick={() => setQuick(k)}>{l}</button>;
  return (
    <div className="card plist">
      <div className="row" style={{ gap: 8 }}>
        <h2 style={{ margin: 0 }}>Packets</h2>
        <span className="small muted">{fmtNum(rows.length)} buffered{dropped ? ` · ${fmtNum(dropped)} not shown (burst)` : ''}</span>
        <span style={{ flex: 1 }} />
        {chip('all', 'All')}{chip('ike', 'IKE')}{chip('esp', 'ESP')}{chip('ah', 'AH')}{chip('other', 'Other')}
        <input type="text" placeholder="filter: e.g. 4500  ike_auth  10.0.0.1  !esp" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ minWidth: 200 }} />
        <button className={`btn ${paused ? 'primary' : ''}`} onClick={() => setPaused(!paused)} title="Freeze the list to inspect packets while capture continues">{paused ? '▶ Resume' : '❚❚ Pause'}</button>
      </div>
      <div className="ptable-wrap" ref={box}>
        <table className="ptable">
          <thead><tr><th>No.</th><th className="hide-m">Time</th><th>Source</th><th>Destination</th><th>Proto</th><th className="hide-m">Len</th><th>Info</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.n} className={`${ROW_CLASS[r.c] || ''} ${sel === r.n ? 'sel' : ''}`} onClick={() => setSel(r.n)}>
                <td className="mono">{r.n}</td><td className="mono hide-m">{r.t.toFixed(4)}</td><td className="mono">{r.src}</td><td className="mono">{r.dst}</td>
                <td><b>{r.proto}</b></td><td className="mono hide-m">{r.len}</td><td className="info">{r.info}</td>
              </tr>
            ))}
            {!shown.length && <tr><td colSpan="7" className="muted" style={{ textAlign: 'center', padding: 30 }}>{running ? 'waiting for packets…' : 'no packets — start a capture, a replay, or connect an agent'}</td></tr>}
          </tbody>
        </table>
      </div>
      {sel != null && <PacketDetail n={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ VPN analysis
function psRow(label, value, tier, conf) {
  return <div className="fact" key={label}><div className="k">{label}</div><div>{value}</div><div>{tier && <Tier t={tier} conf={conf} />}</div></div>;
}

function TunnelCard({ t, ike }) {
  const fr = t.framing || {};
  const short = fr.label ? fr.label.split(' (')[0] : '?';
  const enc = fr.null_encr ? 'NULL encryption — payload readable in cleartext!' : fr.legacy ? 'legacy 64-bit block cipher (Sweet32 class)' : fr.aead ? 'AEAD (GCM/ChaCha-class, integrity built in)' : fr.cbc ? `CBC + HMAC (${fr.integ_bits ? `${fr.integ_bits}-bit ICV` : 'ICV ?'})` : null;
  const keyNote = fr.aead || fr.cbc ? 'AES-128 vs AES-256 not separable on the wire' : null;
  return (
    <div className="tun">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <b>{t.protocol}{t.udp_encap ? '/UDP' : ''} · IPv{t.ipver} · {t.peers[0]} ↔ {t.peers[1]}</b>
        <span className="small muted">{fmtNum(t.packets)} pkts · {fmtBytes(t.bytes)}</span>
      </div>
      {psRow('Mode', t.mode?.value ? `${t.mode.value}${t.mode.best_guess && t.mode.best_guess !== t.mode.value ? ` (guess ${t.mode.best_guess})` : ''}` : '?', t.mode?.tier, t.mode?.confidence)}
      {psRow('Cipher framing', <span>{short}{(enc || keyNote) && <div className="mini">{[enc, keyNote].filter(Boolean).join(' · ')}</div>}</span>, fr.tier, fr.confidence)}
      {psRow('Integrity', fr.null_encr && !fr.icv ? 'none' : fr.icv ? `${fr.icv * 8}-bit ICV` : '?', fr.tier, fr.confidence)}
      {psRow('Traffic inside', t.traffic?.label ? `${t.traffic.label}` : '?', t.traffic?.tier, t.traffic?.confidence)}
      {psRow('PFS on rekey', t.pfs ? `${t.pfs.state}${t.pfs.group_guess && t.pfs.state === 'on' ? ` · ${t.pfs.group_guess.split(' - ')[0]}` : ''}` : '?', t.pfs?.tier, t.pfs?.confidence)}
      {psRow('Anti-replay', t.replay ? (t.replay.duplicates ? `${t.replay.duplicates} duplicate seq!` : t.replay.decreasing ? `${t.replay.decreasing} decreasing seq!` : 'sequence monotonic') : '?', t.replay?.tier)}
      {psRow('Rekeys', `${t.rekey_count || 0}${t.lifetimes?.length ? ` · lifetime ~${Math.round(Math.max(...t.lifetimes))} s` : ''}`, 'Observed')}
      {ike && psRow('Negotiated by', `IKEv${ike.version} ${ike.encr_label} / ${ike.dh}${ike.pqc_hybrid ? ' + PQC' : ''}`, 'Observed')}
    </div>
  );
}

function IkeCard({ i }) {
  const flags = [];
  if (i.version === 1) flags.push([`IKEv1 ${i.v1_mode || ''}`, i.v1_mode === 'aggressive' ? 'bad' : 'warn']);
  if (i.id_plaintext) flags.push(['ID in cleartext', 'bad']);
  if (i.auth?.psk) flags.push(['PSK', 'warn']);
  if (i.pqc_hybrid) flags.push([`PQC hybrid ${(i.pqc_groups || []).join('+')}`, 'good']);
  if (i.nat_t) flags.push(['NAT-T', '']);
  if (i.fragmentation) flags.push(['fragmentation', '']);
  if (i.mobike) flags.push(['MOBIKE', '']);
  if (i.cookie_challenge) flags.push(['cookie challenge', '']);
  if (!i.complete) flags.push(['incomplete', 'warn']);
  return (
    <div className="tun">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <b><span className={`vbadge v${i.version}`}>IKEv{i.version}</span> {i.initiator} → {i.responder}</b>
        <span className="small muted">{i.messages} msgs · {i.duration}s</span>
      </div>
      <div className="small" style={{ margin: '6px 0' }}>
        <span className="chip">ENCR {i.encr_label}</span>{i.prf && <span className="chip">PRF {i.prf}</span>}{i.integ && <span className="chip">INTEG {i.integ}</span>}<span className="chip">DH {i.dh}{i.dh_bits ? ` (${i.dh_bits}-bit sec.)` : ''}</span>
        {i.auth && <span className="chip">AUTH {i.auth.method}</span>}
      </div>
      <div>{flags.map(([f, c]) => <span key={f} className={`flag ${c}`}>{f}</span>)}</div>
      {i.pfs && <div className="mini" style={{ marginTop: 4 }}>Child SA PFS: {i.pfs.state} ({i.pfs.tier}{i.pfs.confidence ? ` ${Math.round(i.pfs.confidence * 100)}%` : ''})</div>}
    </div>
  );
}

function Assessment({ snap, alerts }) {
  const [open, setOpen] = useState(null);
  if (!snap) return <div className="card"><h2>Live assessment</h2><div className="muted small">The first assessment appears about two seconds after the first IPsec packet.</div></div>;
  const a = snap.assessment;
  const findings = (a.findings || []).filter((f) => f.severity !== 'info').sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity]).slice(0, 10);
  const sevCount = a.counts || {};
  return (
    <div className="card">
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ marginBottom: 2 }}>Live assessment</h2>
          <div className="small muted">{a.profile_label} · {snap.capture.tunnel_count} tunnel{snap.capture.tunnel_count === 1 ? '' : 's'}, {snap.capture.ike_sa_count} IKE SA{snap.capture.ike_sa_count === 1 ? '' : 's'} · recomputed in {snap.computed_in_ms} ms</div>
          <div style={{ marginTop: 8 }}>
            <span className={`risk ${a.risk_level?.toLowerCase()}`}>risk {a.risk_level} ({a.risk_score})</span>
            {['critical', 'high', 'medium', 'low'].map((s) => sevCount[s] ? <span key={s} className={`sev ${s}`} style={{ marginLeft: 4 }}>{sevCount[s]} {s}</span> : null)}
          </div>
        </div>
        <Gauge score={a.score} grade={a.grade} size={150} />
      </div>
      <TierBar tiers={a.tiers} />
      <h3>Score by domain</h3>
      <DomainBars domains={a.domains} />
      <h3>Findings ({findings.length} shown of {(a.findings || []).length})</h3>
      {!findings.length && <div className="ok small">No weaknesses found so far in this profile.</div>}
      {findings.map((f) => (
        <div key={f.id + f.subject} className="finding" onClick={() => setOpen(open === f.id + f.subject ? null : f.id + f.subject)}>
          <div className="row" style={{ gap: 8 }}><Sev s={f.severity} /><b>{f.id}</b> {f.title} <span className="muted small">— {f.subject}</span> <span style={{ flex: 1 }} /><Tier t={f.tier} conf={f.confidence} /></div>
          {open === f.id + f.subject && <div className="small" style={{ marginTop: 6 }}><div>{f.message}</div><div className="ok" style={{ marginTop: 4 }}>Fix: {f.fix}</div><div className="muted">{f.ref}</div></div>}
        </div>
      ))}
    </div>
  );
}

function AlertsFeed({ alerts }) {
  return (
    <div className="card">
      <h2>Alerts <span className="small muted">({alerts.length})</span></h2>
      <div className="alerts">
        {!alerts.length && <div className="muted small">Nothing yet. Alerts appear when a tunnel or IKE SA shows up and when a new weakness is detected.</div>}
        {alerts.slice(0, 80).map((al, i) => (
          <div key={`${al.ts}-${i}`} className={`alert ${al.severity}`}>
            <div className="row" style={{ gap: 8 }}><span className="mono small muted">{fmtClock(al.ts)}</span><Sev s={al.severity} /><b>{al.id}</b></div>
            <div>{al.title}{al.subject ? <span className="muted small"> — {al.subject}</span> : null}</div>
            {al.fix && <div className="mini ok">Fix: {al.fix}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ page
export default function Live({ profile, setProfile, profiles, navigate }) {
  const { rowsRef, tick, connected, status, stats, snapshot, alerts, dropped, setStatus } = useLiveStream();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [mtab, setMtab] = useState('packets');
  const running = !!status?.running;
  const a = snapshot?.assessment;
  const crit = alerts.filter((x) => x.severity === 'critical' || x.severity === 'high').length;
  const src = stats?.source || status?.source;
  const pktTotal = stats?.packets ?? status?.packets ?? 0;
  const [showCtl, setShowCtl] = useState(true);
  useEffect(() => { if (running && window.innerWidth < 760) setShowCtl(false); if (!running) setShowCtl(true); }, [running]);
  const pickTab = (k) => { setMtab(k); const el = document.querySelector('.live-grid'); if (el && window.innerWidth < 760) window.scrollTo({ top: el.offsetTop - 58, behavior: 'smooth' }); };
  const srcLabel = !src ? 'no source' : src.kind === 'replay' ? `replay ${src.file} @${src.speed}× ${Math.round((src.progress || 0) * 100)}%` : src.kind === 'interface' ? `interface ${src.iface}` : `agent ${src.agent} on ${src.iface}`;
  const ikeByRef = useMemo(() => Object.fromEntries((snapshot?.ike || []).map((i) => [i.spi_i, i])), [snapshot]);
  useEffect(() => { document.title = running ? `● LIVE ${a ? a.grade : ''} — IPsec X-Ray` : 'IPsec X-Ray — live'; }, [running, a?.grade]);

  return (
    <div className="live">
      <div className={`livebar ${running ? 'on' : ''}`}>
        <span className={`ldot ${running ? 'on' : ''}`} />
        <b>{running ? 'LIVE' : 'STOPPED'}</b>
        <span className="small">{srcLabel}</span>
        {src?.kind === 'replay' && running && <span className="prog"><span style={{ width: `${Math.round((src.progress || 0) * 100)}%` }} /></span>}
        <span style={{ flex: 1 }} />
        <span className="small">{fmtNum(pktTotal)} pkts</span>
        <span className="small">{fmtNum(stats?.pps || 0)} pkt/s</span>
        <span className="small">{fmtRate(stats?.bps || 0)}</span>
        <span className="small" title="WebSocket to the analysis server">{connected ? '⚡ stream on' : '… reconnecting'}</span>
        <button className="btn ctl-toggle" onClick={() => setShowCtl(!showCtl)}>{showCtl ? 'hide controls' : 'controls'}</button>
      </div>
      {showCtl && <SourcePanel status={status} profile={profile} setProfile={setProfile} profiles={profiles} busy={busy} setBusy={setBusy} setError={setError} navigate={navigate}
        onChanged={(r) => { if (r && r.running !== undefined) setStatus((s) => ({ ...(s || {}), ...r })); }} />}
      {error && <div className="note mt" style={{ borderColor: '#ef9a9a', background: '#ffebee', color: '#b71c1c' }}>{error}</div>}

      <div className="kpis mt live-kpis">
        <div className="kpi"><div className="l">Live grade</div><div className="v" style={{ color: a ? gradeColor(a.grade) : '#90A4AE' }}>{a ? a.grade : '—'}</div><div className="s">{a ? `${a.score} / 100 · risk ${a.risk_level}` : 'no IPsec yet'}</div></div>
        <div className="kpi"><div className="l">Tunnels</div><div className="v">{snapshot?.tunnels?.length || 0}</div><div className="s">{snapshot ? `${snapshot.capture.esp_flows} ESP + ${snapshot.capture.ah_flows} AH flows` : '—'}</div></div>
        <div className="kpi"><div className="l">IKE SAs</div><div className="v">{snapshot?.ike?.length || 0}</div><div className="s">{snapshot ? `${snapshot.capture.complete_sas} complete · ${snapshot.capture.incomplete_sas} half-open` : '—'}</div></div>
        <div className="kpi"><div className="l">Alerts</div><div className="v" style={{ color: crit ? '#C62828' : undefined }}>{alerts.filter((x) => x.severity !== 'info').length}</div><div className="s">{crit} critical/high</div></div>
        <div className="kpi"><div className="l">Evidence</div><div className="v" style={{ fontSize: 20, marginTop: 8 }}>{a ? `${a.tiers.observed_pct}% / ${a.tiers.inferred_pct}%` : '—'}</div><div className="s">observed / inferred · AI conf. {a ? `${a.ai_confidence}%` : '—'}</div></div>
      </div>

      <div className="mtabs">
        {[['packets', 'Packets'], ['vpn', 'VPN analysis'], ['alerts', `Alerts${crit ? ` (${crit})` : ''}`], ['charts', 'Charts']].map(([k, l]) => <button key={k} className={mtab === k ? 'active' : ''} onClick={() => pickTab(k)}>{l}</button>)}
      </div>

      <div className={`live-grid mt tab-${mtab}`}>
        <div className="live-main">
          <div className="pane-packets"><PacketList rowsRef={rowsRef} tick={tick} running={running} dropped={dropped} /></div>
          <div className="pane-charts card mt">
            <h2>Traffic <span className="small muted">packets per second by protocol · orange line = bit/s</span></h2>
            <div className="grid2" style={{ gridTemplateColumns: '2fr 1fr', alignItems: 'center' }}>
              <RateChart buckets={stats?.buckets} />
              <Donut counts={stats?.counts} />
            </div>
          </div>
        </div>
        <div className="live-side">
          <div className="pane-vpn">
            <Assessment snap={snapshot} alerts={alerts} />
            <div className="card mt">
              <h2>Tunnels <span className="small muted">(ESP / AH data plane)</span></h2>
              {!(snapshot?.tunnels || []).length && <div className="muted small">No ESP/AH tunnel yet.</div>}
              {(snapshot?.tunnels || []).map((t, i) => <TunnelCard key={i} t={t} ike={ikeByRef[t.ike_ref]} />)}
            </div>
            <div className="card mt">
              <h2>IKE security associations <span className="small muted">(control plane)</span></h2>
              {!(snapshot?.ike || []).length && <div className="muted small">No IKE handshake seen yet.</div>}
              {(snapshot?.ike || []).map((i) => <IkeCard key={i.spi_i} i={i} />)}
            </div>
          </div>
          <div className="pane-alerts mt"><AlertsFeed alerts={alerts} /></div>
        </div>
      </div>
    </div>
  );
}
