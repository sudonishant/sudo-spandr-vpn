import React, { useEffect, useRef, useState } from 'react';
import { api, fmtBytes, gradeColor } from '../api.js';

function Pipeline() {
  const steps = [
    ['PCAP', 'tcpdump / Wireshark', '#607D8B'],
    ['Parse', 'IKEv1 · IKEv2 · ESP · AH', '#1F4E79'],
    ['Infer', 'length physics + ML', '#EF6C00'],
    ['Assess', '66 checks · 4 profiles', '#0070C0'],
    ['Report', 'score · risk · PDF', '#2E7D32'],
  ];
  const w = 96, gap = 14;
  return (
    <svg width="100%" viewBox={`0 0 ${steps.length * (w + gap)} 74`} style={{ maxWidth: 560 }}>
      {steps.map(([t, sub, c], i) => {
        const x = i * (w + gap);
        return (
          <g key={t}>
            <rect x={x} y={8} width={w} height={50} rx={9} fill={c} />
            <text x={x + w / 2} y={30} textAnchor="middle" fill="#fff" fontSize="13" fontWeight="700">{t}</text>
            <text x={x + w / 2} y={46} textAnchor="middle" fill="#fff" fontSize="8.5" opacity=".92">{sub}</text>
            {i < steps.length - 1 && <path d={`M${x + w + 2},33 l${gap - 4},0 m-4,-4 l4,4 l-4,4`} stroke="#90A4AE" strokeWidth="2" fill="none" />}
          </g>
        );
      })}
    </svg>
  );
}

export default function Home({ profile, setProfile, profiles, navigate }) {
  const [samples, setSamples] = useState([]);
  const [results, setResults] = useState([]);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const [over, setOver] = useState(false);
  const fileRef = useRef();

  const refresh = () => api.results().then(setResults).catch(() => {});
  useEffect(() => { api.samples().then(setSamples).catch((e) => setErr(String(e))); refresh(); }, []);

  const runSample = async (name) => {
    setBusy(name); setErr(null);
    try { const r = await api.analyzeSample(name, profile); navigate(`/result/${r.id}`); } catch (e) { setErr(String(e.message || e)); } finally { setBusy(null); }
  };
  const upload = async (file) => {
    if (!file) return;
    setBusy(file.name); setErr(null);
    try { const r = await api.analyzeUpload(file, profile); navigate(`/result/${r.id}`); } catch (e) { setErr(String(e.message || e)); } finally { setBusy(null); }
  };
  const remove = async (id) => { await api.remove(id); refresh(); };

  return (
    <div>
      <div className="hero">
        <div>
          <h1>IPsec X-Ray</h1>
          <p>Passive, AI-assisted analysis of IPsec VPN traffic. Upload a PCAP (or pick a scenario) and get the negotiated IKE parameters,
            the <em>hidden</em> ESP properties inferred from packet-length physics, a standards-based security score (RFC 8221/8247, NIST SP 800-77, CNSA 2.0),
            a threat matrix and executive / technical reports — without keys, decryption or injection.</p>
          <div>
            <span className="pill">IKEv1 · IKEv2 · ESP · AH · NAT-T · IPv6</span>
            <span className="pill">66 checks · 4 profiles</span>
            <span className="pill">Observed / Inferred / Unknown evidence tiers</span>
          </div>
        </div>
        <div style={{ minWidth: 220, textAlign: 'right' }}>
          <div className="small" style={{ opacity: .85, marginBottom: 6 }}>Assessment profile</div>
          <select value={profile} onChange={(e) => setProfile(e.target.value)} style={{ minWidth: 220 }}>
            {Object.entries(profiles).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
          <div className="small" style={{ opacity: .8, marginTop: 8, maxWidth: 260 }}>{profiles[profile]?.description}</div>
        </div>
      </div>

      {err && <div className="note" style={{ marginBottom: 14, background: '#FFEBEE', borderColor: '#EF9A9A', color: '#B71C1C' }}>Error: {err}</div>}

      <div className="grid2">
        <div className="card">
          <h2>Analyze a capture</h2>
          <div className={`drop ${over ? 'over' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
            onDrop={(e) => { e.preventDefault(); setOver(false); upload(e.dataTransfer.files[0]); }}
            onClick={() => fileRef.current.click()}>
            <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" style={{ display: 'none' }} onChange={(e) => upload(e.target.files[0])} />
            {busy ? <span><span className="spinner" /> Analyzing <b>{busy}</b> …</span>
              : <span><b>Drop a .pcap / .pcapng here</b> or click to choose<br /><span className="muted small">IKE on UDP 500/4500, ESP (IP proto 50 or UDP 4500), AH (proto 51). Up to 200 MB.</span></span>}
          </div>
          <div className="small muted mt">Capture tips: <code>tcpdump -i eth0 -w vpn.pcap 'udp port 500 or udp port 4500 or esp or ah'</code>. Include at least one Child-SA rekey to determine PFS.</div>
          <h3>How a capture becomes a score</h3>
          <Pipeline />
          <h3>What you get back</h3>
          <ul className="small" style={{ margin: '0 0 0 16px', padding: 0, lineHeight: 1.6 }}>
            <li><b>Observed</b> facts read from cleartext IKE: version, mode, ciphers, DH group, PQC hybrid, auth method, vendor IDs, leaked identities.</li>
            <li><b>Inferred</b> ESP properties with confidence: cipher framing, tunnel/transport, application inside, PFS, TFC padding, leak meter.</li>
            <li><b>Unknown</b> fields honestly marked (ESN, AES key length, replay window) — never penalised, always recommended.</li>
            <li>Security score, grade, risk score, threat matrix, prioritised fixes, executive & technical reports (HTML / PDF / JSON).</li>
          </ul>
        </div>

        <div className="card">
          <h2>Scenario captures (built-in testbed)</h2>
          <table>
            <thead><tr><th>Scenario</th><th>Expected</th><th></th></tr></thead>
            <tbody>
              {samples.map((s) => (
                <tr key={s.name}>
                  <td><b>{s.name}</b><div className="small muted">{s.description}</div>
                    <div className="small muted">IKEv{s.ike_version} · {s.esp} · {s.mode} · {s.traffic} · PFS {s.pfs} · {fmtBytes(s.size_bytes)} · <a href={api.sampleUrl(s.name)}>download</a></div></td>
                  <td style={{ whiteSpace: 'nowrap' }}>{s.expected_grade.map((g) => <span key={g} style={{ color: gradeColor(g), fontWeight: 700, marginRight: 4 }}>{g}</span>)}</td>
                  <td><button className="btn primary" disabled={!!busy} onClick={() => runSample(s.name)}>{busy === s.name ? <span className="spinner" /> : 'Analyze'}</button></td>
                </tr>
              ))}
              {!samples.length && <tr><td colSpan={3} className="muted">No samples found — run <code>python -m ipsec_xray.testbed.generate</code>.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card mt">
        <h2>Recent results</h2>
        <table>
          <thead><tr><th>Capture</th><th>Profile</th><th>Score</th><th>Grade</th><th>Risk</th><th>IKE</th><th>ESP</th><th>Traffic</th><th>Findings</th><th>When</th><th></th></tr></thead>
          <tbody>
            {results.map((r) => (
              <tr key={r.id} className="click" onClick={() => navigate(`/result/${r.id}`)}>
                <td><b>{r.name}</b></td><td>{r.profile}</td><td>{r.score}</td>
                <td style={{ color: gradeColor(r.grade), fontWeight: 800, fontSize: 16 }}>{r.grade}</td>
                <td>{r.risk}</td>
                <td className="small">{r.summary?.primary_ike}</td><td className="small">{(r.summary?.primary_esp || '').split(' (')[0]}</td><td className="small">{r.summary?.primary_traffic}</td>
                <td className="small">{r.summary?.counts ? `${r.summary.counts.critical}C ${r.summary.counts.high}H ${r.summary.counts.medium}M ${r.summary.counts.low}L` : ''}</td>
                <td className="small muted">{r.created?.replace('T', ' ')}</td>
                <td><button className="btn danger" onClick={(e) => { e.stopPropagation(); remove(r.id); }}>✕</button></td>
              </tr>
            ))}
            {!results.length && <tr><td colSpan={11} className="muted">Nothing analyzed yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
