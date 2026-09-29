import React, { useEffect, useMemo, useState } from 'react';
import { api, gradeColor, riskColor } from '../api.js';
import { DomainBars, Fact, Gauge, Hist, Sev, ThreatMatrix, Tier, TierBar } from './Widgets.jsx';

const TABS = ['Findings', 'Hidden fields (ESP)', 'IKE negotiation', 'Threat matrix', 'Checks', 'JSON'];

export default function Result({ id, profile, setProfile, profiles, navigate }) {
  const [r, setR] = useState(null);
  const [err, setErr] = useState(null);
  const [tab, setTab] = useState(TABS[0]);
  const [sevFilter, setSevFilter] = useState('all');
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.result(id).then((x) => { setR(x); if (x.profile) setProfile(x.profile); }).catch((e) => setErr(String(e.message || e))); }, [id]);

  const changeProfile = async (p) => {
    setBusy(true);
    try { const x = await api.reassess(id, p); setR(x); setProfile(p); } finally { setBusy(false); }
  };

  const a = r?.assessment, f = r?.facts;
  const findings = useMemo(() => (a ? a.findings.filter((x) => sevFilter === 'all' ? true : sevFilter === 'actionable' ? x.severity !== 'info' : x.severity === sevFilter) : []), [a, sevFilter]);

  if (err) return <div className="note">Error: {err}</div>;
  if (!r) return <div className="card"><span className="spinner" /> loading…</div>;

  const truth = r.ground_truth;
  const ikeMain = f.ike.filter((i) => i.complete);
  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <div>
          <a href="#/analyze" onClick={(e) => { e.preventDefault(); navigate('/analyze'); }}>← all results</a>
          <h1 style={{ margin: '4px 0 2px', fontSize: 22, color: 'var(--navy)' }}>{r.name}</h1>
          <div className="small muted">{f.capture.packets} packets · {f.capture.duration} s · {f.capture.ike_sa_count} IKE SA · {f.capture.tunnel_count} tunnel(s) · {f.capture.ipv6 ? 'IPv6 ' : ''}{f.capture.ipv4 ? 'IPv4' : ''} · analyzed in {r.timing.total_s} s · {r.created.replace('T', ' ')}</div>
        </div>
        <div className="row">
          <label className="small muted">Profile</label>
          <select value={r.profile} disabled={busy} onChange={(e) => changeProfile(e.target.value)}>
            {Object.entries(profiles).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
          <a className="btn" href={api.reportUrl(id, 'html', 'executive')} target="_blank" rel="noreferrer">Executive HTML</a>
          <a className="btn" href={api.reportUrl(id, 'pdf', 'executive')} target="_blank" rel="noreferrer">Executive PDF</a>
          <a className="btn" href={api.reportUrl(id, 'html', 'technical')} target="_blank" rel="noreferrer">Technical HTML</a>
          <a className="btn primary" href={api.reportUrl(id, 'pdf', 'technical')} target="_blank" rel="noreferrer">Technical PDF</a>
          <a className="btn" href={api.reportUrl(id, 'json')}>JSON</a>
        </div>
      </div>

      <div className="kpis">
        <div className="kpi" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Gauge score={a.score} grade={a.grade} size={190} /></div>
        <div className="kpi"><div className="l">Security score</div><div className="v" style={{ color: gradeColor(a.grade) }}>{a.score}<span className="small muted"> /100</span></div>
          <div className="s">Grade <b style={{ color: gradeColor(a.grade) }}>{a.grade}</b>{a.grade_cap && <span> · capped by {a.grade_cap.reason.join(', ')}</span>}</div>
          <div className="s">{a.profile_label}</div></div>
        <div className="kpi"><div className="l">Risk score</div><div className="v" style={{ color: riskColor(a.risk_score) }}>{a.risk_score}</div><div className="s">{a.risk_level} exposure (severity-weighted, confidence-scaled)</div></div>
        <div className="kpi"><div className="l">AI confidence</div><div className="v">{a.ai_confidence}%</div><div className="s">mean confidence of inferred fields</div>
          <div style={{ marginTop: 6 }}><TierBar tiers={a.tiers} /></div></div>
        <div className="kpi"><div className="l">Findings</div><div className="v">{a.counts.critical + a.counts.high + a.counts.medium + a.counts.low}</div>
          <div className="s"><Sev s="critical" /> {a.counts.critical} &nbsp; <Sev s="high" /> {a.counts.high}</div>
          <div className="s" style={{ marginTop: 4 }}><Sev s="medium" /> {a.counts.medium} &nbsp; <Sev s="low" /> {a.counts.low} &nbsp; <span className="muted">{a.counts.info} info · {a.counts.pass} pass</span></div></div>
      </div>

      {truth && (
        <div className="truth mt"><b>Testbed ground truth:</b> {truth.ike} · ESP {truth.esp} ({truth.esp_framing}) · {truth.mode} mode · traffic {truth.traffic} · PFS {truth.pfs} · expected grade {truth.expected_grade.join('/')}
          {' '}→ <b>inferred:</b> {f.summary.primary_esp.split(' (')[0]} · {f.summary.primary_mode} · {f.summary.primary_traffic} · PFS {f.summary.pfs} · grade <b>{a.grade}</b></div>
      )}

      <div className="grid2 mt">
        <div className="card">
          <h2>Score breakdown</h2>
          <DomainBars domains={a.domains} />
        </div>
        <div className="card">
          <h2>Priority actions</h2>
          {a.top_actions.length ? (
            <ol style={{ margin: 0, paddingLeft: 18 }}>
              {a.top_actions.map((t) => <li key={t.id} style={{ marginBottom: 7 }}><Sev s={t.severity} /> <b>{t.id}</b> {t.title}<div className="small" style={{ color: '#1b5e20' }}>{t.fix}</div></li>)}
            </ol>
          ) : <div className="ok">No corrective actions required under this profile.</div>}
        </div>
      </div>

      <div className="tabs">{TABS.map((t) => <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>{t}</button>)}</div>

      {tab === 'Findings' && (
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <span className="small muted">Show:</span>
            {['all', 'actionable', 'critical', 'high', 'medium', 'low', 'info'].map((s) => <button key={s} className={`btn ${sevFilter === s ? 'primary' : ''}`} onClick={() => setSevFilter(s)}>{s}</button>)}
            <span className="small muted" style={{ marginLeft: 'auto' }}>{findings.length} of {a.findings.length}</span>
          </div>
          <table>
            <thead><tr><th>Severity</th><th>Check</th><th>Subject</th><th>Evidence</th><th>Detail & fix</th></tr></thead>
            <tbody>
              {findings.map((x, i) => (
                <tr key={i}>
                  <td><Sev s={x.severity} /></td>
                  <td><b>{x.id}</b><div>{x.title}</div><div className="small muted">{x.ref}</div></td>
                  <td className="small">{x.subject}</td>
                  <td><Tier t={x.tier} conf={x.confidence} />{x.penalty > 0 && <div className="small muted">−{x.penalty} pts</div>}</td>
                  <td>{x.message}<div className="small" style={{ color: '#1b5e20', marginTop: 3 }}>Fix: {x.fix}</div>{x.threat?.length > 0 && <div className="small muted">threats: {x.threat.join(', ')}</div>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'Hidden fields (ESP)' && (
        <div>
          {f.tunnels.map((t, k) => <TunnelCard key={k} t={t} />)}
          {!f.tunnels.length && <div className="card muted">No ESP/AH tunnels in this capture.</div>}
        </div>
      )}

      {tab === 'IKE negotiation' && (
        <div>
          {ikeMain.map((i) => <IkeCard key={i.spi_i} i={i} />)}
          {f.capture.incomplete_sas > 0 && <div className="note mt">{f.capture.incomplete_sas} incomplete IKE SA(s) (IKE_SA_INIT without IKE_AUTH) from {f.capture.incomplete_sources} source(s) — {f.capture.cookie_seen ? 'responder answered with COOKIE challenges' : 'no COOKIE challenge seen'}. Summarised as a flood indicator (ANOM-001).</div>}
          {!ikeMain.length && <div className="card muted">No complete IKE negotiation in the capture window.</div>}
          {Object.keys(f.capture.cleartext_between_peers || {}).length > 0 && <div className="card mt"><h2>Cleartext traffic between the IPsec peers</h2>{Object.entries(f.capture.cleartext_between_peers).map(([k, v]) => <span className="chip" key={k}>{k} × {v}</span>)}<div className="small muted">Traffic beside the tunnel bypasses the policy — verify the SPD.</div></div>}
        </div>
      )}

      {tab === 'Threat matrix' && (
        <div className="grid2">
          <div className="card"><h2>Likelihood × impact</h2><ThreatMatrix threats={a.threats} /></div>
          <div className="card"><h2>Threats</h2>
            <table><thead><tr><th>ID</th><th>Threat</th><th>L</th><th>I</th><th>Level</th><th>Triggered by</th></tr></thead>
              <tbody>{a.threats.map((t) => <tr key={t.id}><td>{t.id}</td><td><b>{t.title}</b><div className="small muted">{t.actor} — {t.description}</div></td><td>{t.likelihood}</td><td>{t.impact}</td><td className={t.level === 'Critical' || t.level === 'High' ? 'bad' : ''}>{t.level}</td><td className="small">{t.triggered_by.join(', ') || '—'}</td></tr>)}</tbody></table>
          </div>
        </div>
      )}

      {tab === 'Checks' && (
        <div className="card">
          <h2>Check catalogue — {a.checks_total} checks under {a.profile_label}</h2>
          <table><thead><tr><th>ID</th><th>Check</th><th>Scope</th><th>Severity</th><th>Status</th></tr></thead>
            <tbody>{a.check_results.map((c) => (
              <tr key={c.id}><td><b>{c.id}</b></td><td>{c.title}<div className="small muted">{c.ref}</div></td><td>{c.scope}</td><td>{c.severity !== 'none' ? <Sev s={c.severity} /> : <span className="muted">n/a</span>}</td>
                <td>{c.status === 'fail' ? <span className="bad">FAIL ({c.count})</span> : c.status === 'info' ? <span style={{ color: 'var(--amber)', fontWeight: 600 }}>INFO</span> : c.status === 'na' ? <span className="muted">not applicable</span> : <span className="ok">pass</span>}</td></tr>
            ))}</tbody></table>
        </div>
      )}

      {tab === 'JSON' && <div className="card"><pre className="json">{JSON.stringify({ ...r, facts: { ...f, ike: f.ike.map((i) => ({ ...i, exchange_log: `[${i.exchange_log?.length || 0} entries]` })) } }, null, 2)}</pre></div>}
    </div>
  );
}

function TunnelCard({ t }) {
  const fr = t.framing;
  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <h2>{t.protocol} tunnel {t.peers[0]} ↔ {t.peers[1]} <span className="small muted" style={{ fontWeight: 400 }}>— {t.packets} packets · {t.bytes} bytes · {t.duration} s{t.udp_encap ? ' · UDP-encapsulated' : ''}{t.ipver === 6 ? ' · IPv6' : ''}</span></h2>
      <div className="grid2">
        <div>
          <Fact k="Cipher framing" v={<div><b>{fr.label}</b><div className="small muted">IV {fr.iv ?? '-'} + ICV {fr.icv} B · block {fr.block} B · integrity {fr.integ_bits} bits{fr.physics?.confidence != null && <> · physics {fr.physics.confidence} · ML {Object.entries(fr.ml || {}).slice(0, 1).map(([k, v]) => `${k}=${v}`).join('')}</>}</div><div className="small muted">{fr.note}</div></div>} tier={fr.tier} conf={fr.confidence} />
          <Fact k="Encapsulation mode" v={<div><b>{t.mode.value}</b> {(t.mode.physics?.tunnel != null || t.mode.ml?.tunnel != null) && <span className="small muted">(physics {t.mode.physics?.tunnel != null ? `tunnel ${t.mode.physics.tunnel}` : '—'}{t.mode.ml?.tunnel != null ? ` · ML tunnel ${t.mode.ml.tunnel}` : ''})</span>}{t.mode.evidence && <div className="small" style={{ color: 'var(--green)' }}>{t.mode.evidence}</div>}</div>} tier={t.mode.tier} conf={t.mode.confidence} />
          <Fact k="Traffic inside" v={<div><b>{t.traffic.label}</b>{t.traffic.top?.length > 0 && <div style={{ marginTop: 4 }}>{t.traffic.top.map((c) => <span className="chip" key={c.class} title={c.label}>{c.label.split(' (')[0]} <b>{Math.round(c.p * 100)}%</b></span>)}</div>}{t.cleartext_inner ? <div className="small" style={{ color: 'var(--red)' }}>Inner IP packets decoded from {t.cleartext_inner.packets} NULL-encrypted ESP packets — anyone on the path sees this traffic.</div> : t.traffic.tier !== 'Observed' && <div className="small muted">RandomForest over 37 flow features (sizes, timing, direction ratios); indicator, not proof.</div>}</div>} tier={t.traffic.tier} conf={t.traffic.confidence} />
          <Fact k="Perfect forward secrecy" v={<div><b>{t.pfs.state}</b>{t.pfs.group_guess && <span> — {t.pfs.group_guess}</span>}<div className="small muted">{t.pfs.evidence}</div></div>} tier={t.pfs.tier} conf={t.pfs.confidence} />
          <Fact k="Anti-replay sequence" v={<div>{t.replay.monotonic ? <span className="ok">monotonic</span> : <span className="bad">anomalous</span>} <span className="small muted">duplicates {t.replay.duplicates} · decreases {t.replay.decreasing} · gaps {t.replay.gaps} · max seq {t.replay.seq_max}</span></div>} tier="Observed" />
          <Fact k="Rekeys / lifetimes" v={<div>{t.rekey_count} rekey(s){t.lifetimes.length > 0 && <span className="small muted"> · intervals {t.lifetimes.join(', ')} s</span>}</div>} tier="Observed" />
          <Fact k="Metadata leak meter" v={<div><div className="bar" style={{ maxWidth: 220, display: 'inline-block', width: 220, verticalAlign: 'middle' }}><span style={{ width: `${t.leak_score}%`, background: t.leak_score > 70 ? '#C62828' : '#EF6C00' }} /></div> <b>{t.leak_score}</b>/100 <div className="small muted">size diversity {t.size_diversity} · TFC padding {t.tfc_padding_likely ? 'likely' : 'not seen'}</div></div>} tier="Inferred" conf={t.traffic.confidence} />
          <Fact k="ESN · AES key length · replay window" v={<span className="muted">never transmitted — cannot be determined passively</span>} tier="Unknown" />
        </div>
        <div>
          <h3 style={{ marginTop: 0 }}>Framing candidates (Bayesian posterior over length residues)</h3>
          <div className="cands">
            {(fr.candidates || []).slice(0, 6).map((c) => <div className="r" key={c.key}><div><div className="bar"><span style={{ width: `${100 * c.posterior}%`, background: c.key === fr.lead_key ? '#2E7D32' : '#90A4AE' }} /></div><div className="small">{c.label} <span className="muted">(o={c.overhead}, b={c.block}, fit {Math.round(c.fit * 100)}%)</span></div></div><div className="small" style={{ textAlign: 'right' }}>{(100 * c.posterior).toFixed(1)}%</div></div>)}
            {fr.family === 'ah' && <div className="small muted">AH: ICV length is read directly from the header.</div>}
          </div>
          {fr.physics?.residues_mod16 && <div className="small muted mt">length residues mod 16: {Object.entries(fr.physics.residues_mod16).map(([k, v]) => `${k}:${v}`).join(' · ')}{fr.entropy?.mean_entropy != null && <> · payload entropy {fr.entropy.mean_entropy} (norm.) · IP-header-like first byte {Math.round(100 * fr.entropy.ip_header_like)}%</>}</div>}
          <h3>Flows</h3>
          <table><thead><tr><th>Direction</th><th>SPI</th><th>Pkts</th><th>Bytes</th><th>Len</th><th>Seq</th></tr></thead>
            <tbody>{t.flows.map((fl) => <tr key={fl.spi + fl.src}><td className="small">{fl.src} → {fl.dst}</td><td><code>{fl.spi}</code></td><td>{fl.packets}</td><td>{fl.bytes}</td><td className="small">{fl.len_min}–{fl.len_max}</td><td className="small">{fl.seq.min}..{fl.seq.max}{fl.seq.duplicates ? <span className="bad"> dup {fl.seq.duplicates}</span> : ''}{fl.seq.reorders ? <span className="bad"> dec {fl.seq.reorders}</span> : ''}</td></tr>)}</tbody></table>
          {t.flows[0]?.len_hist && <div className="mt"><Hist hist={t.flows[0].len_hist} /></div>}
        </div>
      </div>
    </div>
  );
}

function IkeCard({ i }) {
  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <h2>IKEv{i.version} {i.initiator} → {i.responder} <span className="small muted" style={{ fontWeight: 400 }}>— {i.v1_mode ? `${i.v1_mode} mode · ` : ''}ports {i.ports.join('/')} · {i.messages} messages · {i.duration} s · SPIi {i.spi_i}</span></h2>
      <div className="grid2">
        <div>
          <Fact k="Encryption" v={<b>{i.encr_label}{i.encr_aead ? ' (AEAD)' : ''}</b>} tier="Observed" />
          <Fact k="PRF / integrity" v={`${i.prf || '-'} / ${i.integ || (i.encr_aead ? 'none (AEAD)' : '-')}`} tier="Observed" />
          <Fact k="Key exchange" v={<div><b>{i.dh}</b> <span className="small muted">{i.dh_bits}-bit security · RFC 8247 {i.dh_status}{i.ke_len ? ` · KE payload ${i.ke_len} B` : ''}</span>{i.pqc_hybrid && <div style={{ color: 'var(--green)', fontWeight: 600 }}>+ post-quantum hybrid: {i.pqc_groups.join(', ')}</div>}{i.add_ke?.length > 0 && <div className="small muted">additional KE: {i.add_ke.map((k) => `${k.name} (${k.len} B)`).join(', ')}</div>}</div>} tier="Observed" />
          <Fact k="Authentication" v={<div>{i.auth.method || <span className="muted">not visible (encrypted IKE_AUTH)</span>}<div className="small muted">{i.auth.evidence || i.auth.note}</div></div>} tier={i.auth.tier} conf={i.auth.confidence} />
          <Fact k="PFS (from rekeys)" v={<div><b>{i.pfs.state}</b>{i.pfs.group_guess ? ` — ${i.pfs.group_guess}` : ''}<div className="small muted">{i.pfs.evidence}</div></div>} tier={i.pfs.tier} conf={i.pfs.confidence} />
          {i.lifetime_seconds && <Fact k="IKE lifetime" v={`${i.lifetime_seconds} s`} tier="Observed" />}
          <Fact k="NAT traversal" v={i.nat_t ? 'in use (UDP 4500)' : i.natt_capable ? 'capable, not used' : 'no'} tier="Observed" />
          <Fact k="Capabilities" v={(() => { const caps = [i.fragmentation && 'fragmentation', i.mobike && 'MOBIKE', i.redirect && 'redirect', i.cookie_challenge && 'cookie challenge', i.intermediate > 0 && 'IKE_INTERMEDIATE', i.certreq_seen && 'CERTREQ', i.cert_seen && 'CERT'].filter(Boolean); return <div>{caps.map((x) => <span className="chip" key={x}>{x}</span>)}{i.sig_hash_algs?.length > 0 && <span className="chip">sig hashes {i.sig_hash_algs.join(',')}</span>}{!caps.length && !i.sig_hash_algs?.length && <span className="muted">none advertised</span>}</div>; })()} tier="Observed" />
        </div>
        <div>
          <h3 style={{ marginTop: 0 }}>Offered proposals ({i.offered_count}) → chosen</h3>
          {i.offered.map((p, k) => <div key={k} className="small" style={{ marginBottom: 4 }}><code>{p}</code></div>)}
          {i.chosen?.summary && <div className="small mt">chosen: <code style={{ background: '#E8F5E9' }}>{i.chosen.summary}</code></div>}
          {i.weak_offered.length > 0 && <div className="small bad mt">weak transforms offered: {i.weak_offered.join(', ')}</div>}
          <h3>Notifications</h3>
          <div>{i.notifies.map((n) => <span className="chip" key={n}>{n}</span>)}{!i.notifies.length && <span className="muted small">none</span>}</div>
          {i.vendor_ids.length > 0 && <><h3>Vendor IDs</h3><div>{i.vendor_ids.map((v) => <span className="chip" key={v.hex} title={v.hex}>{v.vendor}</span>)}</div></>}
          {i.ids.length > 0 && <><h3 style={{ color: 'var(--red)' }}>Identities in cleartext</h3><div>{i.ids.map((x, k) => <div key={k} className="small"><b>{x.direction}</b> {x.type_name}: {x.value} <span className="muted">({x.exchange})</span></div>)}</div></>}
          <h3>Exchanges</h3>
          <div>{Object.entries(i.exchanges).map(([k, v]) => <span className="chip" key={k}>{k} × {v}</span>)}</div>
          {i.errors.length > 0 && <div className="small bad mt">error notifies: {i.errors.join(', ')}</div>}
          <details className="mt"><summary className="small muted">message log ({i.exchange_log.length})</summary>
            <table className="small"><thead><tr><th>t</th><th>exchange</th><th>dir</th><th>len</th><th>payloads</th></tr></thead>
              <tbody>{i.exchange_log.slice(0, 60).map((e, k) => <tr key={k}><td>{(e.ts - i.exchange_log[0].ts).toFixed(3)}</td><td>{e.exchange}{e.response ? ' (resp)' : ''}</td><td>{e.dir}</td><td>{e.len}</td><td className="small muted">{e.payloads.join(',')}{e.notifies.length ? ` N:${e.notifies.join(',')}` : ''}</td></tr>)}</tbody></table>
          </details>
        </div>
      </div>
    </div>
  );
}
