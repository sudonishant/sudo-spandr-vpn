import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Sev } from './Widgets.jsx';

export function ChecksPage({ profile, setProfile, profiles }) {
  const [checks, setChecks] = useState([]);
  const [threats, setThreats] = useState([]);
  const [q, setQ] = useState('');
  useEffect(() => { api.checks(profile).then(setChecks); api.threats().then(setThreats); }, [profile]);
  const fams = [...new Set(checks.map((c) => c.family))];
  const shown = checks.filter((c) => !q || `${c.id} ${c.title} ${c.ref} ${c.when}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div>
      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2 style={{ margin: 0 }}>Check catalogue — {checks.length} checks</h2>
          <div className="row">
            <input type="text" placeholder="filter…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select value={profile} onChange={(e) => setProfile(e.target.value)}>{Object.entries(profiles).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>
          </div>
        </div>
        <div className="small muted" style={{ margin: '6px 0 12px' }}>{profiles[profile]?.description} Families: {fams.map((f) => <span className="chip" key={f}>{f} × {checks.filter((c) => c.family === f).length}</span>)}</div>
        <table>
          <thead><tr><th>ID</th><th>Check</th><th>Scope</th><th>Severity</th><th>Domain</th><th>Condition (facts expression)</th><th>Reference</th><th>Threats</th></tr></thead>
          <tbody>{shown.map((c) => (
            <tr key={c.id}><td><b>{c.id}</b></td><td>{c.title}<div className="small muted">{c.fix}</div></td><td>{c.scope}</td><td>{c.severity === 'none' ? <span className="muted">n/a</span> : <Sev s={c.severity} />}</td><td>{c.domain}</td><td><code style={{ fontSize: 11 }}>{c.when}</code></td><td className="small">{c.ref}</td><td className="small">{c.threat.join(', ')}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <div className="card mt">
        <h2>Threat catalogue</h2>
        <table><thead><tr><th>ID</th><th>Threat</th><th>Actor</th><th>Impact</th><th>Base likelihood</th><th>Description</th></tr></thead>
          <tbody>{threats.map((t) => <tr key={t.id}><td><b>{t.id}</b></td><td>{t.title}</td><td>{t.actor}</td><td>{t.impact}</td><td>{t.base_likelihood}</td><td className="small">{t.description}</td></tr>)}</tbody></table>
      </div>
    </div>
  );
}

export function AboutPage({ health }) {
  const models = health?.model_meta || {};
  return (
    <div>
      <div className="card">
        <h2>How IPsec X-Ray works</h2>
        <div className="grid3">
          <div><h3>1. Parse what is visible</h3><p className="small">IKEv1/IKEv2 headers and cleartext payloads are decoded byte-exactly: SA proposals (offered and chosen), KE group and public-value length, nonces, notifications, vendor IDs, identities in aggressive mode, certificate requests. ESP and AH contribute SPI, sequence number and length. Encrypted payloads are only used through their <em>size</em>.</p></div>
          <div><h3>2. Infer what is hidden</h3><p className="small">ESP length = IV + ⌈(P+2)/block⌉·block + ICV. Length residues mod 16/8/4 identify the cipher framing (CBC, 3DES, AEAD/CTR, NULL) and anchor packets (52-byte TCP ACK, 84-byte ping, 200-byte G.711) pin the IV+ICV overhead and tunnel/transport mode. Rekey message sizes reveal PFS and the group class. Payload entropy exposes NULL encryption. A RandomForest classifies the application inside from 37 flow features.</p></div>
          <div><h3>3. Assess against standards</h3><p className="small">66 checks (RFC 8221, RFC 8247, RFC 9395, RFC 9370, NIST SP 800-77r1, CNSA 2.0) across 7 scoring domains produce a 0–100 score and grade, a severity-weighted risk score and a 12-threat likelihood×impact matrix, under 4 profiles. Every finding carries an evidence tier and confidence; inferred penalties are confidence-scaled; Unknown never penalises.</p></div>
        </div>
      </div>
      <div className="grid2 mt">
        <div className="card">
          <h2>Honest limits</h2>
          <ul className="small">
            <li>AES-128 vs AES-256, AES-GCM vs ChaCha20-Poly1305, HMAC-SHA1-96 vs HMAC-MD5-96 share identical on-wire framing → reported as one framing class.</li>
            <li>IKEv2 IKE_AUTH and CREATE_CHILD_SA are encrypted → authentication method, Child-SA proposal, USE_TRANSPORT_MODE are inferred from sizes or reported Unknown.</li>
            <li>ESN, anti-replay window and lifetimes-in-config are never transmitted → Unknown (recommendations still given).</li>
            <li>PFS needs a rekey inside the capture; small ECDH groups cannot be separated from a long proposal list by size alone.</li>
            <li>The traffic classifier ships trained on simulated flows framed with the exact ESP length model — retrain on lab captures (<code>python -m ipsec_xray.ml.train</code>) before operational use; treat its output as an indicator, not proof.</li>
          </ul>
        </div>
        <div className="card">
          <h2>Model card</h2>
          {Object.keys(models).length ? (
            <table><thead><tr><th>Model</th><th>Classes</th><th>Features</th><th>Hold-out accuracy</th></tr></thead>
              <tbody>{Object.entries(models).map(([k, m]) => <tr key={k}><td><b>{k}</b> <span className="small muted">{m.file}</span></td><td className="small">{m.classes.join(', ')}</td><td>{m.n_features}</td><td>{Math.round(m.holdout_accuracy * 100)}%</td></tr>)}</tbody></table>
          ) : <div className="muted">models not loaded</div>}
          <div className="small muted mt">Calibrated RandomForests (scikit-learn, sigmoid calibration). Hold-out numbers are on synthetic data and are optimistic by construction; the physics model carries 60% of the cipher/mode decision.</div>
        </div>
      </div>
      <div className="card mt">
        <h2>Testbed & dataset</h2>
        <p className="small">Built-in generator: <code>python -m ipsec_xray.testbed.generate</code> writes eight scenario captures with ground truth (<code>samples/manifest.json</code>). Real captures: <code>testbed/strongswan/</code> contains a docker-compose lab (two strongSwan 6 gateways + traffic generators) and <code>capture.sh</code> to record labelled PCAPs for every cipher/mode/PFS/traffic combination in the problem statement; those PCAPs are analyzed with no code changes and can be used to retrain the classifier.</p>
        <p className="small">API: <a href="/docs" target="_blank" rel="noreferrer">/docs</a> (OpenAPI). CLI: <code>python -m ipsec_xray.cli analyze capture.pcap --profile government --pdf report.pdf</code>.</p>
      </div>
    </div>
  );
}
