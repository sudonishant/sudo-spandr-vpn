import React from 'react';
import { gradeColor } from '../api.js';

export function Gauge({ score, grade, size = 170 }) {
  const cx = size / 2, cy = size * 0.58, r = size * 0.42;
  const frac = Math.max(0, Math.min(1, score / 100));
  const arc = (f0, f1) => {
    const a0 = Math.PI * (1 - f0), a1 = Math.PI * (1 - f1);
    const x0 = cx + r * Math.cos(a0), y0 = cy - r * Math.sin(a0);
    const x1 = cx + r * Math.cos(a1), y1 = cy - r * Math.sin(a1);
    return `M${x0},${y0} A${r},${r} 0 ${f1 - f0 > 0.5 ? 1 : 0} 1 ${x1},${y1}`;
  };
  const color = gradeColor(grade);
  return (
    <svg width={size} height={size * 0.7} viewBox={`0 0 ${size} ${size * 0.7}`}>
      <path d={arc(0, 1)} stroke="#e6ebf1" strokeWidth={14} fill="none" strokeLinecap="round" />
      {[0.4, 0.6, 0.75, 0.85, 0.95].map((t) => {
        const a = Math.PI * (1 - t);
        return <line key={t} x1={cx + (r - 11) * Math.cos(a)} y1={cy - (r - 11) * Math.sin(a)} x2={cx + (r + 11) * Math.cos(a)} y2={cy - (r + 11) * Math.sin(a)} stroke="#fff" strokeWidth={2} />;
      })}
      {frac > 0.005 && <path d={arc(0, frac)} stroke={color} strokeWidth={14} fill="none" strokeLinecap="round" style={{ transition: 'd .5s' }} />}
      <text x={cx} y={cy - 6} textAnchor="middle" fontSize={size * 0.22} fontWeight="800" fill={color}>{grade}</text>
      <text x={cx} y={cy + size * 0.1} textAnchor="middle" fontSize={size * 0.085} fill="#62727f">{score} / 100</text>
    </svg>
  );
}

export function Sev({ s }) { return <span className={`sev ${s}`}>{s}</span>; }
export function Tier({ t, conf }) {
  return <span className={`tier ${t}`} title="Observed = read from cleartext fields; Inferred = derived from side channels with confidence; Unknown = not recoverable passively">{t}{t === 'Inferred' && conf != null ? ` ${Math.round(conf * 100)}%` : ''}</span>;
}

export function TierBar({ tiers }) {
  if (!tiers) return null;
  return (
    <div>
      <div className="tiers">
        <span style={{ width: `${tiers.observed_pct}%`, background: '#2E7D32' }} title={`Observed ${tiers.observed_pct}%`} />
        <span style={{ width: `${tiers.inferred_pct}%`, background: '#EF6C00' }} title={`Inferred ${tiers.inferred_pct}%`} />
        <span style={{ width: `${tiers.unknown_pct}%`, background: '#90A4AE' }} title={`Unknown ${tiers.unknown_pct}%`} />
      </div>
      <div className="legend">
        <span><i style={{ background: '#2E7D32' }} />Observed {tiers.observed_pct}% ({tiers.observed})</span>
        <span><i style={{ background: '#EF6C00' }} />Inferred {tiers.inferred_pct}% ({tiers.inferred})</span>
        <span><i style={{ background: '#90A4AE' }} />Unknown {tiers.unknown_pct}% ({tiers.unknown})</span>
      </div>
    </div>
  );
}

export function DomainBars({ domains }) {
  return (
    <div>
      {Object.entries(domains).map(([k, v]) => {
        const pct = (100 * v.score) / v.cap;
        const color = pct >= 80 ? '#2E7D32' : pct >= 50 ? '#EF6C00' : '#C62828';
        return (
          <div key={k} style={{ display: 'grid', gridTemplateColumns: '210px 1fr 70px', gap: 10, alignItems: 'center', margin: '7px 0' }}>
            <div style={{ fontSize: 13 }}>{v.label}</div>
            <div className="bar"><span style={{ width: `${pct}%`, background: color }} /></div>
            <div className="small muted" style={{ textAlign: 'right' }}>{v.score} / {v.cap}</div>
          </div>
        );
      })}
    </div>
  );
}

export function ThreatMatrix({ threats }) {
  const cell = (l, i) => {
    const sc = l * i;
    const color = sc >= 20 ? '#FFCDD2' : sc >= 12 ? '#FFE0B2' : sc >= 6 ? '#FFF9C4' : '#E8F5E9';
    const ids = threats.filter((t) => t.likelihood === l && t.impact === i).map((t) => t.id);
    return (
      <div key={`${l}${i}`} className="cell" style={{ background: color }} title={ids.map((id) => threats.find((t) => t.id === id).title).join('\n')}>
        {ids.join(' ')}
        <div className="mini" style={{ fontWeight: 400 }}>L{l}×I{i}={sc}</div>
      </div>
    );
  };
  return (
    <div>
      <div className="matrix">
        <div className="hdr">L\I</div>
        {[1, 2, 3, 4, 5].map((i) => <div key={i} className="hdr">Impact {i}</div>)}
        {[5, 4, 3, 2, 1].map((l) => (
          <React.Fragment key={l}>
            <div className="hdr">{l}</div>
            {[1, 2, 3, 4, 5].map((i) => cell(l, i))}
          </React.Fragment>
        ))}
      </div>
      <div className="mini" style={{ marginTop: 6 }}>Likelihood rises when linked checks fail; impact is fixed per threat. Hover a cell for the threat names.</div>
    </div>
  );
}

export function Hist({ hist }) {
  const entries = Object.entries(hist || {}).map(([k, v]) => [Number(k), v]).sort((a, b) => a[0] - b[0]);
  if (!entries.length) return null;
  const max = Math.max(...entries.map((e) => e[1]));
  return (
    <div>
      <div className="hist">
        {entries.map(([k, v]) => <div key={k} style={{ height: `${(100 * v) / max}%` }} title={`${k} B × ${v}`} />)}
      </div>
      <div className="mini">most common ESP lengths (bytes): {entries.slice(0, 8).map(([k, v]) => `${k}×${v}`).join(', ')}</div>
    </div>
  );
}

export function Fact({ k, v, tier, conf }) {
  return (
    <div className="fact">
      <div className="k">{k}</div>
      <div>{v}</div>
      <div>{tier && <Tier t={tier} conf={conf} />}</div>
    </div>
  );
}
