const BASE = '';

async function j(res) {
  if (!res.ok) {
    let msg = res.statusText;
    try { const b = await res.json(); msg = b.detail || JSON.stringify(b); } catch (e) { /* ignore */ }
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  health: () => fetch(`${BASE}/api/health`).then(j),
  profiles: () => fetch(`${BASE}/api/profiles`).then(j),
  checks: (profile) => fetch(`${BASE}/api/checks?profile=${profile}`).then(j),
  threats: () => fetch(`${BASE}/api/threats`).then(j),
  samples: () => fetch(`${BASE}/api/samples`).then(j),
  analyzeSample: (name, profile) => fetch(`${BASE}/api/samples/${name}/analyze?profile=${profile}`, { method: 'POST' }).then(j),
  analyzeUpload: (file, profile) => {
    const fd = new FormData();
    fd.append('file', file);
    return fetch(`${BASE}/api/analyze?profile=${profile}`, { method: 'POST', body: fd }).then(j);
  },
  results: () => fetch(`${BASE}/api/results`).then(j),
  result: (id) => fetch(`${BASE}/api/results/${id}`).then(j),
  reassess: (id, profile) => fetch(`${BASE}/api/results/${id}/reassess?profile=${profile}`, { method: 'POST' }).then(j),
  remove: (id) => fetch(`${BASE}/api/results/${id}`, { method: 'DELETE' }).then(j),
  reportUrl: (id, fmt, kind = 'technical') => `${BASE}/api/results/${id}/report.${fmt}?kind=${kind}`,
  sampleUrl: (name) => `${BASE}/api/samples/${name}/download`,
};

export const gradeColor = (g) => ({ 'A+': '#2E7D32', A: '#2E7D32', B: '#7CB342', C: '#EF6C00', D: '#E64A19', F: '#C62828' }[g] || '#607D8B');
export const riskColor = (r) => (r >= 75 ? '#C62828' : r >= 50 ? '#E64A19' : r >= 25 ? '#EF6C00' : '#2E7D32');
export const fmtBytes = (n) => (n > 1e6 ? `${(n / 1e6).toFixed(2)} MB` : n > 1e3 ? `${(n / 1e3).toFixed(1)} kB` : `${n} B`);
