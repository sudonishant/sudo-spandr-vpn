import React, { useEffect, useState } from 'react';
import { api } from './api.js';
import Home from './components/Home.jsx';
import Result from './components/Result.jsx';
import { AboutPage, ChecksPage } from './components/Pages.jsx';
import Live from './components/Live.jsx';

function useHashRoute() {
  const [route, setRoute] = useState(window.location.hash.slice(1) || '/');
  useEffect(() => {
    const on = () => setRoute(window.location.hash.slice(1) || '/');
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  const navigate = (r) => { window.location.hash = r; };
  return [route, navigate];
}

export default function App() {
  const [route, navigate] = useHashRoute();
  const [profile, setProfile] = useState('baseline');
  const [profiles, setProfiles] = useState({});
  const [health, setHealth] = useState(null);
  const [menu, setMenu] = useState(false);
  useEffect(() => { setMenu(false); }, [route]);
  useEffect(() => {
    api.profiles().then(setProfiles).catch(() => {});
    api.health().then(setHealth).catch(() => setHealth({ status: 'down' }));
  }, []);

  const m = route.match(/^\/result\/([a-z0-9]+)/);
  let page;
  if (m) page = <Result id={m[1]} profile={profile} setProfile={setProfile} profiles={profiles} navigate={navigate} />;
  else if (route.startsWith('/checks')) page = <ChecksPage profile={profile} setProfile={setProfile} profiles={profiles} />;
  else if (route.startsWith('/about')) page = <AboutPage health={health} />;
  else if (route.startsWith('/analyze')) page = <Home profile={profile} setProfile={setProfile} profiles={profiles} navigate={navigate} />;
  else page = <Live profile={profile} setProfile={setProfile} profiles={profiles} navigate={navigate} />;

  const link = (to, label) => {
    const active = (to === '/' ? (route === '/' || route.startsWith('/live')) : route.startsWith(to));
    return (
      <a
        href={`#${to}`}
        className={active ? 'active' : ''}
        aria-current={active ? 'page' : undefined}
      >
        {label}
      </a>
    );
  };

  return (
    <div>
      <header className="topbar" role="banner">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="6" fill="#0070C0" /><circle cx="16" cy="16" r="9" fill="none" stroke="#fff" strokeWidth="3" /><circle cx="16" cy="16" r="3" fill="#EF6C00" /></svg>
          <span>IPsec X-Ray <small>SIH26160 · passive VPN analyzer</small></span>
        </div>
        <button className="menu-btn" onClick={() => setMenu(!menu)} aria-label="Toggle navigation menu" aria-expanded={menu}>☰</button>
        <nav className={menu ? 'open' : ''} aria-label="Main navigation">{link('/', 'Live')}{link('/analyze', 'Analyze pcap')}{link('/checks', 'Checks & threats')}{link('/about', 'Method & limits')}<a href="/docs" target="_blank" rel="noreferrer">API</a></nav>
        <div className="status" role="status" aria-live="polite"><span className={`dot ${health?.status === 'ok' ? '' : 'off'}`} aria-hidden="true" />{health?.status === 'ok' ? `engine v${health.version} · models ${health.models ? 'loaded' : 'missing'}` : 'API unreachable'}</div>
      </header>
      <main id="main" className="container" role="main">{page}<footer role="contentinfo">IPsec X-Ray · Team Sudo Spandr · SIH 2026 · No keys, no decryption, no injection — passive analysis only.</footer></main>
    </div>
  );
}
