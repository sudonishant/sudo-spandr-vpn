import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './styles.css';

createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>);

// PWA: installable + instant reload. Service workers need HTTPS or localhost; on plain http over a LAN the app
// still works as a normal responsive web app.
if ('serviceWorker' in navigator && (window.isSecureContext)) {
  window.addEventListener('load', () => { navigator.serviceWorker.register('/sw.js').catch(() => {}); });
}
