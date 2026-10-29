import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import './index.css';

const rootElement = document.getElementById('root');

if (!rootElement) {
  console.error('[SCAMGUARD AI] Root element #root was not found in the DOM.');
  const fallback = document.createElement('div');
  fallback.id = 'root';
  document.body.appendChild(fallback);
  ReactDOM.createRoot(fallback).render(
    <React.StrictMode>
      <ErrorBoundary fallbackTitle="ScamGuard Core System Initialization Error">
        <App />
      </ErrorBoundary>
    </React.StrictMode>
  );
} else {
  try {
    ReactDOM.createRoot(rootElement).render(
      <React.StrictMode>
        <ErrorBoundary fallbackTitle="ScamGuard Core System Initialization Error">
          <App />
        </ErrorBoundary>
      </React.StrictMode>
    );
  } catch (err: any) {
    console.error('[SCAMGUARD AI] Fatal ReactDOM mount error:', err);
    rootElement.innerHTML = `
      <div style="min-height:100vh;background:#060911;color:#f87171;display:flex;align-items:center;justify-content:center;padding:24px;font-family:monospace;">
        <div style="max-width:540px;background:#0f172a;border:1px solid #ef4444;border-radius:16px;padding:32px;text-align:center;">
          <h2 style="font-size:18px;color:#ef4444;margin-bottom:12px;">SCAMGUARD AI — MOUNT EXCEPTION</h2>
          <p style="font-size:12px;color:#94a3b8;margin-bottom:16px;">${err?.message || 'Failed to mount React application.'}</p>
          <button onclick="window.location.reload()" style="background:#06b6d4;color:#000;border:none;padding:8px 16px;border-radius:8px;font-weight:bold;cursor:pointer;">Retry</button>
        </div>
      </div>
    `;
  }
}

