import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { AlertTriangle, WifiOff, Sparkles, X, RefreshCw, LogIn } from 'lucide-react';
import { Link } from 'react-router-dom';

export const ConnectionBanner: React.FC = () => {
  const { user, backendAvailable, retryConnection, authStatus } = useAuth();
  const [geminiConfigured, setGeminiConfigured] = useState<boolean | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [retrying, setRetrying] = useState(false);

  const checkGeminiStatus = async () => {
    try {
      const res = await api.getHealth({ timeoutMs: 3000 });
      if (res && res.gemini) {
        setGeminiConfigured(!!res.gemini.configured);
      }
    } catch {
      setGeminiConfigured(false);
    }
  };

  useEffect(() => {
    if (backendAvailable) {
      checkGeminiStatus();
    }
  }, [backendAvailable]);

  const handleRetry = async () => {
    try {
      setRetrying(true);
      await retryConnection();
      await checkGeminiStatus();
    } finally {
      setRetrying(false);
    }
  };

  if (dismissed) return null;

  // 1. Backend Offline / Unavailable Warning (Exact Requirement 3)
  if (!backendAvailable || authStatus === 'degraded') {
    return (
      <div className="mb-6 p-4 rounded-xl bg-amber-950/70 border border-amber-500/50 text-amber-200 text-xs shadow-lg animate-fade-in flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-start sm:items-center space-x-3">
          <div className="p-2 rounded-lg bg-amber-900/60 border border-amber-600/40 text-amber-300 shrink-0">
            <WifiOff className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold font-mono tracking-wider text-amber-100 uppercase">
                Backend unavailable — some features may be limited.
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-900 border border-amber-700 font-mono text-amber-300">
                Port 8000
              </span>
            </div>
            <p className="text-amber-300/90 mt-0.5 leading-relaxed">
              Unable to reach the backend SOC API server. ScamGuard is operating in <strong className="text-white">Client Heuristic Mode</strong> so you can still scan text, analyze URLs, and inspect threats. To enable persistent telemetry and database storage, execute <code className="px-1.5 py-0.5 rounded bg-black/40 text-cyan-300 font-mono text-[11px]">npm run dev:server</code> in your terminal.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0 self-end sm:self-center">
          <button
            onClick={handleRetry}
            disabled={retrying}
            className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-amber-900/80 hover:bg-amber-800 border border-amber-700/60 text-amber-100 font-mono text-xs transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${retrying ? 'animate-spin' : ''}`} />
            <span>{retrying ? 'Retrying...' : 'Retry Connection'}</span>
          </button>
          <button
            onClick={() => setDismissed(true)}
            className="p-1.5 rounded-lg text-amber-400 hover:text-white hover:bg-amber-900/40 transition-colors"
            aria-label="Dismiss banner"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  // 2. Gemini Unconfigured Information Notice (Independent from Frontend)
  if (backendAvailable && geminiConfigured === false) {
    return (
      <div className="mb-6 p-3.5 rounded-xl bg-cyan-950/50 border border-cyan-700/40 text-cyan-200 text-xs shadow-md animate-fade-in flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-cyan-900/50 text-cyan-300 shrink-0 border border-cyan-800">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold font-mono tracking-wider text-cyan-100">
                HEURISTIC INTELLIGENCE ACTIVE
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-900/80 border border-cyan-700 font-mono text-cyan-300">
                Rule-Based Engine
              </span>
            </div>
            <p className="text-slate-300 mt-0.5">
              Google Gemini API key is not configured in server/.env. Threat detection is operating with full accuracy using high-precision heuristic pattern analysis.
            </p>
          </div>
        </div>

        <button
          onClick={() => setDismissed(true)}
          className="p-1 rounded text-slate-400 hover:text-white shrink-0 self-end sm:self-center"
          aria-label="Dismiss notice"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    );
  }

  // 3. Guest Analyst Notice
  if (!user && backendAvailable) {
    return (
      <div className="mb-6 p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 text-xs shadow-md animate-fade-in flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-slate-800 text-cyan-400 shrink-0 border border-slate-700">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div>
            <span className="font-bold font-mono tracking-wider text-slate-200">
              GUEST ANALYST SESSION
            </span>
            <p className="text-slate-400 mt-0.5">
              Operating in live public triage mode. To persist forensic scan logs, generate exportable certificates, and access threat telemetry, please sign in.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0 self-end sm:self-center">
          <Link
            to="/login"
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-glow-cyan"
          >
            <LogIn className="w-3.5 h-3.5" />
            <span>Sign In</span>
          </Link>
          <button
            onClick={() => setDismissed(true)}
            className="p-1 rounded text-slate-400 hover:text-white"
            aria-label="Dismiss notice"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    );
  }

  return null;
};
