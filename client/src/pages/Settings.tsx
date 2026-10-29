import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import {
  Settings as SettingsIcon,
  Sparkles,
  Cpu,
  Shield,
  Sliders,
  Server,
  Lock,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Clock,
} from 'lucide-react';

export const Settings: React.FC = () => {
  const { showToast } = useToast();
  const [info, setInfo] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getSettingsInfo()
      .then(res => setInfo(res))
      .catch(err => console.error('Failed to load settings info:', err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="space-y-2 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <SettingsIcon className="w-5 h-5 text-cyan-400" />
          <h1 className="text-xl font-bold font-mono text-slate-100">
            System Settings & Engine Configuration
          </h1>
        </div>
        <p className="text-xs text-slate-400">
          Inspect backend service configuration, Google Gemini AI integration state, threat score thresholds, and server telemetry.
        </p>
      </div>

      {/* Gemini Integration & AI Analysis Status */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
              AI Analysis Engine Status
            </h3>
          </div>
          <span
            className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider border ${
              info?.geminiConfigured
                ? 'bg-cyan-950/70 text-cyan-400 border-cyan-800/50'
                : 'bg-amber-950/70 text-amber-400 border-amber-800/50'
            }`}
          >
            {info?.geminiConfigured ? 'Gemini AI Online' : 'Heuristic Mode Active'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase text-slate-500">Google Gemini API Key</span>
            <div className="flex items-center space-x-2">
              <span
                className={`font-semibold ${
                  info?.geminiConfigured ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {info?.geminiConfigured ? 'Configured (Server-Side Vault)' : 'Not Configured (Running Fallback)'}
              </span>
            </div>
            <p className="text-[10px] text-slate-500 font-sans mt-1">
              For security, the API key is never exposed to client browsers and resides strictly in server-side process environment.
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase text-slate-500">Active Threat Model</span>
            <p className="text-slate-200 font-bold text-xs">{info?.activeModel || 'gemini-3.8-flash'}</p>
            <p className="text-[10px] text-slate-500 font-sans mt-1">
              Configured via <code className="text-cyan-400">GEMINI_MODEL</code> in backend environment file.
            </p>
          </div>
        </div>

        {/* Supported Models List */}
        <div className="space-y-2 pt-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
            Supported Google Gemini Models:
          </span>
          <div className="space-y-2">
            {info?.supportedModels?.map((model: any) => (
              <div
                key={model.id}
                className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between ${
                  info?.activeModel === model.id
                    ? 'bg-cyan-950/30 border-cyan-800/60 text-slate-200'
                    : 'bg-slate-950/40 border-slate-800 text-slate-400'
                }`}
              >
                <div>
                  <span className="font-bold text-cyan-300">{model.name}</span>
                  <p className="text-[11px] text-slate-400 font-sans mt-0.5">{model.description}</p>
                </div>
                {info?.activeModel === model.id && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-900/60 text-cyan-300 border border-cyan-700 font-bold shrink-0">
                    Active
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Threat Threshold Reference */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            Threat Score Tiers & Risk Thresholds
          </h3>
        </div>

        <p className="text-xs text-slate-400">
          All scan submissions receive an automated risk score ranging from 0 to 100 based on heuristic pattern weight and Gemini AI linguistic assessment:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-900/40">
            <span className="text-emerald-400 font-bold text-sm block">0 – 29</span>
            <span className="font-semibold text-slate-200">Low Risk</span>
            <p className="text-[11px] text-slate-400 font-sans mt-1">Benign communication with standard linguistic patterns.</p>
          </div>

          <div className="p-3 rounded-xl bg-amber-950/20 border border-amber-900/40">
            <span className="text-amber-400 font-bold text-sm block">30 – 59</span>
            <span className="font-semibold text-slate-200">Moderate Risk</span>
            <p className="text-[11px] text-slate-400 font-sans mt-1">Ambiguous or manipulative traits requiring caution.</p>
          </div>

          <div className="p-3 rounded-xl bg-orange-950/20 border border-orange-900/40">
            <span className="text-orange-400 font-bold text-sm block">60 – 79</span>
            <span className="font-semibold text-slate-200">High Risk</span>
            <p className="text-[11px] text-slate-400 font-sans mt-1">Urgency pressure, prize bait, or deceptive lookalikes.</p>
          </div>

          <div className="p-3 rounded-xl bg-red-950/20 border border-red-900/40">
            <span className="text-red-400 font-bold text-sm block">80 – 100</span>
            <span className="font-semibold text-slate-200">Critical Threat</span>
            <p className="text-[11px] text-slate-400 font-sans mt-1">Confirmed credential harvesting, OTP fraud, or malware.</p>
          </div>
        </div>
      </div>

      {/* Security Preferences & 2FA Status */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
          <Lock className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            Authentication & Security Policies
          </h3>
        </div>

        <div className="space-y-3">
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs">
            <div>
              <span className="font-semibold text-slate-200 font-mono">Two-Factor Authentication (2FA)</span>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Hardware token or TOTP authenticator protection.
              </p>
            </div>
            {/* Accurately marked per Requirement 16 */}
            <span className="px-2.5 py-1 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-400 border border-slate-700">
              Not Configured
            </span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs">
            <div>
              <span className="font-semibold text-slate-200 font-mono">Session Cookie Transport</span>
              <p className="text-[11px] text-slate-400 mt-0.5">
                HTTP-Only, SameSite strict/lax protection against XSS exfiltration.
              </p>
            </div>
            <span className="px-2.5 py-1 rounded text-[10px] font-mono uppercase bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 font-bold">
              Enforced
            </span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs">
            <div>
              <span className="font-semibold text-slate-200 font-mono">SSRF & Loopback Defense Barrier</span>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Blocks private RFC 1918 subnets and cloud metadata endpoints.
              </p>
            </div>
            <span className="px-2.5 py-1 rounded text-[10px] font-mono uppercase bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 font-bold">
              Active
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
