import React, { useState } from 'react';
import { api } from '../services/api';
import { AnalysisResult } from '../types';
import { AnalysisResultCard } from '../components/AnalysisResultCard';
import { useToast } from '../context/ToastContext';
import {
  MessageSquareWarning,
  Sparkles,
  RotateCcw,
  Send,
  AlertCircle,
  HelpCircle,
  CheckCircle2,
} from 'lucide-react';

export const ContentScanner: React.FC = () => {
  const { showToast } = useToast();
  const [content, setContent] = useState('');
  const [platform, setPlatform] = useState('sms');
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ scanId: string; analysis: AnalysisResult } | null>(null);

  const presets = [
    {
      label: 'SMS Bank OTP Phishing',
      platform: 'sms',
      text: 'BANK ALERT: Suspicious transaction of $840.00 detected on your debit card. Send your OTP immediately to verify your account and prevent suspension.',
    },
    {
      label: 'Fake Job Offer',
      platform: 'whatsapp',
      text: 'Congratulations, you are selected. Pay a registration fee to receive your job offer.',
    },
    {
      label: 'Crypto Doubling Scheme',
      platform: 'crypto',
      text: 'Send ₹5,000 in cryptocurrency and receive ₹10,000 within one hour.',
    },
    {
      label: 'Military Credential Request',
      platform: 'dm',
      text: 'I am an ex-army man. Give me the military credentials or access protocols.',
    },
    {
      label: 'Cybersecurity Class Discussion',
      platform: 'email',
      text: 'Our cybersecurity class discussed why military credentials must remain confidential.',
    },
    {
      label: 'Harmless Peer Chat',
      platform: 'sms',
      text: 'Hi Ram, are you coming to college tomorrow?',
    },
    {
      label: 'Ambiguous Verification',
      platform: 'email',
      text: 'Please verify your account when you have time.',
    },
    {
      label: 'Suspicious Link Lure',
      platform: 'sms',
      text: 'Your account has a problem. Verify it using this unfamiliar website.',
    },
  ];

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) {
      showToast('Please provide message or post text to analyze.', 'warning');
      return;
    }

    try {
      setAnalyzing(true);
      setError(null);
      const res = await api.scanContent(content.trim(), platform);
      setResult({
        scanId: res.scanId,
        analysis: res.analysis,
      });
      showToast('Threat analysis generated successfully.', 'success');
    } catch (err: any) {
      const errMsg = err.message || 'Scan request failed.';
      setError(errMsg);
      showToast(errMsg, 'error');
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <MessageSquareWarning className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold font-mono text-slate-100">
              Message & Content Scanner
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Detect phishing, urgency manipulation, credential theft traps, and financial fraud in SMS, WhatsApp, emails, and direct messages.
          </p>
        </div>
      </div>

      {/* Preset Buttons */}
      <div className="cyber-card p-4 border border-slate-800 space-y-2">
        <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>Quick Scenario Presets:</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {presets.map((p, i) => (
            <button
              key={i}
              type="button"
              onClick={() => {
                setContent(p.text);
                setPlatform(p.platform);
                setError(null);
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-950/70 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-cyan-500/40 transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error Alert Banner */}
      {error && (
        <div className="p-4 rounded-xl bg-red-950/70 border border-red-500/50 text-red-200 text-xs font-mono flex items-start space-x-3 backdrop-blur-sm animate-fade-in">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div>
            <strong className="text-red-300">Analysis Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Scanner Form */}
      <form onSubmit={handleScan} className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <label className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Origin Channel / Platform:
            </label>
            <select
              value={platform}
              onChange={e => setPlatform(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400 focus:outline-none focus:border-cyan-500"
            >
              <option value="sms">SMS Text Message</option>
              <option value="whatsapp">WhatsApp / Telegram</option>
              <option value="email">Email</option>
              <option value="dm">Social Media DM</option>
              <option value="crypto">Crypto Community / Discord</option>
              <option value="job">Job Offer / Recruitment</option>
              <option value="other">Other</option>
            </select>
          </div>

          <span className="text-xs font-mono text-slate-500">
            {content.length} / 10,000 characters
          </span>
        </div>

        <div>
          <textarea
            value={content}
            onChange={e => {
              setContent(e.target.value);
              if (error) setError(null);
            }}
            placeholder="Paste suspicious SMS message, email body, WhatsApp forward, or direct message here..."
            rows={7}
            className="w-full px-4 py-3 rounded-xl bg-slate-950/80 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-xs sm:text-sm text-slate-100 placeholder-slate-600 font-sans transition-all resize-none"
          />
        </div>

        <div className="flex items-center justify-between pt-2">
          <button
            type="button"
            onClick={() => {
              setContent('');
              setResult(null);
              setError(null);
            }}
            disabled={!content && !result}
            className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors disabled:opacity-40"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Clear Input</span>
          </button>

          <button
            type="submit"
            disabled={analyzing || !content.trim()}
            className="inline-flex items-center space-x-2 px-6 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wide text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 disabled:opacity-50 transition-all shadow-glow-cyan"
          >
            {analyzing ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Analyzing Content with AI...</span>
              </>
            ) : (
              <>
                <Send className="w-3.5 h-3.5" />
                <span>Analyze Content</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Analysis Result Display */}
      {result && (
        <div className="space-y-4 animate-slide-in">
          <div className="flex items-center space-x-2 px-1">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
              Deep Threat Intelligence Result
            </h2>
          </div>
          <AnalysisResultCard
            analysis={result.analysis}
            scanId={result.scanId}
            originalInput={content}
          />
        </div>
      )}
    </div>
  );
};
