import React, { useState } from 'react';
import { api } from '../services/api';
import { AnalysisResult } from '../types';
import { AnalysisResultCard } from '../components/AnalysisResultCard';
import { useToast } from '../context/ToastContext';
import {
  Share2,
  Instagram,
  Twitter,
  Send as TelegramIcon,
  Facebook,
  Linkedin,
  AlertCircle,
  Sparkles,
  RotateCcw,
  Send,
  ShieldAlert,
} from 'lucide-react';

export const SocialAnalyzer: React.FC = () => {
  const { showToast } = useToast();
  const [platform, setPlatform] = useState<'instagram' | 'twitter' | 'telegram' | 'facebook' | 'linkedin'>('instagram');
  const [content, setContent] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<{ scanId: string; analysis: AnalysisResult } | null>(null);

  const platforms = [
    { id: 'instagram', name: 'Instagram', icon: Instagram, color: 'text-pink-400 border-pink-500/30 bg-pink-500/10' },
    { id: 'twitter', name: 'X / Twitter', icon: Twitter, color: 'text-sky-400 border-sky-500/30 bg-sky-500/10' },
    { id: 'telegram', name: 'Telegram', icon: TelegramIcon, color: 'text-blue-400 border-blue-500/30 bg-blue-500/10' },
    { id: 'facebook', name: 'Facebook', icon: Facebook, color: 'text-indigo-400 border-indigo-500/30 bg-indigo-500/10' },
    { id: 'linkedin', name: 'LinkedIn', icon: Linkedin, color: 'text-blue-400 border-blue-500/30 bg-blue-500/10' },
  ] as const;

  const socialPresets: Record<string, string> = {
    instagram: '🚨 OFFICIAL META VERIFICATION ALERT: Your account has been reported for copyright infringements. To avoid permanent deletion within 24 hours, click our bio link https://meta-support-ticket.xyz and fill out the security verification form with your password.',
    twitter: '🎉 In celebration of our new partnership with Google AI, @VitalikButerin is giving away 2,000 ETH! First 1,000 wallets to send 0.2 ETH to the contract address below receive 0.5 ETH back immediately! Claim now: https://vitalik-eth-airdrop.top',
    telegram: '💎 PRIVATE VIP CRYPTO SIGNALS: 100% daily guaranteed profit! Our AI trading bot achieved 98.4% win rate this month. Join our premium channel for just $200 USDT. Message admin @official_crypto_guru to start earning passive income today.',
    facebook: 'ATTENTION SENIORS: The government has approved a new $4,200 stimulus subsidy for eligible citizens this week. Click here to check your eligibility: https://national-relief-funds.click and provide your SSN and bank details.',
    linkedin: 'Dear connection, I was impressed by your profile and would like to extend an offer for a Senior Cloud Architect position ($185k/yr, fully remote). Please download and review the project specifications and NDA package from: http://194.87.139.12/job-specs.exe',
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) {
      showToast('Please paste a social post, bio, or message text to analyze.', 'warning');
      return;
    }

    try {
      setAnalyzing(true);
      const res = await api.scanSocial(content.trim(), platform);
      setResult({
        scanId: res.scanId,
        analysis: res.analysis,
      });
      showToast('Social content analysis complete.', 'success');
    } catch (err: any) {
      showToast(err.message || 'Social analysis failed.', 'error');
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto animate-fade-in">
      {/* Header & Verification Scope Disclaimer */}
      <div className="space-y-3 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Share2 className="w-5 h-5 text-purple-400" />
          <h1 className="text-xl font-bold font-mono text-slate-100">
            Social Media Threat Analyzer
          </h1>
        </div>
        <p className="text-xs text-slate-400">
          Analyze suspicious social media posts, bios, sponsored promos, direct messages, and influencer giveaway announcements.
        </p>

        {/* Disclaimer per Requirement 9 */}
        <div className="flex items-start space-x-3 p-3.5 rounded-xl bg-slate-900/90 border border-slate-700/60 text-slate-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
          <p>
            <strong className="text-cyan-300 font-semibold">Scope of Verification:</strong> This scanner analyzes the textual and semantic characteristics of pasted content. It does not inspect private social accounts, verify live API followers, or declare an account as automated/bot-operated. Observations reflect unverified heuristic and AI risk markers.
          </p>
        </div>
      </div>

      {/* Platform Selector Tabs */}
      <div>
        <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
          Select Target Platform:
        </label>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {platforms.map(p => {
            const Icon = p.icon;
            const isSelected = platform === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => {
                  setPlatform(p.id);
                  setContent(socialPresets[p.id] || '');
                }}
                className={`flex items-center justify-center space-x-2 p-3 rounded-xl border text-xs font-semibold transition-all ${
                  isSelected
                    ? `${p.color} border-current shadow-md`
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{p.name}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Analysis Form */}
      <form onSubmit={handleAnalyze} className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-slate-400">
            Pasted Post Text / Bio / DM ({platform.toUpperCase()}):
          </span>
          <span className="text-xs font-mono text-slate-500">
            {content.length} / 10,000 chars
          </span>
        </div>

        <div>
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            placeholder={`Paste text from ${platform} post, user bio, giveaway announcement, or DM message here...`}
            rows={7}
            className="w-full px-4 py-3 rounded-xl bg-slate-950/80 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-xs sm:text-sm text-slate-100 placeholder-slate-600 font-sans transition-all resize-none"
          />
        </div>

        <div className="flex items-center justify-between pt-1">
          <button
            type="button"
            onClick={() => {
              setContent('');
              setResult(null);
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
            className="inline-flex items-center space-x-2 px-6 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wide text-slate-950 bg-gradient-to-r from-purple-400 to-cyan-400 hover:from-purple-300 hover:to-cyan-300 disabled:opacity-50 transition-all shadow-glow-cyan"
          >
            {analyzing ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Auditing Social Vectors...</span>
              </>
            ) : (
              <>
                <Send className="w-3.5 h-3.5" />
                <span>Analyze Social Content</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slide-in">
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
