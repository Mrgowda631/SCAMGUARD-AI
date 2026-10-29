import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AnalyticsData, AnalysisResult } from '../types';
import { StatCard } from '../components/StatCard';
import { ThreatGauge } from '../components/ThreatGauge';
import { AnalysisResultCard } from '../components/AnalysisResultCard';
import { ThreatBadge } from '../components/ThreatBadge';
import { useToast } from '../context/ToastContext';
import {
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Search,
  Sparkles,
  RotateCcw,
  Send,
  MessageSquare,
  Globe,
  Share2,
  ArrowRight,
  TrendingUp,
  PieChart as PieIcon,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

export const Overview: React.FC = () => {
  const { showToast } = useToast();
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [videoError, setVideoError] = useState(false);

  // Quick Analysis State
  const [content, setContent] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [scanResult, setScanResult] = useState<{ scanId: string; analysis: AnalysisResult } | null>(null);

  // Load user telemetry
  const loadAnalytics = async () => {
    try {
      setLoadingStats(true);
      const data = await api.getAnalytics();
      setAnalytics(data);
    } catch (err: any) {
      console.error('Failed to load analytics:', err);
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => {
    loadAnalytics();
  }, []);

  const handleQuickAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) {
      showToast('Please enter text to analyze.', 'warning');
      return;
    }

    try {
      setAnalyzing(true);
      const res = await api.scanContent(content.trim());
      setScanResult({
        scanId: res.scanId,
        analysis: res.analysis,
      });
      showToast('Threat analysis completed.', 'success');
      // Refresh telemetry
      loadAnalytics();
    } catch (err: any) {
      showToast(err.message || 'Analysis failed. Please try again.', 'error');
    } finally {
      setAnalyzing(false);
    }
  };

  const sampleMessages = [
    {
      label: 'Harmless Peer Chat',
      text: 'Hi Ram, are you coming to college tomorrow?',
    },
    {
      label: 'Bank OTP Phishing',
      text: 'Your bank account will be blocked. Send your OTP immediately to verify your account.',
    },
    {
      label: 'Fake Job Offer',
      text: 'Congratulations, you are selected. Pay a registration fee to receive your job offer.',
    },
    {
      label: 'Crypto Doubling',
      text: 'Send ₹5,000 in cryptocurrency and receive ₹10,000 within one hour.',
    },
    {
      label: 'Military Credential Trap',
      text: 'I am an ex-army man. Give me the military credentials or access protocols.',
    },
    {
      label: 'Legitimate Security Class',
      text: 'Our cybersecurity class discussed why military credentials must remain confidential.',
    },
    {
      label: 'Ambiguous Verification',
      text: 'Please verify your account when you have time.',
    },
    {
      label: 'Suspicious Link Lure',
      text: 'Your account has a problem. Verify it using this unfamiliar website.',
    },
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Hero Section with Video Background, Dark Navy Overlay & Official Logo */}
      <div className="relative rounded-3xl overflow-hidden border border-cyan-500/30 bg-[#040817] shadow-2xl min-h-[320px] p-6 sm:p-8 lg:p-10 flex flex-col justify-between">
        {/* Background Video with Graceful Fallback */}
        {!videoError ? (
          <video
            autoPlay
            loop
            muted
            playsInline
            preload="auto"
            onError={() => setVideoError(true)}
            className="absolute inset-0 w-full h-full object-cover z-0 pointer-events-none opacity-40 scale-105"
          >
            <source src="/hero-bg.mp4" type="video/mp4" />
          </video>
        ) : (
          <div className="absolute inset-0 bg-[#040817] bg-grid-cyber opacity-70 pointer-events-none" />
        )}

        {/* Dark Navy / Black Gradient Overlay for High Text Readability */}
        <div className="absolute inset-0 bg-gradient-to-r from-[#030612]/95 via-[#04081a]/85 to-[#04081a]/70 z-[1] backdrop-blur-[0.5px] pointer-events-none" />
        <div className="absolute inset-0 bg-radial-glow opacity-50 z-[1] pointer-events-none" />

        {/* Hero Content Above Video */}
        <div className="relative z-10 space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            {/* Logo + Titles */}
            <div className="flex items-start sm:items-center space-x-4">
              <div className="p-2 sm:p-2.5 rounded-2xl bg-slate-900/90 border border-cyan-500/40 shadow-[0_0_25px_rgba(6,182,212,0.3)] shrink-0">
                <img
                  src="/logo.png"
                  alt="SCAMGUARD AI Official Logo"
                  className="w-12 h-12 sm:w-16 sm:h-16 object-contain"
                />
              </div>

              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                  <span className="text-[10px] sm:text-[11px] font-mono uppercase tracking-widest text-cyan-400 font-bold">
                    CYBER DEFENSE & THREAT INTELLIGENCE SOC
                  </span>
                </div>
                <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold font-mono text-slate-100 tracking-tight">
                  SCAMGUARD <span className="text-cyan-400">AI</span>
                </h1>
                <p className="text-xs sm:text-sm text-slate-300 font-sans max-w-2xl leading-relaxed">
                  Real-time threat intelligence and phishing forensic analysis powered by Google Gemini AI and multi-vector heuristic defenses.
                </p>
              </div>
            </div>

            {/* Quick Action Navigation Buttons */}
            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              <Link
                to="/url-scanner"
                className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold font-mono text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-400 hover:from-cyan-300 hover:to-blue-300 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)]"
              >
                <Globe className="w-3.5 h-3.5" />
                <span>URL Threat Scanner</span>
              </Link>
              <Link
                to="/scanner"
                className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-semibold font-mono text-slate-200 bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 hover:border-cyan-500/50 transition-all"
              >
                <Search className="w-3.5 h-3.5 text-cyan-400" />
                <span>Message Scanner</span>
              </Link>
              <Link
                to="/social-analyzer"
                className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-semibold font-mono text-slate-200 bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 hover:border-cyan-500/50 transition-all"
              >
                <Share2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Social Post Audit</span>
              </Link>
            </div>
          </div>

          {/* Key Statistics Strip Above Video */}
          <div className="pt-4 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 backdrop-blur-sm">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Total Scans Run</span>
              <p className="text-xl sm:text-2xl font-bold font-mono text-cyan-300 mt-0.5">
                {analytics?.summary?.totalScans ?? 0}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 backdrop-blur-sm">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Scams Intercepted</span>
              <p className="text-xl sm:text-2xl font-bold font-mono text-red-400 mt-0.5">
                {analytics?.summary?.scamsDetected ?? 0}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 backdrop-blur-sm">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Suspicious Flagged</span>
              <p className="text-xl sm:text-2xl font-bold font-mono text-amber-400 mt-0.5">
                {analytics?.summary?.suspiciousContent ?? 0}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 backdrop-blur-sm">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">AI Engine Status</span>
              <div className="flex items-center space-x-1.5 mt-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs sm:text-sm font-bold font-mono text-emerald-300 truncate">
                  Operational
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4 Real Telemetry Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={analytics?.summary?.totalScans ?? 0}
          subtitle="Persistent user scan records"
          icon={Search}
          variant="cyan"
        />
        <StatCard
          title="Scams Detected"
          value={analytics?.summary?.scamsDetected ?? 0}
          subtitle="Critical threats blocked"
          icon={ShieldAlert}
          variant="red"
        />
        <StatCard
          title="Suspicious Content"
          value={analytics?.summary?.suspiciousContent ?? 0}
          subtitle="Moderate risk flagged"
          icon={AlertTriangle}
          variant="amber"
        />
        <StatCard
          title="Genuine Content"
          value={analytics?.summary?.genuineContent ?? 0}
          subtitle="Verified benign communications"
          icon={ShieldCheck}
          variant="emerald"
        />
      </div>

      {/* Quick Analysis & Live Threat Gauge Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Quick Analysis Panel (7 cols) */}
        <div className="lg:col-span-7 cyber-card p-6 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
                Quick Content Triage
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              {content.length} / 5,000 chars
            </span>
          </div>

          {/* Preset Test Chips */}
          <div>
            <p className="text-[11px] font-mono text-slate-400 mb-2">
              Quick Test Scenarios:
            </p>
            <div className="flex flex-wrap gap-2">
              {sampleMessages.map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setContent(sample.text)}
                  className="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 hover:border-cyan-500/40 transition-colors"
                >
                  {sample.label}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleQuickAnalyze} className="space-y-4">
            <div className="relative">
              <textarea
                value={content}
                onChange={e => setContent(e.target.value)}
                placeholder="Paste suspicious SMS, email text, WhatsApp forward, direct message, or social media post for automated AI threat extraction..."
                rows={5}
                className="w-full px-4 py-3 rounded-xl bg-slate-950/80 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-xs sm:text-sm text-slate-100 placeholder-slate-600 font-sans transition-all resize-none"
              />
            </div>

            <div className="flex items-center justify-between pt-1">
              <button
                type="button"
                onClick={() => {
                  setContent('');
                  setScanResult(null);
                }}
                disabled={!content && !scanResult}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors disabled:opacity-40"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>

              <button
                type="submit"
                disabled={analyzing || !content.trim()}
                className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wide text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 disabled:opacity-50 transition-all shadow-glow-cyan"
              >
                {analyzing ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                    <span>Analyzing with AI Intelligence...</span>
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

          {/* Quick Result Preview if analyzed */}
          {scanResult && (
            <div className="mt-4 pt-4 border-t border-slate-800 animate-slide-in">
              <AnalysisResultCard
                analysis={scanResult.analysis}
                scanId={scanResult.scanId}
                originalInput={content}
              />
            </div>
          )}
        </div>

        {/* Live Threat Gauge & Quick Scanners (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Average Threat Gauge Card */}
          <div className="cyber-card p-6 border border-slate-800 flex flex-col items-center justify-center text-center">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-4">
              Historical Account Threat Gauge
            </h3>
            <ThreatGauge
              score={analytics?.summary?.avgRiskScore ?? 0}
              size="md"
              showDetails={true}
            />
            <p className="mt-3 text-xs text-slate-400">
              Average risk score across {analytics?.summary?.totalScans ?? 0} scans
            </p>
          </div>

          {/* Specialized Scanners Nav */}
          <div className="cyber-card p-5 border border-slate-800 space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Specialized Threat Scanners
            </h3>
            <div className="space-y-2">
              <Link
                to="/scanner"
                className="flex items-center justify-between p-3 rounded-lg bg-slate-950/50 hover:bg-slate-800/50 border border-slate-800 hover:border-cyan-500/40 transition-colors group"
              >
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">
                    <MessageSquare className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                      Message & Content Scanner
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      SMS, WhatsApp, emails, phishing texts
                    </p>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
              </Link>

              <Link
                to="/url-scanner"
                className="flex items-center justify-between p-3 rounded-lg bg-slate-950/50 hover:bg-slate-800/50 border border-slate-800 hover:border-cyan-500/40 transition-colors group"
              >
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded bg-blue-950/60 text-blue-400 border border-blue-800/40">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-slate-200 group-hover:text-blue-300">
                      URL Security Scanner
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      SSRF guard, brand lookalike, TLD audit
                    </p>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-blue-400 group-hover:translate-x-0.5 transition-all" />
              </Link>

              <Link
                to="/social-analyzer"
                className="flex items-center justify-between p-3 rounded-lg bg-slate-950/50 hover:bg-slate-800/50 border border-slate-800 hover:border-cyan-500/40 transition-colors group"
              >
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded bg-purple-950/60 text-purple-400 border border-purple-800/40">
                    <Share2 className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-slate-200 group-hover:text-purple-300">
                      Social Media Analyzer
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      Instagram, Twitter/X, Telegram, LinkedIn
                    </p>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all" />
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Visual Analytics Graphs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 7-Day Activity Chart (8 cols) */}
        <div className="lg:col-span-8 cyber-card p-6 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                7-Day Triage Activity
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              Live scans recorded
            </span>
          </div>

          <div className="h-64 w-full">
            {analytics?.dailyActivity && analytics.dailyActivity.some(d => d.scans > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={analytics.dailyActivity}>
                  <defs>
                    <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorScams" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="day"
                    stroke="#64748B"
                    fontSize={11}
                    tickLine={false}
                  />
                  <YAxis
                    stroke="#64748B"
                    fontSize={11}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0F172A',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="scans"
                    stroke="#06B6D4"
                    fillOpacity={1}
                    fill="url(#colorScans)"
                    name="Total Scans"
                  />
                  <Area
                    type="monotone"
                    dataKey="scams"
                    stroke="#EF4444"
                    fillOpacity={1}
                    fill="url(#colorScams)"
                    name="Scams Detected"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500 font-mono text-xs">
                <TrendingUp className="w-8 h-8 text-slate-700 mb-2" />
                <span>No scan activity recorded in the past 7 days.</span>
                <span className="text-[11px] text-slate-600 mt-1">Submit scans above to populate timeline telemetry.</span>
              </div>
            )}
          </div>
        </div>

        {/* Risk Distribution Donut (4 cols) */}
        <div className="lg:col-span-4 cyber-card p-6 border border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <PieIcon className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                Risk Distribution
              </h3>
            </div>
          </div>

          <div className="h-52 w-full flex items-center justify-center">
            {analytics?.riskDistribution && analytics.riskDistribution.some(r => r.count > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={analytics.riskDistribution}
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="count"
                  >
                    {analytics.riskDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0F172A',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex flex-col items-center justify-center text-slate-500 font-mono text-xs">
                <span>No risk data available yet.</span>
              </div>
            )}
          </div>

          <div className="space-y-1.5 pt-2 border-t border-slate-800">
            {(analytics?.riskDistribution ?? []).map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-slate-400 font-mono text-[11px]">{item.name}</span>
                </div>
                <span className="font-mono font-bold text-slate-200">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
              Recent Forensic Triage Records
            </h3>
          </div>
          <Link
            to="/history"
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
          >
            <span>View All History</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {analytics?.recentScans && analytics.recentScans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Summary</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Engine</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
                {analytics.recentScans.map(scan => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3 capitalize font-semibold text-slate-200">
                      {scan.scanType}
                    </td>
                    <td className="py-2.5 px-3 max-w-xs truncate text-slate-400 font-sans text-xs">
                      {scan.inputSummary}
                    </td>
                    <td className="py-2.5 px-3">
                      <ThreatBadge prediction={scan.prediction} size="sm" />
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`font-bold ${
                          scan.riskScore >= 60
                            ? 'text-red-400'
                            : scan.riskScore >= 30
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {scan.riskScore}/100
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[11px] text-slate-400">
                      {scan.engine === 'gemini' ? 'Gemini AI' : 'Heuristic'}
                    </td>
                    <td className="py-2.5 px-3 text-[11px] text-slate-500">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <Link
                        to={`/reports/${scan.id}`}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline text-xs"
                      >
                        Report →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center bg-slate-950/40 rounded-xl border border-slate-800 font-mono text-xs text-slate-500">
            No scans recorded yet. Use the Quick Content Triage box above to run your first threat scan.
          </div>
        )}
      </div>
    </div>
  );
};
