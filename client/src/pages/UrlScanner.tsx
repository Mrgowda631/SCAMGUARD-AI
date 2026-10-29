import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import { UrlAnalysisResponse, ScanItem } from '../types';
import { ThreatGauge } from '../components/ThreatGauge';
import { ThreatBadge } from '../components/ThreatBadge';
import { useToast } from '../context/ToastContext';
import {
  GlobeLock,
  Search,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ExternalLink,
  Sparkles,
  RotateCcw,
  Clock,
  Copy,
  Check,
  History,
  AlertCircle,
  ArrowRight,
  Shield,
  ExternalLink as LinkIcon,
} from 'lucide-react';
import { Link } from 'react-router-dom';

export const UrlScanner: React.FC = () => {
  const { showToast } = useToast();
  const inputRef = useRef<HTMLInputElement>(null);

  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [report, setReport] = useState<{ scanId: string; data: UrlAnalysisResponse } | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Authenticated user scan history
  const [urlHistory, setUrlHistory] = useState<ScanItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const sampleUrls = [
    { label: 'PayPal Typosquatting', url: 'https://paypa1-security-update.top/login.php?token=xyz982' },
    { label: 'Punycode Homograph', url: 'https://xn--pple-43d.com/verify-account' },
    { label: 'URL Shortener', url: 'https://bit.ly/3xY7zq' },
    { label: 'Unusual Port Target', url: 'http://phishing-domain.com:8443/auth' },
    { label: 'Raw IP Host Link', url: 'http://185.220.101.5/verify-account/auth' },
    { label: 'Legitimate Web Domain', url: 'https://www.github.com/security' },
  ];

  // Fetch recent URL scans for this analyst
  const fetchUrlHistory = async () => {
    try {
      setLoadingHistory(true);
      const res = await api.getScans({ scanType: 'url', limit: 5 });
      if (res && res.scans) {
        setUrlHistory(res.scans);
      }
    } catch {
      // Non-blocking history fetch
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchUrlHistory();
  }, []);

  const handleScanUrl = async (e?: React.FormEvent, overrideUrl?: string) => {
    if (e) e.preventDefault();
    setScanError(null);

    const targetUrl = (overrideUrl || url).trim();
    if (!targetUrl) {
      setScanError('Please enter a website URL address to audit.');
      showToast('Please enter a URL to audit.', 'warning');
      return;
    }

    // Client-side quick syntax pre-flight
    if (/^(javascript|file|ftp|data|blob):/i.test(targetUrl)) {
      setScanError('Disallowed protocol. Only HTTP and HTTPS web URLs are permitted.');
      showToast('Unsupported URL protocol.', 'error');
      return;
    }

    try {
      setScanning(true);
      setScanStep('Verifying URL syntax & SSRF boundary protection...');
      
      const stepTimer1 = setTimeout(() => {
        setScanStep('Auditing typosquatting, punycode, ports & domain structural vectors...');
      }, 700);

      const stepTimer2 = setTimeout(() => {
        setScanStep('Analyzing threat indicators via Gemini AI & forensic models...');
      }, 1600);

      const res = await api.scanUrl(targetUrl);
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);

      setReport({
        scanId: res.scanId,
        data: res.urlReport,
      });

      showToast('URL security assessment complete.', 'success');
      // Refresh user's scan history list
      fetchUrlHistory();
    } catch (err: any) {
      const msg = err.message || 'URL security scan failed. Please verify the URL format and try again.';
      setScanError(msg);
      showToast(msg, 'error');
    } finally {
      setScanning(false);
      setScanStep('');
    }
  };

  const handleCopyUrl = (textToCopy: string) => {
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    showToast('Copied to clipboard', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleResetScan = () => {
    setReport(null);
    setUrl('');
    setScanError(null);
    setTimeout(() => {
      inputRef.current?.focus();
    }, 100);
  };

  // Derive Three-Tier Verdict details
  const getVerdictDetails = (reportData: UrlAnalysisResponse) => {
    const tier = reportData.verdictTier || (
      reportData.analysis.risk_score >= 60 || reportData.analysis.prediction === 'scam'
        ? 'High Risk'
        : reportData.analysis.risk_score >= 30 || reportData.analysis.prediction === 'suspicious'
        ? 'Potentially Suspicious'
        : 'No Obvious Threat Detected'
    );

    switch (tier) {
      case 'High Risk':
        return {
          title: 'HIGH RISK — MALICIOUS THREAT DETECTED',
          badgeColor: 'bg-red-500/20 text-red-400 border-red-500/40',
          borderColor: 'border-red-500/50',
          glowColor: 'shadow-[0_0_30px_rgba(239,68,68,0.2)]',
          icon: ShieldAlert,
          iconColor: 'text-red-400',
          desc: 'High probability of phishing, credential harvesting, malware delivery, or deceptive impersonation. Do not interact with this destination.',
        };
      case 'Potentially Suspicious':
        return {
          title: 'POTENTIALLY SUSPICIOUS — EXERCISE HEIGHTENED CAUTION',
          badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
          borderColor: 'border-amber-500/50',
          glowColor: 'shadow-[0_0_30px_rgba(245,158,11,0.2)]',
          icon: AlertTriangle,
          iconColor: 'text-amber-400',
          desc: 'Suspicious structural vectors or brand indicators detected. Verify domain authenticity before entering any personal data or credentials.',
        };
      default:
        return {
          title: 'NO OBVIOUS THREAT DETECTED',
          badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
          borderColor: 'border-emerald-500/50',
          glowColor: 'shadow-[0_0_30px_rgba(16,185,129,0.2)]',
          icon: ShieldCheck,
          iconColor: 'text-emerald-400',
          desc: 'No recognized phishing indicators or structural anomalies observed in automated tests. However, automated scans cannot guarantee complete safety.',
        };
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto animate-fade-in select-none">
      {/* Header & Defensive Advisory Warning */}
      <div className="space-y-3 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-slate-900 border border-slate-700 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            <GlobeLock className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-bold font-mono text-slate-100">
              URL Threat & Phishing Security Scanner
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Deep static and AI forensic inspection of uniform resource locators (URLs). Detect brand typosquatting, punycode, non-standard ports, deceptive subdomains, and credential-harvesting paths.
            </p>
          </div>
        </div>

        {/* Security Defensive Warning Banner */}
        <div className="flex items-start space-x-3 p-3.5 rounded-xl bg-amber-950/25 border border-amber-500/35 text-amber-300 text-xs leading-relaxed">
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
          <p>
            <strong className="font-semibold text-amber-200 font-mono">DEFENSIVE PROTOCOL:</strong> Never open, click, or test suspicious links directly in your production browser. Hostile web pages may deploy zero-day browser exploits, session-hijacking scripts, or drive-by credential harvesters. Always analyze links through an isolated security perimeter.
          </p>
        </div>
      </div>

      {/* Preset Test Scenarios */}
      <div className="cyber-card p-4 border border-slate-800 space-y-2.5">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Forensic Test Sample Targets:</span>
          </div>
          <span className="text-[10px] text-slate-500 hidden sm:inline">Click to prefill & inspect</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {sampleUrls.map((s, i) => (
            <button
              key={i}
              type="button"
              onClick={() => {
                setUrl(s.url);
                setScanError(null);
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-950/80 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-cyan-500/50 hover:text-cyan-300 transition-all font-mono"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Scanner Form */}
      <form onSubmit={e => handleScanUrl(e)} className="cyber-card p-6 border border-slate-800 space-y-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="url-input" className="block text-xs font-mono uppercase tracking-wider text-slate-300">
              Target URL Address to Inspect:
            </label>
            <span className="text-[11px] font-mono text-cyan-400">HTTP & HTTPS Web Protocols</span>
          </div>

          <div className="relative">
            <input
              id="url-input"
              ref={inputRef}
              type="text"
              value={url}
              onChange={e => {
                setUrl(e.target.value);
                if (scanError) setScanError(null);
              }}
              placeholder="e.g. paypa1-account-verify.xyz/login.php or https://bank-login.top"
              className="w-full pl-4 pr-12 py-3 rounded-xl bg-slate-950/90 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-xs sm:text-sm text-slate-100 placeholder-slate-600 font-mono transition-all outline-none"
            />
            {url && (
              <button
                type="button"
                onClick={() => setUrl('')}
                className="absolute right-3 top-3 text-slate-500 hover:text-slate-300 p-1 text-xs"
                title="Clear input"
              >
                ✕
              </button>
            )}
          </div>
          <p className="text-[11px] text-slate-500 mt-1.5 font-sans">
            URLs entered without <code className="text-cyan-400 font-mono">https://</code> are safely normalized automatically without changing the intended destination.
          </p>
        </div>

        {/* Scan Error Message */}
        {scanError && (
          <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-500/50 text-red-200 text-xs font-sans flex items-start space-x-2 animate-slide-in">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
            <div className="flex-1 leading-relaxed">
              <strong className="font-semibold block font-mono text-red-300">Invalid URL Target:</strong>
              {scanError}
            </div>
          </div>
        )}

        {/* Active Scan Progress State */}
        {scanning && (
          <div className="p-4 rounded-xl bg-slate-950/80 border border-cyan-500/30 space-y-3 animate-fade-in">
            <div className="flex items-center space-x-3 text-cyan-400">
              <span className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin shrink-0" />
              <span className="text-xs font-mono font-semibold tracking-wide animate-pulse">
                {scanStep || 'Executing URL Threat Intelligence Pipeline...'}
              </span>
            </div>
            <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-400 animate-pulse rounded-full w-full" />
            </div>
          </div>
        )}

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
          <span className="text-[11px] font-mono text-slate-500 flex items-center space-x-1.5">
            <Shield className="w-3.5 h-3.5 text-cyan-500/70" />
            <span>Strict SSRF Perimeter & Zero-Server-Visit Execution Policy</span>
          </span>

          <button
            type="submit"
            disabled={scanning || !url.trim()}
            className="inline-flex items-center justify-center space-x-2 px-6 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wide text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 disabled:opacity-50 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] shrink-0"
          >
            {scanning ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Auditing Target...</span>
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                <span>Execute URL Audit</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* URL Forensic Analysis Report */}
      {report && (() => {
        const verdict = getVerdictDetails(report.data);
        const VerdictIcon = verdict.icon;

        return (
          <div className="space-y-6 animate-slide-in">
            {/* Top Verdict Card */}
            <div className={`cyber-card p-6 border ${verdict.borderColor} ${verdict.glowColor} space-y-6 bg-slate-900/90`}>
              {/* Verdict Header Banner */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div className="flex items-start sm:items-center space-x-3">
                  <div className={`p-2.5 rounded-xl bg-slate-950 border ${verdict.borderColor} shrink-0`}>
                    <VerdictIcon className={`w-6 h-6 ${verdict.iconColor}`} />
                  </div>
                  <div>
                    <span className={`inline-block text-[11px] font-mono uppercase font-bold px-2 py-0.5 rounded-md border ${verdict.badgeColor} mb-1`}>
                      {verdict.title}
                    </span>
                    <p className="text-xs text-slate-300 font-sans leading-relaxed">
                      {verdict.desc}
                    </p>
                  </div>
                </div>

                {/* Scan Another URL Button */}
                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    type="button"
                    onClick={handleResetScan}
                    className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-mono font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Scan Another URL</span>
                  </button>

                  <Link
                    to={`/reports/${report.scanId}`}
                    className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-mono font-semibold text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 transition-colors"
                  >
                    <span>Full Forensic Dossier</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {/* Target & Normalized Information */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block mb-1">
                    Submitted Input URL:
                  </span>
                  <div className="flex items-center justify-between space-x-2 bg-slate-900 p-2 rounded-lg border border-slate-800">
                    <span className="text-xs font-mono text-slate-200 truncate">{report.data.url}</span>
                    <button
                      onClick={() => handleCopyUrl(report.data.url)}
                      className="p-1 hover:text-cyan-400 text-slate-400 transition-colors"
                      title="Copy URL"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block mb-1">
                    Normalized Hostname & Port:
                  </span>
                  <div className="flex items-center justify-between space-x-2 bg-slate-900 p-2 rounded-lg border border-slate-800">
                    <span className="text-xs font-mono text-cyan-300 font-semibold truncate">
                      {report.data.parsed.hostname}{report.data.parsed.port ? `:${report.data.parsed.port}` : ''}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500 uppercase px-1.5 py-0.5 rounded bg-slate-800">
                      {report.data.parsed.protocol}
                    </span>
                  </div>
                </div>
              </div>

              {/* Score Gauge & Explanation */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                <div className="flex flex-col items-center justify-center p-4 bg-slate-950/60 rounded-xl border border-slate-800/80">
                  <ThreatGauge score={report.data.analysis.risk_score} size="md" />
                  <div className="mt-2 text-center">
                    <ThreatBadge
                      prediction={report.data.analysis.prediction}
                      category={report.data.analysis.category}
                    />
                  </div>
                </div>

                <div className="md:col-span-2 space-y-3">
                  <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold block mb-1">
                      Threat Intelligence Summary:
                    </span>
                    <p className="text-sm text-slate-100 font-medium leading-relaxed">
                      {report.data.analysis.summary}
                    </p>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-950/40 border border-slate-800/60">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold block mb-1">
                      Forensic Rationale:
                    </span>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {report.data.analysis.explanation}
                    </p>
                  </div>
                </div>
              </div>

              {/* Suspicious URL Features Detected (Grid Cards) */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
                  Suspicious Characteristics & Vectors Audit
                </h3>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {/* Brand Typo / Lookalike */}
                  <div className={`p-3 rounded-lg border ${report.data.features.hasLookalikeBrand ? 'bg-red-950/30 border-red-500/40 text-red-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Brand Mimicry</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.features.hasLookalikeBrand ? `Flagged (${report.data.features.matchedBrand})` : 'Clean'}
                    </span>
                  </div>

                  {/* Misleading Subdomain */}
                  <div className={`p-3 rounded-lg border ${report.data.features.hasMisleadingSubdomain ? 'bg-red-950/30 border-red-500/40 text-red-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Subdomain Mimicry</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.features.hasMisleadingSubdomain ? 'Flagged Deceptive' : 'Standard'}
                    </span>
                  </div>

                  {/* Punycode Homograph */}
                  <div className={`p-3 rounded-lg border ${report.data.features.hasPunycode ? 'bg-red-950/30 border-red-500/40 text-red-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Punycode / IDN</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.features.hasPunycode ? 'Flagged (xn--)' : 'Standard ASCII'}
                    </span>
                  </div>

                  {/* Unusual Port */}
                  <div className={`p-3 rounded-lg border ${report.data.features.hasUnusualPort ? 'bg-amber-950/30 border-amber-500/40 text-amber-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Service Port</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.features.hasUnusualPort ? `Non-standard (:${report.data.parsed.port})` : `Standard (:${report.data.parsed.port})`}
                    </span>
                  </div>

                  {/* URL Shortener */}
                  <div className={`p-3 rounded-lg border ${report.data.features.isUrlShortener ? 'bg-amber-950/30 border-amber-500/40 text-amber-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">URL Shortener</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.features.isUrlShortener ? 'Active Shortener' : 'Direct Link'}
                    </span>
                  </div>

                  {/* High Risk TLD */}
                  <div className={`p-3 rounded-lg border ${report.data.features.hasHighRiskTld ? 'bg-red-950/30 border-red-500/40 text-red-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">TLD Risk Category</span>
                    <span className="text-xs font-mono font-semibold">
                      .{report.data.parsed.tld} {report.data.features.hasHighRiskTld ? '(Disposable)' : ''}
                    </span>
                  </div>

                  {/* Deceptive Path */}
                  <div className={`p-3 rounded-lg border ${report.data.features.hasDeceptivePath ? 'bg-red-950/30 border-red-500/40 text-red-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Auth Keywords</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.features.hasDeceptivePath ? 'Harvesting Pattern' : 'Clean Path'}
                    </span>
                  </div>

                  {/* Raw IP Address */}
                  <div className={`p-3 rounded-lg border ${report.data.parsed.isIpAddress ? 'bg-red-950/30 border-red-500/40 text-red-200' : 'bg-slate-950/60 border-slate-800 text-slate-300'}`}>
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Host Format</span>
                    <span className="text-xs font-mono font-semibold">
                      {report.data.parsed.isIpAddress ? 'Numerical IP' : 'Registered Domain'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Specific Extracted Risk Indicators */}
              {report.data.analysis.indicators && report.data.analysis.indicators.length > 0 && (
                <div className="space-y-3 pt-3 border-t border-slate-800">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
                    Detected Threat Indicators ({report.data.analysis.indicators.length})
                  </h3>
                  <div className="space-y-2">
                    {report.data.analysis.indicators.map((ind, i) => (
                      <div
                        key={i}
                        className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-start space-x-3 text-xs"
                      >
                        <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <code className="text-cyan-300 font-mono text-[11px] bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                            {ind.phrase}
                          </code>
                          <p className="text-slate-300 text-xs mt-1 leading-relaxed">{ind.reason}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Available Technical Checks */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
                    Available Security Audits Completed ({report.data.availableChecks.length})
                  </h3>
                </div>

                <div className="space-y-2">
                  {report.data.availableChecks.map((check, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-start justify-between gap-3 text-xs"
                    >
                      <div className="flex items-start space-x-2.5">
                        {check.status === 'flagged' ? (
                          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        ) : (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <span className="font-semibold text-slate-200">{check.name}</span>
                          <p className="text-slate-400 text-[11px] mt-0.5">{check.details}</p>
                        </div>
                      </div>
                      <span
                        className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold shrink-0 ${
                          check.status === 'flagged'
                            ? 'bg-amber-950/60 text-amber-400 border border-amber-800/40'
                            : 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40'
                        }`}
                      >
                        {check.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Unavailable Checks (Declared honestly) */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="flex items-center space-x-2">
                  <HelpCircle className="w-4 h-4 text-slate-500" />
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-400">
                    Unavailable Technical Checks ({report.data.unavailableChecks.length})
                  </h3>
                </div>

                <div className="space-y-2">
                  {report.data.unavailableChecks.map((check, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/60 flex items-start justify-between gap-3 text-xs opacity-80"
                    >
                      <div className="flex items-start space-x-2.5">
                        <XCircle className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                        <div>
                          <span className="font-semibold text-slate-400">{check.name}</span>
                          <p className="text-slate-500 text-[11px] mt-0.5">{check.details}</p>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800/60 text-slate-400 border border-slate-700/40 shrink-0">
                        Unavailable
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Precautions Checklist */}
              {report.data.analysis.recommendations && report.data.analysis.recommendations.length > 0 && (
                <div className="space-y-2.5 pt-3 border-t border-slate-800">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
                    Recommended Security Precautions
                  </h3>
                  <div className="space-y-1.5">
                    {report.data.analysis.recommendations.map((rec, i) => (
                      <div
                        key={i}
                        className="flex items-start space-x-2.5 text-xs text-slate-200 bg-slate-950/60 p-3 rounded-lg border border-slate-800"
                      >
                        <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                        <span className="leading-relaxed">{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Mandatory Defensive Disclaimer */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 text-[11px] font-sans text-slate-400 space-y-1">
                <span className="font-mono text-cyan-400 font-semibold block uppercase">
                  Important Threat Intelligence Disclaimer:
                </span>
                <p className="leading-relaxed">
                  {report.data.disclaimer || 'Automated security checks and heuristic AI models cannot guarantee complete safety. Zero-day domains or compromised authentic infrastructure may evade detection. Always verify the domain origin and sender identity before submitting confidential credentials.'}
                </p>
                <div className="text-[10px] font-mono text-slate-500 pt-1 flex items-center space-x-2">
                  <Clock className="w-3 h-3 text-slate-500" />
                  <span>Audited on: {new Date(report.data.scanTimestamp || Date.now()).toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Authenticated Analyst's Recent URL Scan History */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs sm:text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
              Analyst Recent URL Audit History
            </h2>
          </div>
          <Link
            to="/history"
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
          >
            <span>Full History</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {loadingHistory ? (
          <div className="py-8 flex justify-center items-center text-xs font-mono text-slate-500 space-x-2">
            <span className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <span>Loading database records...</span>
          </div>
        ) : urlHistory.length === 0 ? (
          <p className="text-xs text-slate-500 font-mono py-4 text-center">
            No URL audits recorded yet. Submit a URL address above to initiate your first scan.
          </p>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {urlHistory.map(scan => (
              <div
                key={scan.id}
                className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-900/40 px-2 rounded-lg transition-colors"
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center space-x-2">
                    <ThreatBadge prediction={scan.prediction} category={scan.category} />
                    <span className="text-[10px] font-mono text-slate-500">
                      Score: <strong className="text-slate-200">{scan.riskScore}/100</strong>
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-300 truncate max-w-lg">
                    {scan.inputSummary}
                  </p>
                </div>

                <div className="flex items-center space-x-3 shrink-0">
                  <span className="text-[11px] font-mono text-slate-500">
                    {new Date(scan.createdAt).toLocaleDateString()}
                  </span>
                  <Link
                    to={`/reports/${scan.id}`}
                    className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-cyan-300 transition-colors"
                    title="View Forensic Report"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
