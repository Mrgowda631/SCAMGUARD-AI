import React from 'react';
import { ThreatGauge } from './ThreatGauge';
import { ThreatBadge } from './ThreatBadge';
import { AnalysisResult, UrlAnalysisDetail } from '../types';
import {
  Sparkles,
  ShieldCheck,
  AlertOctagon,
  CheckCircle2,
  Cpu,
  FileText,
  ExternalLink,
  Globe,
  AlertCircle,
  AlertTriangle,
  Target,
  ArrowRightCircle,
  FileSearch,
} from 'lucide-react';
import { Link } from 'react-router-dom';

interface AnalysisResultCardProps {
  analysis: AnalysisResult;
  scanId?: string;
  originalInput?: string;
}

export const AnalysisResultCard: React.FC<AnalysisResultCardProps> = ({
  analysis,
  scanId,
  originalInput,
}) => {
  // Derive classification & risk level if not explicitly provided
  const classification =
    analysis.classification ||
    (analysis.prediction === 'scam' ? 'SCAM' : analysis.prediction === 'suspicious' ? 'SUSPICIOUS' : 'SAFE');
  const riskScore = analysis.risk_score;
  const riskLevel =
    analysis.risk_level ||
    (riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 21 ? 'MEDIUM' : 'LOW');

  const confidencePercent =
    typeof analysis.confidence === 'number'
      ? analysis.confidence > 1
        ? Math.min(100, Math.round(analysis.confidence))
        : Math.min(100, Math.round(analysis.confidence * 100))
      : 85;

  const riskBadgeStyles = {
    CRITICAL: 'bg-red-950/70 text-red-300 border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.25)]',
    HIGH: 'bg-orange-950/70 text-orange-300 border-orange-500/50 shadow-[0_0_12px_rgba(249,115,22,0.25)]',
    MEDIUM: 'bg-amber-950/70 text-amber-300 border-amber-500/50 shadow-[0_0_12px_rgba(245,158,11,0.2)]',
    LOW: 'bg-emerald-950/70 text-emerald-300 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.2)]',
  }[riskLevel];

  const recommendationsList = analysis.recommendations?.length
    ? analysis.recommendations
    : analysis.recommended_action
    ? [analysis.recommended_action]
    : [];

  const isUrlDetail = (urlVal: any): urlVal is UrlAnalysisDetail => {
    return urlVal && typeof urlVal === 'object' && 'found' in urlVal;
  };

  return (
    <div className="cyber-card p-6 border border-slate-800 bg-slate-900/80 rounded-xl space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex flex-wrap items-center gap-2.5">
          <ThreatBadge prediction={analysis.prediction} category={analysis.category} />

          {/* Classification & Risk Level Pill */}
          <div className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider border ${riskBadgeStyles}`}>
            <span>{classification}</span>
            <span className="mx-1 text-slate-500">•</span>
            <span>{riskLevel} RISK</span>
          </div>

          {/* Engine Origin Badge */}
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800/60 border border-slate-700/50 text-xs font-mono text-slate-300">
            {analysis.engine === 'openai' ? (
              <>
                <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-300">OpenAI Neural Engine</span>
              </>
            ) : analysis.engine === 'gemini' ? (
              <>
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-cyan-300">Gemini AI Model</span>
              </>
            ) : (
              <>
                <Cpu className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-amber-300">Stage 2 Rule Engine</span>
              </>
            )}
          </div>

          {/* Analysis Source Flag */}
          {analysis.analysis_source && (
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800/40 text-slate-400 border border-slate-800">
              Source: {analysis.analysis_source}
            </span>
          )}
        </div>

        {scanId && (
          <div className="flex items-center space-x-2">
            <Link
              to={`/reports/${scanId}`}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/50 transition-colors"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Forensic Report</span>
              <ExternalLink className="w-3 h-3 ml-0.5" />
            </Link>
          </div>
        )}
      </div>

      {/* Manual Review Alert Banner (if requires_review is flagged) */}
      {analysis.requires_review && (
        <div className="p-3.5 rounded-xl bg-amber-950/50 border border-amber-600/50 flex items-start space-x-3 text-xs text-amber-200">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <strong className="font-mono font-bold block text-amber-300 uppercase tracking-wider text-[11px]">
              Analyst Discretion Flagged (Requires Human Review):
            </strong>
            <p className="text-amber-200/90 leading-relaxed font-sans">
              This message exhibited ambiguous phrasing, potential evasion, or a scoring variance between contextual AI and security rules. Review sender verification channels carefully.
            </p>
          </div>
        </div>
      )}

      {/* Main Grid: Gauge & Forensic Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
        {/* Threat Gauge */}
        <div className="flex justify-center p-4 bg-slate-950/40 rounded-xl border border-slate-800/60">
          <ThreatGauge score={analysis.risk_score} size="md" />
        </div>

        {/* Executive Summary & Confidence */}
        <div className="md:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Executive Threat Assessment
            </span>
            <span className="text-xs font-mono text-slate-400">
              Confidence:{' '}
              <strong className="text-slate-200">{confidencePercent}%</strong>
            </span>
          </div>

          <p className="text-sm text-slate-200 font-medium leading-relaxed bg-slate-950/30 p-3.5 rounded-lg border border-slate-800/60">
            {analysis.summary}
          </p>

          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            {analysis.explanation}
          </p>
        </div>
      </div>

      {/* Forensic Breakdown: Sender Intent & Requested Action (Phase 3 & 5) */}
      {(analysis.intent || analysis.requested_action) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 text-xs">
          {analysis.intent && (
            <div className="space-y-1">
              <div className="flex items-center space-x-1.5 text-cyan-400 font-mono font-bold uppercase tracking-wider text-[11px]">
                <Target className="w-3.5 h-3.5" />
                <span>Identified Sender Intent</span>
              </div>
              <p className="text-slate-200 font-medium pl-5">{analysis.intent}</p>
            </div>
          )}
          {analysis.requested_action && (
            <div className="space-y-1">
              <div className="flex items-center space-x-1.5 text-amber-400 font-mono font-bold uppercase tracking-wider text-[11px]">
                <ArrowRightCircle className="w-3.5 h-3.5" />
                <span>Target Action Requested</span>
              </div>
              <p className="text-slate-200 font-medium pl-5">{analysis.requested_action}</p>
            </div>
          )}
        </div>
      )}

      {/* Extracted Forensic Evidence Quotes (Phase 3 & 5) */}
      {analysis.evidence && analysis.evidence.length > 0 && (
        <div className="space-y-2 pt-1">
          <div className="flex items-center space-x-2 text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            <FileSearch className="w-4 h-4 text-cyan-400" />
            <span>Extracted Forensic Evidence ({analysis.evidence.length})</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {analysis.evidence.map((ev, i) => (
              <span
                key={i}
                className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-200/90"
              >
                "{ev}"
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Embedded URL Analysis Section (Supports Object and String) */}
      {analysis.url_analysis && (
        <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800/80 flex items-start space-x-3 text-xs">
          <Globe className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1 flex-1">
            <div className="font-mono font-bold text-slate-300 uppercase tracking-wider text-[11px]">
              URL Security Verification:
            </div>
            {isUrlDetail(analysis.url_analysis) ? (
              <div className="space-y-1 text-slate-300 font-mono text-[11px]">
                {analysis.url_analysis.found ? (
                  <>
                    <p className="text-slate-200">
                      Detected Links ({analysis.url_analysis.urls.length}):{' '}
                      <span className="text-cyan-400">{analysis.url_analysis.urls.join(', ')}</span>
                    </p>
                    {analysis.url_analysis.findings.length > 0 && (
                      <ul className="list-disc list-inside text-slate-400 space-y-0.5">
                        {analysis.url_analysis.findings.map((f, i) => (
                          <li key={i}>{f}</li>
                        ))}
                      </ul>
                    )}
                  </>
                ) : (
                  <p className="text-slate-400">No embedded URLs detected in message body.</p>
                )}
              </div>
            ) : (
              <p className="text-slate-400 font-mono text-[12px] leading-relaxed">
                {String(analysis.url_analysis)}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Identified Threat Indicators */}
      {((analysis.indicators && analysis.indicators.length > 0) ||
        (analysis.detected_indicators && analysis.detected_indicators.length > 0)) && (
        <div className="space-y-3 pt-2">
          <div className="flex items-center space-x-2">
            <AlertOctagon className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
              Key Threat Indicators ({analysis.indicators?.length || analysis.detected_indicators?.length})
            </h4>
          </div>

          <div className="grid grid-cols-1 gap-2.5">
            {analysis.indicators && analysis.indicators.length > 0
              ? analysis.indicators.map((ind, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 flex flex-col sm:flex-row sm:items-start justify-between gap-2"
                  >
                    <div className="flex items-start space-x-2">
                      <span className="inline-block px-1.5 py-0.5 rounded text-[11px] font-mono bg-cyan-950/50 text-cyan-300 border border-cyan-800/40 shrink-0">
                        Marker #{i + 1}
                      </span>
                      <div>
                        <span className="text-xs font-semibold text-slate-200 font-mono">
                          "{ind.phrase}"
                        </span>
                        <p className="text-xs text-slate-400 mt-0.5">{ind.reason}</p>
                      </div>
                    </div>
                  </div>
                ))
              : analysis.detected_indicators?.map((indicatorStr, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 flex items-start space-x-2 text-xs"
                  >
                    <span className="inline-block px-1.5 py-0.5 rounded text-[11px] font-mono bg-cyan-950/50 text-cyan-300 border border-cyan-800/40 shrink-0">
                      Indicator #{i + 1}
                    </span>
                    <span className="text-slate-300 font-mono">{indicatorStr}</span>
                  </div>
                ))}
          </div>
        </div>
      )}

      {/* Recommended Security Actions */}
      {recommendationsList.length > 0 && (
        <div className="space-y-2.5 pt-2">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
              Recommended Remediation & Actions
            </h4>
          </div>

          <ul className="space-y-1.5">
            {recommendationsList.map((rec, i) => (
              <li
                key={i}
                className="flex items-start space-x-2 text-xs text-slate-300 bg-emerald-950/15 p-2.5 rounded-lg border border-emerald-900/30"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Forensic Scope & Analytical Limitations */}
      {analysis.limitations && (
        <div className="p-3 rounded-lg bg-slate-950/30 border border-slate-800/60 flex items-start space-x-2 text-[11px] text-slate-400">
          <AlertCircle className="w-3.5 h-3.5 text-amber-500/80 shrink-0 mt-0.5" />
          <span>
            <strong className="text-slate-300 font-mono">Forensic Limitations:</strong>{' '}
            {Array.isArray(analysis.limitations)
              ? analysis.limitations.join(' ')
              : String(analysis.limitations)}
          </span>
        </div>
      )}

      {/* Scanned Input Snippet */}
      {originalInput && (
        <div className="pt-2">
          <details className="text-xs group">
            <summary className="cursor-pointer text-slate-400 hover:text-cyan-400 font-mono select-none">
              ▸ View Raw Submitted Telemetry
            </summary>
            <div className="mt-2 p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-slate-400 text-xs whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
              {originalInput}
            </div>
          </details>
        </div>
      )}
    </div>
  );
};
