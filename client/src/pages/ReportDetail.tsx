import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../services/api';
import { ForensicReport } from '../types';
import { ThreatGauge } from '../components/ThreatGauge';
import { ThreatBadge } from '../components/ThreatBadge';
import { useToast } from '../context/ToastContext';
import {
  FileCheck,
  Download,
  Printer,
  ChevronLeft,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Clock,
  Layers,
  Info,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

export const ReportDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { showToast } = useToast();
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    api.getReport(id)
      .then(res => setReport(res.report))
      .catch(err => showToast(err.message || 'Failed to generate forensic report.', 'error'))
      .finally(() => setLoading(false));
  }, [id]);

  const handleDownloadTxt = async () => {
    if (!report) return;
    try {
      await api.downloadReportTxt(report.scanId, `${report.reportId}.txt`);
      showToast('TXT report downloaded.', 'success');
    } catch {
      showToast('Failed to download TXT.', 'error');
    }
  };

  const handleDownloadJson = async () => {
    if (!report) return;
    try {
      await api.downloadReportJson(report.scanId, `${report.reportId}.json`);
      showToast('JSON report downloaded.', 'success');
    } catch {
      showToast('Failed to download JSON.', 'error');
    }
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto p-12 text-center text-slate-400 font-mono text-xs">
        <span className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin inline-block mr-2" />
        Generating automated forensic dossier...
      </div>
    );
  }

  if (!report) {
    return (
      <div className="max-w-4xl mx-auto p-12 text-center text-slate-500 font-mono text-xs cyber-card">
        <p>Report not found or access denied.</p>
        <Link to="/reports" className="mt-4 inline-block text-cyan-400 underline">
          Return to Reports
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-fade-in print:bg-white print:text-black">
      {/* Top Action Bar (hidden on print) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800 print:hidden">
        <Link
          to="/reports"
          className="inline-flex items-center space-x-1.5 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <ChevronLeft className="w-4 h-4" />
          <span>Back to All Reports</span>
        </Link>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => window.print()}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
          <button
            onClick={handleDownloadTxt}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Download TXT</span>
          </button>
          <button
            onClick={handleDownloadJson}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold transition-colors font-mono"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download JSON</span>
          </button>
        </div>
      </div>

      {/* Official Forensic Report Document */}
      <div className="cyber-card p-8 border border-slate-800 bg-slate-900/90 rounded-2xl space-y-8 shadow-2xl print:border-none print:shadow-none print:bg-white print:text-black">
        {/* Header Block */}
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono text-cyan-400 font-bold tracking-widest uppercase">
                SCAMGUARD AI // THREAT ADVISORY
              </span>
            </div>
            <h1 className="text-2xl font-bold font-mono text-slate-100 tracking-tight mt-1">
              Automated Forensic Analysis Report
            </h1>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Report ID: <span className="text-cyan-400 font-bold">{report.reportId}</span>
            </p>
          </div>

          <div className="text-right sm:text-right font-mono text-xs text-slate-400 space-y-1">
            <p>Generated: {new Date(report.generatedAt).toLocaleString()}</p>
            <p>Original Scan: {new Date(report.scanTimestamp).toLocaleString()}</p>
            <p>Analysis Engine: <span className="text-slate-200">{report.analysisEngine}</span></p>
          </div>
        </div>

        {/* Verdict Summary Card */}
        {(() => {
          const classification = report.classification || (report.prediction === 'scam' ? 'SCAM' : report.prediction === 'suspicious' ? 'SUSPICIOUS' : 'SAFE');
          const riskLevel = report.riskLevel || (report.riskScore >= 80 ? 'CRITICAL' : report.riskScore >= 60 ? 'HIGH' : report.riskScore >= 30 ? 'MEDIUM' : 'LOW');
          const riskBadgeStyles = {
            CRITICAL: 'bg-red-950/70 text-red-300 border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.25)]',
            HIGH: 'bg-orange-950/70 text-orange-300 border-orange-500/50 shadow-[0_0_12px_rgba(249,115,22,0.25)]',
            MEDIUM: 'bg-amber-950/70 text-amber-300 border-amber-500/50 shadow-[0_0_12px_rgba(245,158,11,0.2)]',
            LOW: 'bg-emerald-950/70 text-emerald-300 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.2)]',
          }[riskLevel] || 'bg-slate-900 text-slate-300 border-slate-700';

          return (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 rounded-xl bg-slate-950/60 border border-slate-800 items-center">
              <div className="flex justify-center">
                <ThreatGauge score={report.riskScore} size="md" showDetails={false} />
              </div>

              <div className="md:col-span-2 space-y-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  <ThreatBadge prediction={report.prediction} category={report.category} />
                  <div className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider border ${riskBadgeStyles}`}>
                    <span>{classification}</span>
                    <span className="mx-1 text-slate-500">•</span>
                    <span>{riskLevel} RISK</span>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Confidence: <strong>{typeof report.confidence === 'number' ? (report.confidence > 1 ? Math.min(100, Math.round(report.confidence)) : Math.min(100, Math.round(report.confidence * 100))) : 85}%</strong>
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-slate-300 font-medium leading-relaxed">
                  {report.explanation}
                </p>
              </div>
            </div>
          );
        })()}

        {/* Submitted Telemetry Input */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-400">
            Submitted Target Telemetry
          </h3>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
            {report.inputRaw || report.inputSummary}
          </div>
        </div>

        {/* Identified Key Threat Indicators */}
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
              Corroborating Threat Indicators ({report.indicators?.length || 0})
            </h3>
          </div>

          {report.indicators && report.indicators.length > 0 ? (
            <div className="space-y-2">
              {report.indicators.map((ind: any, idx) => {
                const phrase = typeof ind === 'string' ? ind : (ind.phrase || ind.text || JSON.stringify(ind));
                const reason = typeof ind === 'object' && ind.reason ? ind.reason : 'Corroborating forensic threat indicator';
                return (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-3 text-xs"
                  >
                    <span className="font-mono text-cyan-400 font-bold shrink-0">
                      [{idx + 1}]
                    </span>
                    <div>
                      <span className="font-mono font-semibold text-slate-200">
                        "{phrase}"
                      </span>
                      <p className="text-slate-400 text-xs mt-0.5">{reason}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 text-xs text-slate-500 font-mono">
              No prominent threat indicators extracted.
            </div>
          )}
        </div>

        {/* Actionable Recommendations */}
        {report.recommendations && report.recommendations.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">
                Actionable Remediation Directives
              </h3>
            </div>

            <div className="space-y-2">
              {report.recommendations.map((rec, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-emerald-950/10 border border-emerald-900/30 flex items-start space-x-3 text-xs text-slate-300"
                >
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Verification Limitations & Disclaimer (Mandatory per Requirement 12) */}
        <div className="pt-6 border-t border-slate-800 space-y-3 text-xs text-slate-500 font-mono">
          <div className="flex items-start space-x-2.5 p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="text-slate-400 font-semibold">{report.disclaimer || 'Automated Cybersecurity Threat Intelligence Report.'}</p>
              <ul className="list-disc list-inside space-y-0.5 text-[11px] text-slate-500">
                {Array.isArray(report.limitations) ? (
                  report.limitations.map((lim, i) => (
                    <li key={i}>{lim}</li>
                  ))
                ) : report.limitations ? (
                  <li>{String(report.limitations)}</li>
                ) : (
                  <li>Automated telemetry analysis completed without specific limitations.</li>
                )}
              </ul>
            </div>
          </div>

          <div className="text-center pt-2">
            <p className="text-[10px] text-slate-600">
              SCAMGUARD AI // BCA Final-Year Cybersecurity & AI Project // End of Dossier
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
