import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScanItem } from '../types';
import { ThreatBadge } from '../components/ThreatBadge';
import { useToast } from '../context/ToastContext';
import {
  FileCheck,
  Search,
  FileText,
  Download,
  ExternalLink,
  Shield,
  Calendar,
  Layers,
} from 'lucide-react';
import { Link } from 'react-router-dom';

export const ForensicReports: React.FC = () => {
  const { showToast } = useToast();
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    api.getScans({ limit: 50, search })
      .then(res => setScans(res.scans || []))
      .catch(err => showToast(err.message || 'Failed to load report candidate scans.', 'error'))
      .finally(() => setLoading(false));
  }, [search]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="space-y-2 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <FileCheck className="w-5 h-5 text-cyan-400" />
          <h1 className="text-xl font-bold font-mono text-slate-100">
            Forensic Threat Intelligence Reports
          </h1>
        </div>
        <p className="text-xs text-slate-400">
          Generate structured, exportable incident analysis reports for any completed scam triage record. Suitable for audit trails, security team handoffs, and user awareness documentation.
        </p>
      </div>

      {/* Search Bar */}
      <div className="cyber-card p-4 border border-slate-800">
        <div className="relative max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search scans to generate report..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-600 font-sans focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Reports Candidates Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          <div className="col-span-full p-12 text-center text-slate-400 font-mono text-xs">
            <span className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin inline-block mr-2" />
            Loading scan dossiers...
          </div>
        ) : scans.length > 0 ? (
          scans.map(scan => (
            <div
              key={scan.id}
              className="cyber-card p-5 border border-slate-800 flex flex-col justify-between space-y-4 hover:border-cyan-500/40 transition-all"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800">
                    {scan.scanType}
                  </span>
                  <ThreatBadge prediction={scan.prediction} size="sm" />
                </div>

                <p className="text-xs text-slate-300 font-sans line-clamp-2">
                  {scan.inputSummary}
                </p>

                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                  <span>
                    Score: <strong className={scan.riskScore >= 60 ? 'text-red-400' : 'text-emerald-400'}>{scan.riskScore}/100</strong>
                  </span>
                  <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-500">
                  {scan.engine === 'gemini' ? 'Gemini AI Model' : 'Heuristic Engine'}
                </span>
                <Link
                  to={`/reports/${scan.id}`}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors font-mono"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Open Report</span>
                </Link>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full p-12 text-center text-slate-500 font-mono text-xs cyber-card">
            No completed scan dossiers found. Run scans in the Message Scanner or URL Scanner to generate reports.
          </div>
        )}
      </div>
    </div>
  );
};
