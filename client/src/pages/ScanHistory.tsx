import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScanItem } from '../types';
import { ThreatBadge } from '../components/ThreatBadge';
import { Modal } from '../components/Modal';
import { ThreatGauge } from '../components/ThreatGauge';
import { useToast } from '../context/ToastContext';
import {
  History,
  Search,
  Download,
  Trash2,
  Eye,
  Filter,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  FileSpreadsheet,
  FileJson,
  FileText,
  AlertTriangle,
} from 'lucide-react';
import { Link } from 'react-router-dom';

export const ScanHistory: React.FC = () => {
  const { showToast } = useToast();
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const limit = 10;

  // Filter States
  const [search, setSearch] = useState('');
  const [scanType, setScanType] = useState('all');
  const [prediction, setPrediction] = useState('all');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('desc');

  // Detail Modal State
  const [selectedScan, setSelectedScan] = useState<ScanItem | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Delete Confirmation State
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const res = await api.getScans({
        page,
        limit,
        search,
        scanType,
        prediction,
        sortBy,
        sortOrder,
      });
      setScans(res.scans || []);
      setTotal(res.total || 0);
    } catch (err: any) {
      showToast(err.message || 'Failed to retrieve scan history.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [page, search, scanType, prediction, sortBy, sortOrder]);

  const handleOpenDetail = async (id: string) => {
    try {
      setLoadingDetail(true);
      const res = await api.getScan(id);
      setSelectedScan(res.scan);
    } catch (err: any) {
      showToast(err.message || 'Could not load scan details.', 'error');
    } finally {
      setLoadingDetail(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteId) return;
    try {
      setDeleting(true);
      await api.deleteScan(deleteId);
      showToast('Scan record deleted successfully.', 'success');
      setDeleteId(null);
      fetchScans();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete scan.', 'error');
    } finally {
      setDeleting(false);
    }
  };

  const handleExportCsv = async () => {
    try {
      await api.downloadExportCsv();
      showToast('CSV export downloaded.', 'success');
    } catch (err: any) {
      showToast('Failed to export CSV.', 'error');
    }
  };

  const handleExportJson = async () => {
    try {
      await api.downloadExportJson();
      showToast('JSON export downloaded.', 'success');
    } catch (err: any) {
      showToast('Failed to export JSON.', 'error');
    }
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Header & Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold font-mono text-slate-100">
              Forensic Scan History
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Browse, filter, inspect, and export persistent threat audit records for your account.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleExportCsv}
            disabled={total === 0}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 transition-colors disabled:opacity-40"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleExportJson}
            disabled={total === 0}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 transition-colors disabled:opacity-40"
          >
            <FileJson className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-card p-4 border border-slate-800 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
        {/* Search Input */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search keywords, categories..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 text-slate-200 placeholder-slate-600 font-sans"
          />
        </div>

        {/* Scan Type Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-slate-400 font-mono text-[11px] shrink-0">Type:</span>
          <select
            value={scanType}
            onChange={e => {
              setScanType(e.target.value);
              setPage(1);
            }}
            className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500"
          >
            <option value="all">All Scanners</option>
            <option value="message">Message / Content</option>
            <option value="url">URL Security</option>
            <option value="social">Social Media</option>
          </select>
        </div>

        {/* Verdict Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-slate-400 font-mono text-[11px] shrink-0">Verdict:</span>
          <select
            value={prediction}
            onChange={e => {
              setPrediction(e.target.value);
              setPage(1);
            }}
            className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500"
          >
            <option value="all">All Verdicts</option>
            <option value="scam">Scam Only</option>
            <option value="suspicious">Suspicious Only</option>
            <option value="genuine">Genuine Only</option>
          </select>
        </div>

        {/* Sorting */}
        <div className="flex items-center space-x-2">
          <span className="text-slate-400 font-mono text-[11px] shrink-0">Sort:</span>
          <select
            value={`${sortBy}-${sortOrder}`}
            onChange={e => {
              const [sb, so] = e.target.value.split('-');
              setSortBy(sb);
              setSortOrder(so);
              setPage(1);
            }}
            className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500"
          >
            <option value="created_at-desc">Newest First</option>
            <option value="created_at-asc">Oldest First</option>
            <option value="risk_score-desc">Highest Threat Score</option>
            <option value="risk_score-asc">Lowest Threat Score</option>
          </select>
        </div>
      </div>

      {/* Scans Table */}
      <div className="cyber-card border border-slate-800 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            <span className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin inline-block mr-2" />
            Loading scan history...
          </div>
        ) : scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Channel</th>
                  <th className="py-3 px-4">Summary</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
                {scans.map(scan => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-200 capitalize">
                      {scan.scanType}
                    </td>
                    <td className="py-3 px-4 max-w-xs truncate text-slate-400 font-sans text-xs">
                      {scan.inputSummary}
                    </td>
                    <td className="py-3 px-4">
                      <ThreatBadge prediction={scan.prediction} size="sm" />
                    </td>
                    <td className="py-3 px-4">
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
                    <td className="py-3 px-4 text-[11px] text-cyan-400">
                      {scan.category.replace(/_/g, ' ')}
                    </td>
                    <td className="py-3 px-4 text-[11px] text-slate-500 whitespace-nowrap">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="inline-flex items-center space-x-2">
                        <button
                          onClick={() => handleOpenDetail(scan.id)}
                          title="View Details"
                          className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <Link
                          to={`/reports/${scan.id}`}
                          title="Generate Report"
                          className="p-1.5 rounded text-slate-400 hover:text-blue-400 hover:bg-slate-800 transition-colors"
                        >
                          <FileText className="w-3.5 h-3.5" />
                        </Link>
                        <button
                          onClick={() => setDeleteId(scan.id)}
                          title="Delete Record"
                          className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-12 text-center text-slate-500 font-mono text-xs">
            No matching scan records found.
          </div>
        )}

        {/* Pagination Bar */}
        {total > 0 && (
          <div className="px-4 py-3 bg-slate-950/60 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>
              Showing {(page - 1) * limit + 1}–{Math.min(page * limit, total)} of {total} records
            </span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span>
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      <Modal
        isOpen={!!selectedScan}
        onClose={() => setSelectedScan(null)}
        title={`Scan Inspection: ${selectedScan?.id?.slice(0, 8)}`}
        maxWidth="xl"
      >
        {selectedScan && (
          <div className="space-y-4 text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <ThreatBadge
                prediction={selectedScan.prediction}
                category={selectedScan.category}
              />
              <span className="font-mono text-slate-400">
                Threat Score: <strong className="text-cyan-400">{selectedScan.riskScore}/100</strong>
              </span>
            </div>

            <div>
              <span className="text-slate-400 font-mono uppercase text-[10px]">Submitted Content:</span>
              <div className="mt-1 p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-slate-300 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                {selectedScan.inputRaw || selectedScan.inputSummary}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-mono uppercase text-[10px]">Forensic Explanation:</span>
              <p className="mt-1 text-slate-300 leading-relaxed bg-slate-950/50 p-3 rounded-lg border border-slate-800">
                {selectedScan.explanation}
              </p>
            </div>

            {selectedScan.indicators && selectedScan.indicators.length > 0 && (
              <div>
                <span className="text-slate-400 font-mono uppercase text-[10px]">Detected Indicators:</span>
                <div className="mt-1 space-y-1.5">
                  {selectedScan.indicators.map((ind: any, i) => {
                    const phrase = typeof ind === 'string' ? ind : (ind.phrase || ind.text || JSON.stringify(ind));
                    const reason = typeof ind === 'object' && ind.reason ? ind.reason : 'Detected indicator';
                    return (
                      <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px]">
                        <strong className="text-cyan-400">"{phrase}"</strong> — <span className="text-slate-400">{reason}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <Link
                to={`/reports/${selectedScan.id}`}
                className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-lg text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors font-mono"
              >
                <span>View Full Forensic Report</span>
              </Link>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteId}
        onClose={() => setDeleteId(null)}
        title="Confirm Record Deletion"
        maxWidth="sm"
      >
        <div className="space-y-4">
          <div className="flex items-start space-x-3 text-xs text-slate-300">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <p>
              Are you sure you want to permanently delete this scan record? This operation cannot be undone.
            </p>
          </div>

          <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setDeleteId(null)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={confirmDelete}
              disabled={deleting}
              className="px-4 py-1.5 rounded-lg text-xs font-bold text-white bg-red-600 hover:bg-red-500 transition-colors font-mono disabled:opacity-50"
            >
              {deleting ? 'Deleting...' : 'Delete Record'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
