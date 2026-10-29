import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AdminOverviewData } from '../types';
import { StatCard } from '../components/StatCard';
import { useToast } from '../context/ToastContext';
import {
  ShieldAlert,
  Users,
  Search,
  Cpu,
  Server,
  Activity,
  AlertTriangle,
  ShieldCheck,
  Sparkles,
  Clock,
  Terminal,
} from 'lucide-react';

export const AdminDashboard: React.FC = () => {
  const { showToast } = useToast();
  const [data, setData] = useState<AdminOverviewData | null>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.getAdminOverview(), api.getAdminUsers()])
      .then(([overviewRes, usersRes]) => {
        setData(overviewRes);
        setUsers(usersRes.users || []);
      })
      .catch(err => {
        showToast(err.message || 'Failed to load administrator telemetry.', 'error');
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono text-xs">
        <span className="w-5 h-5 border-2 border-red-500 border-t-transparent rounded-full animate-spin inline-block mr-2" />
        Verifying administrator authorization and loading telemetry...
      </div>
    );
  }

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${d > 0 ? `${d}d ` : ''}${h}h ${m}m ${s}s`;
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Admin Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-900 border border-red-900/40 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-red-400 font-bold px-1.5 py-0.5 rounded bg-red-950 border border-red-800">
              RESTRICTED SOC CLEARANCE
            </span>
          </div>
          <h1 className="text-xl font-bold font-mono text-slate-100 mt-2">
            Super Administrator Operations Control
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            System-wide user accounts, global scan counts, threat distribution telemetry, and audit logs.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-slate-300">
          <Server className="w-4 h-4 text-cyan-400" />
          <span>Uptime: {formatUptime(data?.systemHealth?.uptimeSeconds || 0)}</span>
        </div>
      </div>

      {/* Global Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Registered Users"
          value={data?.telemetry.totalUsers ?? 0}
          subtitle="Platform accounts"
          icon={Users}
          variant="cyan"
        />
        <StatCard
          title="Global Scans"
          value={data?.telemetry.totalScans ?? 0}
          subtitle="All platform submissions"
          icon={Search}
          variant="blue"
        />
        <StatCard
          title="Scams Flagged"
          value={data?.telemetry.totalScams ?? 0}
          subtitle="Critical security threats"
          icon={ShieldAlert}
          variant="red"
        />
        <StatCard
          title="Active Sessions"
          value={data?.telemetry.activeSessions ?? 0}
          subtitle="Signed authenticated tokens"
          icon={Activity}
          variant="emerald"
        />
      </div>

      {/* Engine Telemetry & Health */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Gemini Engine Telemetry */}
        <div className="cyber-card p-5 border border-slate-800 space-y-3">
          <div className="flex items-center space-x-2 pb-2 border-b border-slate-800">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
              AI Analysis Integration
            </h3>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Gemini Cloud API:</span>
              <span className={`font-bold ${data?.geminiStatus.configured ? 'text-emerald-400' : 'text-amber-400'}`}>
                {data?.geminiStatus.configured ? 'ACTIVE (Online)' : 'OFFLINE (Heuristic Mode)'}
              </span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Configured Model:</span>
              <span className="text-cyan-300 font-semibold">{data?.geminiStatus.model}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Engine Triage Ratio:</span>
              <span className="text-slate-200">
                {data?.telemetry.geminiScans} Gemini / {data?.telemetry.heuristicScans} Heuristic
              </span>
            </div>
          </div>
        </div>

        {/* Server Process Telemetry */}
        <div className="cyber-card p-5 border border-slate-800 space-y-3">
          <div className="flex items-center space-x-2 pb-2 border-b border-slate-800">
            <Server className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
              Server Host Telemetry
            </h3>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Node Runtime:</span>
              <span className="text-slate-200">{data?.systemHealth.nodeVersion}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Heap Memory Used:</span>
              <span className="text-slate-200">{data?.systemHealth.memoryUsageMb} MB</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Environment:</span>
              <span className="text-cyan-400 capitalize">{data?.systemHealth.environment}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Registered Users Table (Sanitized per Requirement 15) */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2">
          <Users className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            Registered Analyst Accounts ({users.length})
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Name</th>
                <th className="py-2.5 px-3">Email Address</th>
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Scans Performed</th>
                <th className="py-2.5 px-3">Registered Date</th>
                <th className="py-2.5 px-3">Last Active</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
              {users.map(u => (
                <tr key={u.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-slate-200">{u.name}</td>
                  <td className="py-2.5 px-3 text-slate-400">{u.email}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        u.role === 'admin'
                          ? 'bg-red-950/70 text-red-400 border border-red-800/50'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {u.role.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-bold text-cyan-400">{u.scanCount}</td>
                  <td className="py-2.5 px-3 text-[11px] text-slate-500">
                    {new Date(u.createdAt).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 px-3 text-[11px] text-slate-500">
                    {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Log Trail */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            System Security Audit Trail
          </h3>
        </div>

        <div className="space-y-2">
          {data?.recentLogs && data.recentLogs.length > 0 ? (
            data.recentLogs.map(log => (
              <div
                key={log.id}
                className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs font-mono"
              >
                <div className="flex items-center space-x-3">
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-900 text-cyan-400 border border-slate-800 font-bold">
                    {log.action}
                  </span>
                  <span className="text-slate-300">{log.details}</span>
                </div>
                <span className="text-[11px] text-slate-500 whitespace-nowrap">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))
          ) : (
            <p className="text-xs font-mono text-slate-500">No audit events recorded.</p>
          )}
        </div>
      </div>
    </div>
  );
};
