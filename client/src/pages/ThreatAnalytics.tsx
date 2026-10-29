import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AnalyticsData } from '../types';
import { StatCard } from '../components/StatCard';
import { useToast } from '../context/ToastContext';
import {
  BarChart3,
  TrendingUp,
  PieChart as PieIcon,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Search,
  Layers,
  Info,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
} from 'recharts';

export const ThreatAnalytics: React.FC = () => {
  const { showToast } = useToast();
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAnalytics()
      .then(data => setAnalytics(data))
      .catch(err => showToast(err.message || 'Failed to load telemetry.', 'error'))
      .finally(() => setLoading(false));
  }, []);

  const categoryColors = ['#06B6D4', '#3B82F6', '#8B5CF6', '#EC4899', '#EF4444', '#F59E0B', '#10B981'];

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Header & Disclaimer */}
      <div className="space-y-3 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <BarChart3 className="w-5 h-5 text-cyan-400" />
          <h1 className="text-xl font-bold font-mono text-slate-100">
            Threat Intelligence & Analytics
          </h1>
        </div>
        <p className="text-xs text-slate-400">
          Aggregated quantitative threat metrics derived from authenticated forensic scan records.
        </p>

        {/* Clear Disclaimer per Requirement 11 */}
        <div className="flex items-start space-x-3 p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 text-xs">
          <Info className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
          <p>
            <strong className="text-cyan-300 font-semibold">Data Scope Statement:</strong> The statistics and distributions displayed below reflect real scans stored within this system's database. They reflect user-submitted forensic triage records and do not represent the total volume of malicious activity across the global internet.
          </p>
        </div>
      </div>

      {/* Top 4 Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={analytics?.summary?.totalScans ?? 0}
          subtitle="Lifetime account volume"
          icon={Search}
          variant="cyan"
        />
        <StatCard
          title="Scams Blocked"
          value={analytics?.summary?.scamsDetected ?? 0}
          subtitle="Score >= 60"
          icon={ShieldAlert}
          variant="red"
        />
        <StatCard
          title="Suspicious Messages"
          value={analytics?.summary?.suspiciousContent ?? 0}
          subtitle="Score 30-59"
          icon={AlertTriangle}
          variant="amber"
        />
        <StatCard
          title="Genuine Validations"
          value={analytics?.summary?.genuineContent ?? 0}
          subtitle="Score 0-29"
          icon={ShieldCheck}
          variant="emerald"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 7-Day Timeline Area Chart (7 cols) */}
        <div className="lg:col-span-7 cyber-card p-6 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                7-Day Threat Activity Timeline
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Total vs Scams</span>
          </div>

          <div className="h-64 w-full">
            {analytics?.dailyActivity && analytics.dailyActivity.some(d => d.scans > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={analytics.dailyActivity}>
                  <defs>
                    <linearGradient id="anScans" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="anScams" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                  <XAxis dataKey="day" stroke="#64748B" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
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
                    fill="url(#anScans)"
                    name="All Submissions"
                  />
                  <Area
                    type="monotone"
                    dataKey="scams"
                    stroke="#EF4444"
                    fill="url(#anScams)"
                    name="Scams Confirmed"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-xs">
                No 7-day activity recorded yet.
              </div>
            )}
          </div>
        </div>

        {/* Risk Distribution Donut (5 cols) */}
        <div className="lg:col-span-5 cyber-card p-6 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2">
            <PieIcon className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Threat Score Band Allocation
            </h3>
          </div>

          <div className="h-56 w-full flex items-center justify-center">
            {analytics?.riskDistribution && analytics.riskDistribution.some(r => r.count > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={analytics.riskDistribution}
                    innerRadius={55}
                    outerRadius={80}
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
              <div className="flex items-center justify-center text-slate-500 font-mono text-xs">
                No risk distribution records.
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800">
            {(analytics?.riskDistribution ?? []).map((item, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 rounded bg-slate-950/40 border border-slate-800/80">
                <div className="flex items-center space-x-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-400 font-mono text-[10px]">{item.name.split(' ')[0]}</span>
                </div>
                <span className="font-mono font-bold text-slate-200 text-xs">{item.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Category Breakdown Bar Chart (7 cols) */}
        <div className="lg:col-span-7 cyber-card p-6 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Scam & Threat Category Breakdown
            </h3>
          </div>

          <div className="h-64 w-full">
            {analytics?.categoryBreakdown && analytics.categoryBreakdown.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analytics.categoryBreakdown} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                  <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="category"
                    stroke="#94A3B8"
                    fontSize={11}
                    tickLine={false}
                    width={110}
                    tickFormatter={val => val.replace(/_/g, ' ')}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0F172A',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" fill="#06B6D4" radius={[0, 4, 4, 0]}>
                    {analytics.categoryBreakdown.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={categoryColors[index % categoryColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-xs">
                No categorized threats identified yet.
              </div>
            )}
          </div>
        </div>

        {/* Channel Breakdown (5 cols) */}
        <div className="lg:col-span-5 cyber-card p-6 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-purple-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Triage Channel Breakdown
            </h3>
          </div>

          <div className="space-y-3 pt-2">
            {analytics?.typeBreakdown && analytics.typeBreakdown.length > 0 ? (
              analytics.typeBreakdown.map((tb, idx) => {
                const total = analytics.summary?.totalScans || 1;
                const pct = Math.round((tb.count / total) * 100);
                return (
                  <div key={idx} className="space-y-1.5 p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="capitalize font-semibold text-slate-200">
                        {tb.type === 'message' ? 'Message & Content' : tb.type === 'url' ? 'URL Security' : 'Social Media'}
                      </span>
                      <span className="text-cyan-400">
                        {tb.count} ({pct}%)
                      </span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="p-8 text-center text-slate-500 font-mono text-xs">
                No channel volume recorded yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
