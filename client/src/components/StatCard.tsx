import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'red' | 'amber' | 'emerald' | 'blue';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'cyan',
}) => {
  const styles = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]',
      valColor: 'text-cyan-400',
    },
    red: {
      border: 'border-red-500/20 hover:border-red-500/40',
      iconBg: 'bg-red-500/10 text-red-400 border-red-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(239,68,68,0.15)]',
      valColor: 'text-red-400',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
      valColor: 'text-amber-400',
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]',
      valColor: 'text-emerald-400',
    },
    blue: {
      border: 'border-blue-500/20 hover:border-blue-500/40',
      iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(59,130,246,0.15)]',
      valColor: 'text-blue-400',
    },
  }[variant];

  return (
    <div
      className={`group relative p-5 rounded-xl bg-slate-900/60 backdrop-blur-md border ${styles.border} transition-all duration-300 ${styles.glow}`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            {title}
          </p>
          <div className="mt-2 flex items-baseline">
            <span className={`text-3xl font-bold font-mono tracking-tight ${styles.valColor}`}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </span>
          </div>
          {subtitle && (
            <p className="mt-1 text-xs text-slate-500 font-mono">
              {subtitle}
            </p>
          )}
        </div>
        <div className={`p-2.5 rounded-lg border ${styles.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
