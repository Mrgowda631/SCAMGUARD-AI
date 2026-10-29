import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck } from 'lucide-react';

interface ThreatBadgeProps {
  prediction: 'scam' | 'suspicious' | 'genuine' | string;
  category?: string;
  size?: 'sm' | 'md';
}

export const ThreatBadge: React.FC<ThreatBadgeProps> = ({
  prediction,
  category,
  size = 'md',
}) => {
  const normalized = prediction?.toLowerCase();

  const configs = {
    scam: {
      bg: 'bg-red-500/10 border-red-500/30 text-red-400',
      glow: 'shadow-[0_0_12px_rgba(239,68,68,0.2)]',
      label: 'SCAM DETECTED',
      icon: ShieldAlert,
    },
    suspicious: {
      bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
      glow: 'shadow-[0_0_12px_rgba(245,158,11,0.2)]',
      label: 'SUSPICIOUS CONTENT',
      icon: AlertTriangle,
    },
    genuine: {
      bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
      glow: 'shadow-[0_0_12px_rgba(16,185,129,0.2)]',
      label: 'GENUINE / BENIGN',
      icon: ShieldCheck,
    },
  }[normalized] || {
    bg: 'bg-slate-500/10 border-slate-500/30 text-slate-300',
    glow: '',
    label: normalized.toUpperCase(),
    icon: ShieldCheck,
  };

  const Icon = configs.icon;
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-xs';

  return (
    <div className="inline-flex items-center space-x-2">
      <span
        className={`inline-flex items-center space-x-1.5 font-semibold uppercase tracking-wider rounded-md border ${configs.bg} ${configs.glow} ${sizeClasses}`}
      >
        <Icon className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
        <span>{configs.label}</span>
      </span>

      {category && category !== 'legitimate' && (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800/40">
          {category.replace(/_/g, ' ')}
        </span>
      )}
    </div>
  );
};
