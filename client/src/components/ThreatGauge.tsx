import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

interface ThreatGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showDetails?: boolean;
}

export const ThreatGauge: React.FC<ThreatGaugeProps> = ({
  score,
  size = 'md',
  showDetails = true,
}) => {
  const clamped = Math.min(100, Math.max(0, Math.round(score)));

  // Risk bands per requirements:
  // 0–29: Low risk
  // 30–59: Moderate risk
  // 60–79: High risk
  // 80–100: Critical risk
  let riskTier = 'Low Risk';
  let strokeColor = '#10B981'; // emerald
  let textColor = 'text-emerald-400';
  let glowColor = 'rgba(16, 185, 129, 0.3)';
  let Icon = ShieldCheck;

  if (clamped >= 80) {
    riskTier = 'Critical Threat';
    strokeColor = '#EF4444'; // red
    textColor = 'text-red-400';
    glowColor = 'rgba(239, 68, 68, 0.4)';
    Icon = ShieldAlert;
  } else if (clamped >= 60) {
    riskTier = 'High Risk';
    strokeColor = '#F97316'; // orange
    textColor = 'text-orange-400';
    glowColor = 'rgba(249, 115, 22, 0.35)';
    Icon = AlertTriangle;
  } else if (clamped >= 30) {
    riskTier = 'Moderate Risk';
    strokeColor = '#F59E0B'; // amber
    textColor = 'text-amber-400';
    glowColor = 'rgba(245, 158, 11, 0.35)';
    Icon = AlertTriangle;
  }

  const dimensions = {
    sm: { size: 100, strokeWidth: 8, fontSize: 'text-xl' },
    md: { size: 160, strokeWidth: 12, fontSize: 'text-3xl' },
    lg: { size: 220, strokeWidth: 16, fontSize: 'text-5xl' },
  }[size];

  const center = dimensions.size / 2;
  const radius = center - dimensions.strokeWidth;
  const circumference = 2 * Math.PI * radius;
  // Arc represents 260 degrees (leaving bottom gap for gauge appearance)
  const arcLength = circumference * 0.75;
  const offset = arcLength - (clamped / 100) * arcLength;

  return (
    <div className="flex flex-col items-center justify-center">
      <div
        className="relative flex items-center justify-center"
        style={{ width: dimensions.size, height: dimensions.size }}
      >
        <svg
          width={dimensions.size}
          height={dimensions.size}
          className="transform -rotate-135"
        >
          {/* Background Track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            stroke="#1E293B"
            strokeWidth={dimensions.strokeWidth}
            fill="transparent"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Animated Value Arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            stroke={strokeColor}
            strokeWidth={dimensions.strokeWidth}
            fill="transparent"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 1s ease-out, stroke 0.5s ease',
              filter: `drop-shadow(0 0 8px ${glowColor})`,
            }}
          />
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="flex items-baseline">
            <span className={`font-mono font-bold ${dimensions.fontSize} ${textColor}`}>
              {clamped}
            </span>
            <span className="text-xs text-slate-500 font-mono ml-0.5">/100</span>
          </div>
          <div className="flex items-center space-x-1 mt-0.5">
            <Icon className={`w-3.5 h-3.5 ${textColor}`} />
            <span className={`text-xs font-semibold uppercase tracking-wider ${textColor}`}>
              {riskTier}
            </span>
          </div>
        </div>
      </div>

      {showDetails && (
        <div className="mt-2 text-center max-w-[240px]">
          <p className="text-[11px] text-slate-500 leading-tight">
            Threat gauge score is an algorithmic estimate based on detected indicators, not a guarantee.
          </p>
        </div>
      )}
    </div>
  );
};
