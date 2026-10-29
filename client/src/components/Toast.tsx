import React from 'react';
import { useToast, ToastType } from '../context/ToastContext';
import { CheckCircle2, AlertTriangle, AlertOctagon, Info, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useToast();

  if (toasts.length === 0) return null;

  const icons: Record<ToastType, React.ReactNode> = {
    success: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />,
    warning: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />,
    error: <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />,
    info: <Info className="w-4 h-4 text-cyan-400 shrink-0" />,
  };

  const borders: Record<ToastType, string> = {
    success: 'border-emerald-500/40 bg-slate-900/95 text-emerald-100',
    warning: 'border-amber-500/40 bg-slate-900/95 text-amber-100',
    error: 'border-red-500/40 bg-slate-900/95 text-red-100',
    info: 'border-cyan-500/40 bg-slate-900/95 text-cyan-100',
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col space-y-2.5 max-w-sm w-full pointer-events-none">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`pointer-events-auto flex items-center justify-between p-3.5 rounded-xl border shadow-xl backdrop-blur-md transition-all duration-300 animate-slide-in ${borders[toast.type]}`}
        >
          <div className="flex items-center space-x-2.5">
            {icons[toast.type]}
            <p className="text-xs font-medium">{toast.message}</p>
          </div>
          <button
            onClick={() => removeToast(toast.id)}
            className="text-slate-400 hover:text-slate-200 transition-colors p-1"
            aria-label="Dismiss toast"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
};
