import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw, Home, Terminal } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('SCAMGUARD SOC Caught Component Error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  private handleGoHome = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.href = '/';
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#060911] text-slate-100 flex items-center justify-center p-4 bg-grid-cyber relative">
          <div className="absolute inset-0 bg-radial-glow pointer-events-none" />
          
          <div className="max-w-xl w-full p-6 sm:p-8 rounded-2xl bg-slate-900/90 border border-red-500/40 shadow-2xl relative z-10 space-y-6">
            <div className="flex items-center space-x-3 pb-4 border-b border-slate-800">
              <div className="p-3 rounded-xl bg-red-950/80 border border-red-500/50 text-red-400">
                <ShieldAlert className="w-8 h-8" />
              </div>
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-red-950/80 border border-red-800/60 text-red-400 font-bold">
                  SOC FAIL-SAFE SHIELD
                </span>
                <h1 className="text-xl font-bold font-mono text-slate-100 mt-1">
                  {this.props.fallbackTitle || 'Security Console Exception Intercepted'}
                </h1>
              </div>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              An unexpected component render exception occurred in the client application. SCAMGUARD AI fail-safe protection intercepted this error to prevent system crash.
            </p>

            {this.state.error && (
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center space-x-2 text-xs font-mono text-red-400">
                  <Terminal className="w-4 h-4 shrink-0" />
                  <span className="font-bold truncate">{this.state.error.name}: {this.state.error.message}</span>
                </div>
                {this.state.errorInfo && (
                  <pre className="text-[10px] font-mono text-slate-500 overflow-x-auto max-h-32 p-2 bg-slate-900/60 rounded border border-slate-800/60">
                    {this.state.errorInfo.componentStack}
                  </pre>
                )}
              </div>
            )}

            <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
              <button
                onClick={this.handleReset}
                className="w-full sm:w-auto flex-1 flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wider text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 transition-all shadow-glow-cyan"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Reload Security Console</span>
              </button>
              <button
                onClick={this.handleGoHome}
                className="w-full sm:w-auto flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 transition-all border border-slate-700"
              >
                <Home className="w-4 h-4" />
                <span>Return to Overview</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
