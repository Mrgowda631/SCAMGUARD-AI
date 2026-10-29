import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { Shield, Sparkles, Cpu, User, Menu, X, LogOut } from 'lucide-react';
import { Link } from 'react-router-dom';

interface NavbarProps {
  onMobileToggle: () => void;
  isMobileOpen: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ onMobileToggle, isMobileOpen }) => {
  const { user, logout } = useAuth();
  const [geminiStatus, setGeminiStatus] = useState<{ configured: boolean; model: string; activeEngine: string } | null>(null);

  useEffect(() => {
    api.getHealth()
      .then(res => {
        if (res && res.gemini) {
          setGeminiStatus(res.gemini);
        }
      })
      .catch(() => {
        setGeminiStatus({
          configured: false,
          model: 'unknown',
          activeEngine: 'heuristic_fallback',
        });
      });
  }, []);

  return (
    <header className="sticky top-0 z-40 w-full bg-[#060911]/90 backdrop-blur-md border-b border-slate-800/80 px-4 lg:px-8 py-3 flex items-center justify-between">
      {/* Brand & Mobile Toggle */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onMobileToggle}
          className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          aria-label="Toggle navigation menu"
        >
          {isMobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>

        <Link to="/" className="flex items-center space-x-2.5 group">
          <div className="p-1 rounded-lg bg-slate-900 border border-slate-700/80 shadow-[0_0_12px_rgba(6,182,212,0.25)] flex items-center justify-center shrink-0">
            <img
              src="/logo.png"
              alt="SCAMGUARD AI Logo"
              className="w-8 h-8 object-contain"
            />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center space-x-2">
              <span className="font-extrabold tracking-wider text-base bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent font-mono">
                SCAMGUARD AI
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-400 font-semibold">
                SOC v1.0
              </span>
            </div>
            <span className="text-[10px] text-slate-500 font-mono hidden sm:inline">
              Cybersecurity & AI Intelligence Project
            </span>
          </div>
        </Link>
      </div>

      {/* Engine Status & User Profile */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* Active Engine Pill */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono">
          {geminiStatus?.configured ? (
            <>
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-300">Gemini AI Model</span>
              <span className="text-slate-500 text-[10px]">({geminiStatus.model})</span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-amber-300">Offline Heuristic Engine</span>
            </>
          )}
        </div>

        {/* User Pill */}
        {user ? (
          <div className="flex items-center space-x-3">
            <Link
              to="/profile"
              className="flex items-center space-x-2 p-1.5 pr-3 rounded-lg bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 transition-colors"
            >
              <div className="w-7 h-7 rounded-md bg-gradient-to-tr from-cyan-900 to-blue-900 border border-cyan-500/30 flex items-center justify-center text-xs font-bold font-mono text-cyan-300">
                {user.name.slice(0, 2).toUpperCase()}
              </div>
              <div className="flex flex-col text-left">
                <span className="text-xs font-medium text-slate-200 leading-tight">
                  {user.name}
                </span>
                <span className="text-[10px] font-mono text-slate-500 capitalize">
                  {user.role === 'admin' ? 'Super Admin' : 'Security Analyst'}
                </span>
              </div>
            </Link>

            <button
              onClick={() => logout()}
              title="Sign Out"
              className="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="flex items-center space-x-2">
            <Link
              to="/login"
              className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors"
            >
              Sign In
            </Link>
            <Link
              to="/register"
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors font-semibold shadow-glow-cyan"
            >
              Register
            </Link>
          </div>
        )}
      </div>
    </header>
  );
};
