import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  MessageSquareWarning,
  GlobeLock,
  Share2,
  History,
  BarChart3,
  FileCheck,
  BookOpen,
  UserCheck,
  Settings,
  ShieldAlert,
  LogOut,
} from 'lucide-react';

interface SidebarProps {
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ onCloseMobile }) => {
  const { user, logout } = useAuth();

  const mainLinks = [
    { to: '/', label: 'Security Overview', icon: LayoutDashboard },
    { to: '/scanner', label: 'Message Scanner', icon: MessageSquareWarning },
    { to: '/url-scanner', label: 'URL Security Scanner', icon: GlobeLock },
    { to: '/social-analyzer', label: 'Social Media Analyzer', icon: Share2 },
    { to: '/history', label: 'Scan History', icon: History },
    { to: '/analytics', label: 'Threat Analytics', icon: BarChart3 },
    { to: '/reports', label: 'Forensic Reports', icon: FileCheck },
    { to: '/awareness', label: 'Scam Awareness Hub', icon: BookOpen },
    { to: '/profile', label: 'Analyst Profile', icon: UserCheck },
    { to: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 h-full bg-[#060911]/95 border-r border-slate-800 flex flex-col justify-between py-4 px-3 select-none">
      <div className="space-y-5">
        {/* Brand Logo & Header */}
        <div className="px-2 pt-1 pb-3 border-b border-slate-800/80 flex items-center space-x-3">
          <div className="p-1 rounded-xl bg-slate-900 border border-slate-700/80 shadow-[0_0_12px_rgba(6,182,212,0.25)] flex items-center justify-center shrink-0">
            <img
              src="/logo.png"
              alt="SCAMGUARD AI Logo"
              className="w-8 h-8 object-contain"
            />
          </div>
          <div className="flex flex-col">
            <span className="font-extrabold tracking-wider text-sm font-mono bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              SCAMGUARD AI
            </span>
            <span className="text-[10px] font-mono text-slate-500">
              Cybersecurity SOC
            </span>
          </div>
        </div>

        {/* Navigation Section */}
        <div>
          <p className="px-3 mb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
            SOC Operations
          </p>
          <nav className="space-y-1">
            {mainLinks.map(link => {
              const Icon = link.icon;
              return (
                <NavLink
                  key={link.to}
                  to={link.to}
                  onClick={onCloseMobile}
                  className={({ isActive }) =>
                    `flex items-center space-x-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.15)] font-semibold'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{link.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Administrator Section */}
        {user?.role === 'admin' && (
          <div>
            <div className="px-3 mb-2 flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-red-400 font-semibold">
                Privileged Access
              </span>
              <span className="text-[9px] font-mono px-1 rounded bg-red-950/60 border border-red-800/50 text-red-400 font-bold">
                ROOT
              </span>
            </div>
            <nav className="space-y-1">
              <NavLink
                to="/admin"
                onClick={onCloseMobile}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-red-500/10 text-red-400 border border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.15)] font-semibold'
                      : 'text-slate-400 hover:text-red-300 hover:bg-red-950/30'
                  }`
                }
              >
                <ShieldAlert className="w-4 h-4 shrink-0 text-red-400" />
                <span>Admin Dashboard</span>
              </NavLink>
            </nav>
          </div>
        )}
      </div>

      {/* Footer / User Info */}
      <div className="pt-4 border-t border-slate-800/80 space-y-3">
        {user ? (
          <div className="px-2">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="font-mono text-[11px] truncate max-w-[140px]">{user.email}</span>
              <span className="text-[10px] font-mono px-1 rounded bg-slate-800 text-cyan-300">
                {user.role}
              </span>
            </div>
            <button
              onClick={() => logout()}
              className="w-full flex items-center justify-center space-x-2 px-3 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-slate-800 hover:border-red-500/30 transition-all"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Terminate Session</span>
            </button>
          </div>
        ) : (
          <div className="px-2">
            <NavLink
              to="/login"
              className="w-full flex items-center justify-center px-3 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-glow-cyan"
            >
              Log In to SOC
            </NavLink>
          </div>
        )}

        <div className="px-2 text-center">
          <p className="text-[10px] font-mono text-slate-600">
            SCAMGUARD SOC v1.0.0
          </p>
        </div>
      </div>
    </aside>
  );
};
