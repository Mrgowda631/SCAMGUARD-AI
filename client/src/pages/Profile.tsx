import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import { evaluatePasswordStrength } from '../utils/passwordValidator';
import {
  UserCheck,
  Shield,
  KeyRound,
  Laptop,
  Clock,
  CheckCircle2,
  Calendar,
  Lock,
} from 'lucide-react';

export const Profile: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [updatingPassword, setUpdatingPassword] = useState(false);

  const [sessions, setSessions] = useState<any[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(true);

  const fetchSessions = async () => {
    try {
      setLoadingSessions(true);
      const res = await api.getSessions();
      setSessions(res.sessions || []);
    } catch (err: any) {
      console.error('Failed to load active sessions:', err);
    } finally {
      setLoadingSessions(false);
    }
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword || !newPassword) {
      showToast('Please fill out all password fields.', 'warning');
      return;
    }

    const pwdEval = evaluatePasswordStrength(newPassword);
    if (!pwdEval.valid) {
      showToast(
        pwdEval.errors[0] ||
        'Weak password rejected: Password must include uppercase, lowercase, numbers, and special characters.',
        'error'
      );
      return;
    }

    if (newPassword !== confirmPassword) {
      showToast('New passwords do not match.', 'error');
      return;
    }

    try {
      setUpdatingPassword(true);
      const res = await api.changePassword(currentPassword, newPassword);
      showToast(res.message || 'Password changed successfully.', 'success');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      fetchSessions();
    } catch (err: any) {
      showToast(err.message || 'Failed to update password.', 'error');
    } finally {
      setUpdatingPassword(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="space-y-2 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <UserCheck className="w-5 h-5 text-cyan-400" />
          <h1 className="text-xl font-bold font-mono text-slate-100">
            Analyst Profile & Security Credentials
          </h1>
        </div>
        <p className="text-xs text-slate-400">
          Manage your SOC analyst identity, account credentials, and view authenticated active browser sessions.
        </p>
      </div>

      {/* Profile Overview Card */}
      <div className="cyber-card p-6 border border-slate-800 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
        <div className="flex items-center space-x-4">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-600 to-blue-600 border border-cyan-400/40 flex items-center justify-center text-xl font-mono font-bold text-slate-950 shadow-glow-cyan">
            {user?.name?.slice(0, 2).toUpperCase() || 'SA'}
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">{user?.name}</h2>
            <p className="text-xs font-mono text-slate-400">{user?.email}</p>
            <span className="inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 font-semibold">
              {user?.role === 'admin' ? 'Super Administrator' : 'Threat Intelligence Analyst'}
            </span>
          </div>
        </div>

        <div className="md:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center space-x-2.5">
            <Calendar className="w-4 h-4 text-slate-500" />
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">Account Created</span>
              <span className="text-slate-300 font-semibold">
                {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
              </span>
            </div>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center space-x-2.5">
            <Shield className="w-4 h-4 text-emerald-400" />
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">Auth State</span>
              <span className="text-emerald-400 font-semibold">HTTP-Only Signed Session</span>
            </div>
          </div>
        </div>
      </div>

      {/* Password Change Form */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
          <KeyRound className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            Rotate Security Password
          </h3>
        </div>

        <form onSubmit={handleChangePassword} className="space-y-4 max-w-md">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Current Password:
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={e => setCurrentPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs text-slate-100 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              New Password (A-Z, a-z, 0-9, special char):
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs text-slate-100 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Confirm New Password:
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs text-slate-100 font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={updatingPassword}
            className="px-4 py-2 rounded-lg text-xs font-bold font-mono text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 transition-colors shadow-glow-cyan"
          >
            {updatingPassword ? 'Updating Password...' : 'Update Password'}
          </button>
        </form>
      </div>

      {/* Active Sessions List */}
      <div className="cyber-card p-6 border border-slate-800 space-y-4">
        <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
          <Laptop className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            Active Authenticated Sessions
          </h3>
        </div>

        <div className="space-y-2.5">
          {loadingSessions ? (
            <p className="text-xs font-mono text-slate-500">Loading active sessions...</p>
          ) : sessions.length > 0 ? (
            sessions.map(s => (
              <div
                key={s.id}
                className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs"
              >
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-lg bg-slate-900 text-slate-400 border border-slate-800">
                    <Laptop className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-slate-200 font-mono">
                        {s.userAgent?.slice(0, 40) || 'Web Browser'}
                      </span>
                      {s.isCurrent && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950/70 text-emerald-400 border border-emerald-800/40 font-bold">
                          Current Device
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono block mt-0.5">
                      Session Started: {new Date(s.createdAt).toLocaleString()}
                    </span>
                  </div>
                </div>

                <div className="text-right font-mono text-[11px] text-slate-500">
                  <span>Expires: {new Date(s.expiresAt).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          ) : (
            <p className="text-xs font-mono text-slate-500">No active session records found.</p>
          )}
        </div>
      </div>
    </div>
  );
};
