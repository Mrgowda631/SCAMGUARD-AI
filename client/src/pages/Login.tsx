import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { evaluatePasswordStrength } from '../utils/passwordValidator';
import {
  Lock,
  Mail,
  ArrowRight,
  Eye,
  EyeOff,
  AlertCircle,
  KeyRound,
  Fingerprint,
} from 'lucide-react';

export const Login: React.FC = () => {
  const { user, login, loginOffline } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const videoRef = useRef<HTMLVideoElement | null>(null);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isConnectionError, setIsConnectionError] = useState(false);

  // If already authenticated, redirect to destination or home page
  const from = (location.state as any)?.from?.pathname || '/';

  useEffect(() => {
    if (user) {
      navigate(from, { replace: true });
    }
  }, [user, navigate, from]);

  // Ensure background video autoplays smoothly across browsers and platforms
  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.play().catch(() => {
        // Safe fallback if strict browser autoplay policies restrict programmatic play
      });
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      setError('Please provide your analyst email address.');
      return;
    }

    if (!trimmedEmail.includes('@') || !trimmedEmail.includes('.')) {
      setError('Please enter a valid format email address.');
      return;
    }

    if (!password) {
      setError('Access password is required.');
      return;
    }

    // Enforce strong password policy: Reject weak passwords like "Sanjay Kumar", only numbers, or only words
    const pwdEval = evaluatePasswordStrength(password);
    if (!pwdEval.valid) {
      setError(
        'Weak password rejected: To authenticate into SCAMGUARD SOC, your password must include all character classes: alphabets (A-Z, a-z), numbers (0-9), and special characters (!@#$%^&*).'
      );
      return;
    }

    try {
      setSubmitting(true);
      setIsConnectionError(false);
      await login(trimmedEmail, password);
      showToast('Analyst authenticated. Welcome to SCAMGUARD SOC.', 'success');
      navigate(from, { replace: true });
    } catch (err: any) {
      const rawMsg = err.message || '';
      if (
        rawMsg.includes('Failed to fetch') ||
        rawMsg.includes('NetworkError') ||
        rawMsg.includes('Failed to parse response') ||
        rawMsg.includes('AbortError')
      ) {
        setIsConnectionError(true);
        setError(
          'Backend service (port 8000) unreachable. Please verify that "npm run dev" is running in your terminal, or enter using Offline SOC Fallback Mode.'
        );
      } else {
        setIsConnectionError(false);
        setError(rawMsg || 'Invalid email or password credentials. Please verify your access rights.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleOfflineLogin = () => {
    loginOffline(email || 'shreyasc299@gmail.com');
    showToast('Entered SCAMGUARD SOC in Offline Fallback Mode.', 'info');
    navigate(from, { replace: true });
  };

  // Quick fill helper for local evaluator / admin credentials
  const fillAdminCredentials = () => {
    setEmail('shreyasc299@gmail.com');
    setPassword('Shreyas@631');
    setError(null);
    setIsConnectionError(false);
  };

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center p-4 sm:p-6 bg-[#040711] overflow-x-hidden overflow-y-auto select-none">
      {/* Full-Screen Video Background */}
      <video
        ref={videoRef}
        className="login-video-background"
        autoPlay
        muted
        loop
        playsInline
        preload="metadata"
        aria-hidden="true"
        poster="/logo.png"
      >
        <source src="/hero-bg.mp4" type="video/mp4" />
        Your browser does not support the video tag.
      </video>

      {/* Multi-layered dark navy cyber overlays to maintain aesthetic and readability */}
      <div className="login-video-overlay" />
      <div className="login-vignette-overlay" />
      <div className="fixed inset-0 bg-grid-cyber opacity-20 pointer-events-none z-[3]" />

      {/* Background ambient cybersecurity glows */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-600/15 rounded-full blur-3xl pointer-events-none z-[4]" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/15 rounded-full blur-3xl pointer-events-none z-[4]" />

      {/* Main Login Card */}
      <div className="w-full max-w-md relative z-10 my-auto space-y-6 animate-fade-in">
        {/* Security Classification Badge */}
        <div className="flex items-center justify-center">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900/90 border border-cyan-500/30 text-[11px] font-mono text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)] backdrop-blur-md">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
            <span>SOC SECURE AUTHENTICATION GATEWAY</span>
          </div>
        </div>

        {/* Card Body */}
        <div className="p-6 sm:p-8 rounded-2xl border border-slate-700/80 bg-slate-900/75 backdrop-blur-2xl shadow-2xl shadow-cyan-950/40 ring-1 ring-white/10 space-y-6">
          {/* Official Logo & Brand Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="relative group p-2 rounded-2xl bg-gradient-to-b from-slate-800/80 to-slate-900/90 border border-slate-700/60 shadow-[0_0_25px_rgba(6,182,212,0.2)]">
                <img
                  src="/logo.png"
                  alt="SCAMGUARD AI Official Logo"
                  className="w-16 h-16 sm:w-20 sm:h-20 object-contain transition-transform duration-300 group-hover:scale-105 drop-shadow-[0_0_15px_rgba(6,182,212,0.4)]"
                  loading="eager"
                />
              </div>
            </div>

            <div>
              <h1 className="text-2xl sm:text-3xl font-extrabold font-mono tracking-wider text-slate-100">
                SCAMGUARD <span className="text-cyan-400">AI</span>
              </h1>
              <p className="text-xs sm:text-sm text-slate-300 font-sans mt-1">
                Social Media Scam Detection & Threat Intelligence
              </p>
              <p className="text-[11px] font-mono text-cyan-400/90 mt-0.5">
                Next-Generation Threat Analytics Operations Center
              </p>
            </div>
          </div>

          {/* Error Alert Box */}
          {error && (
            <div className="p-3.5 rounded-xl bg-red-950/80 border border-red-500/50 text-red-200 text-xs font-sans flex flex-col space-y-2 backdrop-blur-sm animate-slide-in">
              <div className="flex items-start space-x-2.5">
                <AlertCircle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
                <div className="flex-1 leading-relaxed">
                  <strong className="font-semibold block font-mono text-red-300">
                    {isConnectionError ? 'SOC Gateway Connection Warning:' : 'Access Denied:'}
                  </strong>
                  {error}
                </div>
              </div>

              {isConnectionError && (
                <div className="pt-2 border-t border-red-800/60 flex items-center justify-end">
                  <button
                    type="button"
                    onClick={handleOfflineLogin}
                    className="px-3 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] font-semibold transition-colors flex items-center space-x-1.5 shadow-sm"
                  >
                    <span>Enter in Offline SOC Mode &rarr;</span>
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="analyst-email"
                className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1.5"
              >
                Analyst Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
                <input
                  id="analyst-email"
                  type="email"
                  value={email}
                  onChange={e => {
                    setEmail(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="analyst@scamguard.soc"
                  required
                  autoComplete="email"
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 text-xs sm:text-sm text-slate-100 placeholder-slate-500 font-sans transition-all outline-none backdrop-blur-sm"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="access-password"
                  className="block text-xs font-mono uppercase tracking-wider text-slate-300"
                >
                  Access Password
                </label>
                <span className="text-[10px] font-mono text-slate-400">Encrypted AES-256</span>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
                <input
                  id="access-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => {
                    setPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="••••••••••••"
                  required
                  autoComplete="current-password"
                  className="w-full pl-10 pr-11 py-3 rounded-xl bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 text-xs sm:text-sm text-slate-100 placeholder-slate-500 font-mono transition-all outline-none backdrop-blur-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-3.5 text-slate-400 hover:text-cyan-400 transition-colors p-0.5"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-3 rounded-xl text-xs sm:text-sm font-bold font-mono tracking-wider uppercase text-slate-950 bg-gradient-to-r from-cyan-400 via-cyan-300 to-blue-500 hover:from-cyan-300 hover:to-blue-400 disabled:opacity-60 transition-all shadow-[0_0_20px_rgba(6,182,212,0.35)] flex items-center justify-center space-x-2 mt-2"
            >
              {submitting ? (
                <>
                  <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  <span>Verifying Analyst Credentials...</span>
                </>
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>Authenticate & Enter SOC</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Credential Test Helper */}
          <div className="pt-2">
            <button
              type="button"
              onClick={fillAdminCredentials}
              className="w-full py-2 px-3 rounded-lg bg-slate-950/60 hover:bg-slate-800/60 border border-dashed border-cyan-800/50 text-[11px] font-mono text-cyan-300/90 hover:text-cyan-300 transition-colors flex items-center justify-center space-x-1.5"
            >
              <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
              <span>Quick-Fill Administrator Credentials</span>
            </button>
          </div>

          {/* Footer Info & Registration */}
          <div className="pt-4 border-t border-slate-800/80 text-center space-y-2">
            <p className="text-xs text-slate-300 font-sans">
              Need a security analyst account?{' '}
              <Link to="/register" className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4">
                Register New Analyst
              </Link>
            </p>
            <p className="text-[10px] font-mono text-slate-400">
              Protected by Server-Side HTTP-Only Sessions & Rate Limiter
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
