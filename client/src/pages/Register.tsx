import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { evaluatePasswordStrength } from '../utils/passwordValidator';
import {
  Shield,
  Lock,
  Mail,
  User,
  ArrowRight,
  Eye,
  EyeOff,
  UserPlus,
  AlertCircle,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

export const Register: React.FC = () => {
  const { user, register } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    if (user) {
      navigate('/', { replace: true });
    }
  }, [user, navigate]);

  // Ensure background video autoplays smoothly across browsers and platforms
  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.play().catch(() => {
        // Safe fallback if strict browser autoplay policies restrict programmatic play
      });
    }
  }, []);

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedName = name.trim();
    const trimmedEmail = email.trim();

    if (!trimmedName || !trimmedEmail || !password) {
      setError('Please fill in all required fields.');
      return;
    }

    if (!trimmedEmail.includes('@') || !trimmedEmail.includes('.')) {
      setError('Please provide a valid email address format.');
      return;
    }

    // Enforce strict password complexity: Reject weak passwords, only words, or only numbers
    const pwdEval = evaluatePasswordStrength(password);
    if (!pwdEval.valid) {
      setError(
        pwdEval.errors[0] ||
        'Weak password rejected: Password must include uppercase & lowercase alphabets, numbers, and special characters. Passwords with only words or only numbers are prohibited.'
      );
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match. Please verify your confirm password.');
      return;
    }

    try {
      setSubmitting(true);
      await register(trimmedName, trimmedEmail, password);
      showToast('Analyst account successfully created. Welcome to SCAMGUARD SOC!', 'success');
      navigate('/');
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center p-4 sm:p-6 bg-[#040711] overflow-x-hidden overflow-y-auto select-none">
      {/* Full-Screen Video Background */}
      <video
        ref={videoRef}
        className="register-video-background"
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

      {/* Multi-layered dark cyber overlays to ensure crystal-clear text readability */}
      <div className="register-video-overlay" />
      <div className="register-vignette-overlay" />
      <div className="fixed inset-0 bg-grid-cyber opacity-25 pointer-events-none z-[3]" />

      {/* Ambient cybersecurity glows */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-600/15 rounded-full blur-3xl pointer-events-none z-[4]" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/15 rounded-full blur-3xl pointer-events-none z-[4]" />

      {/* Main Registration Card */}
      <div className="w-full max-w-md relative z-10 my-auto space-y-6 animate-fade-in-up">
        {/* Security Classification Badge */}
        <div className="flex items-center justify-center">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900/90 border border-cyan-500/30 text-[11px] font-mono text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)] backdrop-blur-md">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
            <span>SOC ANALYST ONBOARDING GATEWAY</span>
          </div>
        </div>

        {/* Card Body with Glassmorphism */}
        <div className="p-6 sm:p-8 rounded-2xl border border-slate-700/70 bg-slate-900/75 backdrop-blur-2xl shadow-2xl shadow-cyan-950/40 ring-1 ring-white/10 space-y-6">
          {/* Official Logo & Brand Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="relative group p-2.5 rounded-2xl bg-gradient-to-b from-slate-800/80 to-slate-900/90 border border-slate-700/60 shadow-[0_0_25px_rgba(6,182,212,0.25)]">
                <img
                  src="/logo.png"
                  alt="SCAMGUARD AI"
                  className="w-14 h-14 object-contain drop-shadow-[0_0_15px_rgba(6,182,212,0.4)]"
                />
              </div>
            </div>
            <h1 className="text-2xl font-extrabold font-mono tracking-wider text-slate-100">
              SCAMGUARD <span className="text-cyan-400">AI</span>
            </h1>
            <p className="text-xs text-slate-300 font-mono">
              Create Security Analyst Workspace Account
            </p>
          </div>

          {/* Error Alert */}
          {error && (
            <div className="p-3.5 rounded-xl bg-red-950/80 border border-red-500/50 text-red-200 text-xs font-mono flex items-start space-x-2.5 backdrop-blur-sm animate-fade-in">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Registration Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="reg-name"
                className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1.5"
              >
                Analyst Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
                <input
                  id="reg-name"
                  type="text"
                  value={name}
                  onChange={e => {
                    setName(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="Specialist Jane Doe"
                  required
                  autoComplete="name"
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 text-xs sm:text-sm text-slate-100 placeholder-slate-500 font-sans transition-all outline-none backdrop-blur-sm"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="reg-email"
                className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1.5"
              >
                Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
                <input
                  id="reg-email"
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
                  htmlFor="reg-password"
                  className="block text-xs font-mono uppercase tracking-wider text-slate-300"
                >
                  Password
                </label>
                <span className="text-[10px] font-mono text-slate-400">Min 8 characters</span>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
                <input
                  id="reg-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => {
                    setPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="e.g. Sentinel#2026Secure!"
                  required
                  autoComplete="new-password"
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

              {/* Real-time Password Security Policy Checklist & Strength Meter */}
              {password.length > 0 && (() => {
                const evalResult = evaluatePasswordStrength(password);
                const barColor =
                  evalResult.strengthLabel === 'Strong'
                    ? 'bg-emerald-400'
                    : evalResult.strengthLabel === 'Fair'
                    ? 'bg-cyan-400'
                    : evalResult.strengthLabel === 'Weak'
                    ? 'bg-amber-400'
                    : 'bg-red-500';

                const barWidth =
                  evalResult.strengthLabel === 'Strong'
                    ? 'w-full'
                    : evalResult.strengthLabel === 'Fair'
                    ? 'w-3/4'
                    : evalResult.strengthLabel === 'Weak'
                    ? 'w-1/2'
                    : 'w-1/4';

                return (
                  <div className="mt-2 p-3 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 text-xs font-mono animate-fade-in">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Password Security Rating:</span>
                      <span
                        className={`font-bold ${
                          evalResult.strengthLabel === 'Strong'
                            ? 'text-emerald-400'
                            : evalResult.strengthLabel === 'Fair'
                            ? 'text-cyan-400'
                            : evalResult.strengthLabel === 'Weak'
                            ? 'text-amber-400'
                            : 'text-red-400'
                        }`}
                      >
                        {evalResult.strengthLabel.toUpperCase()}
                      </span>
                    </div>

                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className={`h-full ${barColor} ${barWidth} transition-all duration-300`} />
                    </div>

                    <div className="grid grid-cols-2 gap-1.5 pt-1 text-[11px]">
                      <div
                        className={`flex items-center space-x-1.5 ${
                          evalResult.checks.minLength ? 'text-emerald-400' : 'text-slate-500'
                        }`}
                      >
                        {evalResult.checks.minLength ? (
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 shrink-0" />
                        )}
                        <span>8+ Characters</span>
                      </div>

                      <div
                        className={`flex items-center space-x-1.5 ${
                          evalResult.checks.hasUppercase && evalResult.checks.hasLowercase
                            ? 'text-emerald-400'
                            : 'text-slate-500'
                        }`}
                      >
                        {evalResult.checks.hasUppercase && evalResult.checks.hasLowercase ? (
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 shrink-0" />
                        )}
                        <span>A-Z and a-z</span>
                      </div>

                      <div
                        className={`flex items-center space-x-1.5 ${
                          evalResult.checks.hasNumber ? 'text-emerald-400' : 'text-slate-500'
                        }`}
                      >
                        {evalResult.checks.hasNumber ? (
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 shrink-0" />
                        )}
                        <span>0-9 Numbers</span>
                      </div>

                      <div
                        className={`flex items-center space-x-1.5 ${
                          evalResult.checks.hasSpecial ? 'text-emerald-400' : 'text-slate-500'
                        }`}
                      >
                        {evalResult.checks.hasSpecial ? (
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 shrink-0" />
                        )}
                        <span>Special (!@#$)</span>
                      </div>
                    </div>

                    {/* Warning if only words or only numbers */}
                    {(!evalResult.checks.notOnlyWords || !evalResult.checks.notOnlyNumbers) && (
                      <p className="text-[10px] text-red-400/90 pt-1 border-t border-slate-800/80 leading-tight">
                        ⚠ Weak pattern detected: Passwords cannot be only words/letters or only numbers.
                      </p>
                    )}
                  </div>
                );
              })()}
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="reg-confirm-password"
                  className="block text-xs font-mono uppercase tracking-wider text-slate-300"
                >
                  Confirm Password
                </label>
                <span className="text-[10px] font-mono text-slate-400">Verification check</span>
              </div>
              <div className="relative">
                <Shield className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
                <input
                  id="reg-confirm-password"
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={e => {
                    setConfirmPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="••••••••••••"
                  required
                  autoComplete="new-password"
                  className="w-full pl-10 pr-11 py-3 rounded-xl bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 text-xs sm:text-sm text-slate-100 placeholder-slate-500 font-mono transition-all outline-none backdrop-blur-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3.5 top-3.5 text-slate-400 hover:text-cyan-400 transition-colors p-0.5"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
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
                  <span>Creating Analyst Profile...</span>
                </>
              ) : (
                <>
                  <UserPlus className="w-4 h-4" />
                  <span>Complete Registration</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer Info & Sign In Link */}
          <div className="pt-4 border-t border-slate-800/80 text-center space-y-2">
            <p className="text-xs text-slate-300 font-sans">
              Already registered?{' '}
              <Link
                to="/login"
                className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4"
              >
                Sign In to Existing Account
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
