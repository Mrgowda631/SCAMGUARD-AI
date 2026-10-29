import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation, Link } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { ToastContainer } from './components/Toast';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ConnectionBanner } from './components/ConnectionBanner';
import { getApiBaseUrl } from './services/api';

// Pages
import { Overview } from './pages/Overview';
import { ContentScanner } from './pages/ContentScanner';
import { UrlScanner } from './pages/UrlScanner';
import { SocialAnalyzer } from './pages/SocialAnalyzer';
import { ScanHistory } from './pages/ScanHistory';
import { ThreatAnalytics } from './pages/ThreatAnalytics';
import { ForensicReports } from './pages/ForensicReports';
import { ReportDetail } from './pages/ReportDetail';
import { AwarenessHub } from './pages/AwarenessHub';
import { Profile } from './pages/Profile';
import { Settings } from './pages/Settings';
import { AdminDashboard } from './pages/AdminDashboard';
import { Login } from './pages/Login';
import { Register } from './pages/Register';

/**
 * Universal SOC Application Shell
 * Renders immediately without blocking on network requests or backend availability.
 */
const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#060911] bg-grid-cyber flex flex-col text-slate-100">
      <Navbar
        onMobileToggle={() => setMobileMenuOpen(!mobileMenuOpen)}
        isMobileOpen={mobileMenuOpen}
      />

      <div className="flex flex-1 relative overflow-hidden">
        {/* Desktop Persistent Sidebar */}
        <div className="hidden lg:block shrink-0">
          <Sidebar />
        </div>

        {/* Mobile Slideout Sidebar Drawer */}
        {mobileMenuOpen && (
          <div className="fixed inset-0 z-50 lg:hidden flex">
            <div
              className="fixed inset-0 bg-black/70 backdrop-blur-sm animate-fade-in"
              onClick={() => setMobileMenuOpen(false)}
            />
            <div className="relative z-10 w-64 h-full bg-[#060911] border-r border-slate-800 shadow-2xl animate-slide-in">
              <Sidebar onCloseMobile={() => setMobileMenuOpen(false)} />
            </div>
          </div>
        )}

        {/* Main Content Area with Non-Blocking Connection / Engine Status Banner */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full overflow-y-auto">
          <ConnectionBanner />
          <ErrorBoundary fallbackTitle="Security Workspace Module Error">
            {children}
          </ErrorBoundary>
        </main>
      </div>

      <ToastContainer />
    </div>
  );
};

/**
 * Route guard that requires active authentication (e.g. for profile, settings, personal scan history).
 * If initialization is in progress, shows an in-page loader rather than blanking the shell.
 */
const RequireAuth: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading, authStatus, retryConnection } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#060911] flex flex-col items-center justify-center space-y-4">
        <div className="relative flex items-center justify-center p-3 rounded-2xl bg-slate-900/80 border border-cyan-500/30 shadow-[0_0_30px_rgba(6,182,212,0.15)]">
          <img
            src="/logo.png"
            alt="SCAMGUARD AI"
            className="w-12 h-12 object-contain"
          />
        </div>
        <div className="flex items-center space-x-2 text-cyan-400">
          <div className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <span className="font-mono text-xs tracking-wider">VERIFYING ANALYST CREDENTIALS...</span>
        </div>
      </div>
    );
  }

  if (authStatus === 'degraded') {
    const isDev = import.meta.env.DEV;
    const apiUrl = getApiBaseUrl();

    return (
      <div className="max-w-md mx-auto my-12 p-6 rounded-2xl bg-amber-950/40 border border-amber-500/40 text-center space-y-4 shadow-xl">
        <div className="w-12 h-12 mx-auto rounded-full bg-amber-900/60 border border-amber-600/50 flex items-center justify-center text-amber-300">
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <div>
          <p className="text-sm font-semibold text-amber-200">
            Backend API Disconnected
          </p>
          <p className="text-[11px] font-mono text-cyan-400 mt-0.5">
            Target Endpoint: {apiUrl}
          </p>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          {isDev ? (
            <>
              This protected route requires an active backend API and database connection. Start the local server with{' '}
              <code className="px-1.5 py-0.5 rounded bg-black/60 text-cyan-300 font-mono">npm run dev:server</code>.
            </>
          ) : (
            <>
              Unable to establish a connection with the production database. Configure{' '}
              <code className="px-1.5 py-0.5 rounded bg-black/60 text-cyan-300 font-mono">VITE_API_URL</code> in your Netlify Site Settings or ensure your backend service is running.
            </>
          )}
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-2 pt-2">
          <button
            onClick={() => retryConnection()}
            className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-mono font-bold bg-amber-900/80 hover:bg-amber-800 text-amber-100 transition-colors"
          >
            Retry Connection
          </button>
          <Link
            to="/awareness"
            className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors text-center"
          >
            Awareness Hub
          </Link>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

/**
 * Privileged route guard for root administrator operations
 */
const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-[50vh] flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        <p className="font-mono text-xs text-slate-400 tracking-wider">
          VERIFYING ROOT ADMINISTRATIVE PRIVILEGES...
        </p>
      </div>
    );
  }

  if (user?.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <Routes>
            {/* Public Authentication Pages */}
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* Core SOC Capabilities (Protected: Login is required for all SOC Operations) */}
            <Route
              path="/"
              element={
                <RequireAuth>
                  <AppLayout>
                    <Overview />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/scanner"
              element={
                <RequireAuth>
                  <AppLayout>
                    <ContentScanner />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/url-scanner"
              element={
                <RequireAuth>
                  <AppLayout>
                    <UrlScanner />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/social-analyzer"
              element={
                <RequireAuth>
                  <AppLayout>
                    <SocialAnalyzer />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/analytics"
              element={
                <RequireAuth>
                  <AppLayout>
                    <ThreatAnalytics />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/awareness"
              element={
                <RequireAuth>
                  <AppLayout>
                    <AwarenessHub />
                  </AppLayout>
                </RequireAuth>
              }
            />

            {/* Authenticated Analyst Records & Operations */}
            <Route
              path="/history"
              element={
                <RequireAuth>
                  <AppLayout>
                    <ScanHistory />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/reports"
              element={
                <RequireAuth>
                  <AppLayout>
                    <ForensicReports />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/reports/:id"
              element={
                <RequireAuth>
                  <AppLayout>
                    <ReportDetail />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/profile"
              element={
                <RequireAuth>
                  <AppLayout>
                    <Profile />
                  </AppLayout>
                </RequireAuth>
              }
            />
            <Route
              path="/settings"
              element={
                <RequireAuth>
                  <AppLayout>
                    <Settings />
                  </AppLayout>
                </RequireAuth>
              }
            />

            {/* Root Administration */}
            <Route
              path="/admin"
              element={
                <RequireAuth>
                  <AdminRoute>
                    <AppLayout>
                      <AdminDashboard />
                    </AppLayout>
                  </AdminRoute>
                </RequireAuth>
              }
            />

            {/* Catch-all Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
