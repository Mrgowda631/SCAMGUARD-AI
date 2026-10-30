import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { User } from '../types';
import { api } from '../services/api';

export type AuthStatus = 'initializing' | 'authenticated' | 'unauthenticated' | 'degraded';

interface AuthContextType {
  user: User | null;
  authStatus: AuthStatus;
  loading: boolean;
  backendAvailable: boolean;
  connectionError: string | null;
  login: (email: string, password: string) => Promise<void>;
  loginOffline: (analystEmail?: string) => void;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  retryConnection: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus>('initializing');
  const [backendAvailable, setBackendAvailable] = useState<boolean>(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const checkAuth = useCallback(async () => {
    try {
      setConnectionError(null);
      const res = await api.getMe({ timeoutMs: 2500 });
      if (res && res.user) {
        setUser(res.user);
        setAuthStatus('authenticated');
        setBackendAvailable(true);
      } else {
        setUser(null);
        setAuthStatus('unauthenticated');
        setBackendAvailable(true);
      }
    } catch (err: any) {
      setUser(null);
      setAuthStatus('degraded');
      setBackendAvailable(false);
      setConnectionError('Backend unavailable — some features may be limited.');
    }
  }, []);

  useEffect(() => {
    let isCancelled = false;

    // Hard fail-safe: Ensure authStatus NEVER stalls in 'initializing' for more than 2.5 seconds
    const safetyTimer = setTimeout(() => {
      if (!isCancelled) {
        setAuthStatus((prev) => (prev === 'initializing' ? 'unauthenticated' : prev));
      }
    }, 2500);

    const init = async () => {
      try {
        setConnectionError(null);
        const res = await api.getMe({ timeoutMs: 2000 });
        if (isCancelled) return;
        if (res && res.user) {
          setUser(res.user);
          setAuthStatus('authenticated');
          setBackendAvailable(true);
        } else {
          // Check for saved offline session
          const savedOffline = localStorage.getItem('scamguard_offline_user');
          if (savedOffline) {
            try {
              setUser(JSON.parse(savedOffline));
              setAuthStatus('degraded');
              setBackendAvailable(false);
              return;
            } catch {
              localStorage.removeItem('scamguard_offline_user');
            }
          }
          setUser(null);
          setAuthStatus('unauthenticated');
          setBackendAvailable(true);
        }
      } catch (err: any) {
        if (isCancelled) return;
        const savedOffline = localStorage.getItem('scamguard_offline_user');
        if (savedOffline) {
          try {
            setUser(JSON.parse(savedOffline));
            setAuthStatus('degraded');
            setBackendAvailable(false);
            return;
          } catch {
            localStorage.removeItem('scamguard_offline_user');
          }
        }
        setUser(null);
        setAuthStatus('degraded');
        setBackendAvailable(false);
        setConnectionError('Backend unavailable — some features may be limited.');
      } finally {
        clearTimeout(safetyTimer);
      }
    };

    init();

    return () => {
      isCancelled = true;
      clearTimeout(safetyTimer);
    };
  }, []);

  const loginOffline = (analystEmail: string = 'shreyasc299@gmail.com') => {
    const offlineAdmin: User = {
      id: '9edd6b5d-24ef-4519-a8f5-89fffcc74d91',
      name: 'System Administrator (Offline Fallback)',
      email: analystEmail.trim() || 'shreyasc299@gmail.com',
      role: 'admin',
      createdAt: new Date().toISOString(),
    };
    setUser(offlineAdmin);
    setAuthStatus('degraded');
    setBackendAvailable(false);
    setConnectionError('Operating in Offline SOC Mode — Backend server (port 8000) unreachable.');
    localStorage.setItem('scamguard_offline_user', JSON.stringify(offlineAdmin));
  };

  const login = async (email: string, password: string) => {
    try {
      const res = await api.login(email, password);
      setUser(res.user);
      setAuthStatus('authenticated');
      setBackendAvailable(true);
      setConnectionError(null);
      localStorage.removeItem('scamguard_offline_user');
    } catch (err: any) {
      // If server is unreachable (Failed to fetch) AND credentials match default admin,
      // enable seamless local fallback authentication so the analyst is NEVER blocked!
      const isConnectionIssue =
        err.message?.includes('Failed to fetch') ||
        err.message?.includes('NetworkError') ||
        err.message?.includes('unreachable') ||
        err.message?.includes('Failed to parse response') ||
        err.message?.includes('AbortError');

      if (
        isConnectionIssue &&
        email.toLowerCase() === 'shreyasc299@gmail.com' &&
        password === 'Shreyas@631'
      ) {
        loginOffline(email);
        return;
      }
      throw err;
    }
  };

  const register = async (name: string, email: string, password: string) => {
    const res = await api.register(name, email, password);
    setUser(res.user);
    setAuthStatus('authenticated');
    setBackendAvailable(true);
    setConnectionError(null);
    localStorage.removeItem('scamguard_offline_user');
  };

  const logout = async () => {
    localStorage.removeItem('scamguard_offline_user');
    localStorage.removeItem('scamguard_session_id');
    try {
      await api.logout();
    } finally {
      setUser(null);
      setAuthStatus('unauthenticated');
    }
  };

  const retryConnection = async () => {
    setAuthStatus('initializing');
    await checkAuth();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        authStatus,
        loading: authStatus === 'initializing',
        backendAvailable,
        connectionError,
        login,
        loginOffline,
        register,
        logout,
        refreshUser: checkAuth,
        retryConnection,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
