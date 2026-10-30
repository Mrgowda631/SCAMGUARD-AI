import {
  User,
  AnalysisResult,
  ScanItem,
  UrlAnalysisResponse,
  AnalyticsData,
  ForensicReport,
  AdminOverviewData,
} from '../types';

const rawBaseUrl = (import.meta.env.VITE_API_URL as string | undefined)?.trim().replace(/\/+$/, '');
const BASE_URL = rawBaseUrl
  ? (rawBaseUrl.endsWith('/api') ? rawBaseUrl : `${rawBaseUrl}/api`)
  : '/api';

export const getApiBaseUrl = (): string => BASE_URL;

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 25000, signal: externalSignal, ...fetchOptions } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  if (externalSignal) {
    externalSignal.addEventListener('abort', () => controller.abort());
  }

  try {
    const headers = new Headers(fetchOptions.headers || {});
    if (!headers.has('Content-Type') && !(fetchOptions.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    // Attach session token for cross-origin authentication (Safari / Netlify / Render compatibility)
    const storedSession = localStorage.getItem('scamguard_session_id');
    if (storedSession && !headers.has('X-Session-Id')) {
      headers.set('X-Session-Id', storedSession);
    }

    let response: Response;
    try {
      response = await fetch(`${BASE_URL}${endpoint}`, {
        ...fetchOptions,
        headers,
        signal: controller.signal,
        credentials: 'include', // Ensures HTTP-only session cookies are transmitted
      });
    } catch (networkErr: any) {
      // Automatic dual-channel fallback: If running on localhost and proxy fetch fails (e.g. Vite proxy drop),
      // attempt direct fetch to backend service on port 8000
      if (
        typeof window !== 'undefined' &&
        (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') &&
        !BASE_URL.includes(':8000')
      ) {
        const directUrl = `http://${window.location.hostname}:8000/api${endpoint}`;
        try {
          response = await fetch(directUrl, {
            ...fetchOptions,
            headers,
            signal: controller.signal,
            credentials: 'include',
          });
        } catch {
          throw networkErr;
        }
      } else {
        throw networkErr;
      }
    }

    // Handle file downloads
    const disposition = response.headers.get('Content-Disposition');
    if (disposition && disposition.includes('attachment')) {
      const blob = await response.blob();
      return blob as unknown as T;
    }

    let data: any;
    try {
      data = await response.json();
    } catch {
      throw new Error(`Failed to parse response from server (${response.status} ${response.statusText})`);
    }

    if (!response.ok || data.success === false) {
      if (endpoint === '/auth/me' && response.status === 401) {
        return { success: false, user: null } as unknown as T;
      }
      const errorMsg = data.error || (data.details ? data.details.map((d: any) => d.message).join(', ') : 'Request failed');
      throw new Error(errorMsg);
    }

    return data as T;
  } catch (err: any) {
    if (err.name === 'AbortError') {
      throw new Error(`Request timed out after ${timeoutMs}ms: ${endpoint}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

import { runClientHeuristic } from './clientHeuristic';

export const DEFAULT_ANALYTICS: AnalyticsData = {
  summary: {
    totalScans: 0,
    scamsDetected: 0,
    suspiciousContent: 0,
    genuineContent: 0,
    avgRiskScore: 0,
  },
  dailyActivity: [
    { date: '2026-10-10', day: 'Mon', scans: 0, scams: 0 },
    { date: '2026-10-11', day: 'Tue', scans: 0, scams: 0 },
    { date: '2026-10-12', day: 'Wed', scans: 0, scams: 0 },
    { date: '2026-10-13', day: 'Thu', scans: 0, scams: 0 },
    { date: '2026-10-14', day: 'Fri', scans: 0, scams: 0 },
    { date: '2026-10-15', day: 'Sat', scans: 0, scams: 0 },
    { date: '2026-10-16', day: 'Sun', scans: 0, scams: 0 },
  ],
  riskDistribution: [
    { name: 'Critical Scam (60-100)', count: 0, color: '#EF4444' },
    { name: 'Suspicious (30-59)', count: 0, color: '#F59E0B' },
    { name: 'Genuine / Benign (0-29)', count: 0, color: '#10B981' },
  ],
  categoryBreakdown: [],
  typeBreakdown: [
    { type: 'message', count: 0 },
    { type: 'url', count: 0 },
    { type: 'social', count: 0 },
  ],
  recentScans: [],
  disclaimer: 'Displaying local client baseline telemetry. Connect to the backend API service for persistent database telemetry.',
};

export const api = {
  // System Health
  getHealth: (options: RequestOptions = {}) => request<any>('/health', { timeoutMs: 3500, ...options }),
  getSettingsInfo: (options: RequestOptions = {}) => request<any>('/settings/info', { timeoutMs: 3500, ...options }),

  // Auth
  register: async (name: string, email: string, password: string) => {
    const res = await request<{ success: boolean; user: User; message: string; sessionId?: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password }),
      timeoutMs: 8000,
    });
    if (res.sessionId) {
      localStorage.setItem('scamguard_session_id', res.sessionId);
    }
    return res;
  },

  login: async (email: string, password: string) => {
    const res = await request<{ success: boolean; user: User; message: string; sessionId?: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
      timeoutMs: 8000,
    });
    if (res.sessionId) {
      localStorage.setItem('scamguard_session_id', res.sessionId);
    }
    return res;
  },

  logout: async () => {
    try {
      return await request<{ success: boolean; message: string }>('/auth/logout', {
        method: 'POST',
        timeoutMs: 3000,
      });
    } finally {
      localStorage.removeItem('scamguard_session_id');
    }
  },

  getMe: (options: RequestOptions = {}) =>
    request<{ success: boolean; user: User }>('/auth/me', { timeoutMs: 3500, ...options }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ success: boolean; message: string }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  getSessions: () =>
    request<{ success: boolean; sessions: any[] }>('/auth/sessions'),

  // Real-Time AI Threat Scanners
  scanContent: (content: string, platform?: string) =>
    request<{ success: boolean; scanId: string; analysis: AnalysisResult; timestamp: string }>('/detect', {
      method: 'POST',
      body: JSON.stringify({ content, platform }),
      timeoutMs: 30000,
    }),

  scanUrl: (url: string) =>
    request<{ success: boolean; scanId: string; urlReport: UrlAnalysisResponse; timestamp: string }>('/detect-url', {
      method: 'POST',
      body: JSON.stringify({ url }),
      timeoutMs: 30000,
    }),

  scanSocial: (content: string, platform: string) =>
    request<{ success: boolean; scanId: string; analysis: AnalysisResult; platform: string; timestamp: string }>(
      '/detect-social',
      {
        method: 'POST',
        body: JSON.stringify({ content, platform }),
        timeoutMs: 30000,
      }
    ),

  // Scans history
  getScans: (params?: {
    page?: number;
    limit?: number;
    search?: string;
    scanType?: string;
    prediction?: string;
    sortBy?: string;
    sortOrder?: string;
  }) => {
    const query = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, val]) => {
        if (val !== undefined && val !== null && val !== '') {
          query.set(key, String(val));
        }
      });
    }
    return request<{
      success: boolean;
      page: number;
      limit: number;
      total: number;
      totalPages: number;
      scans: ScanItem[];
    }>(`/scans?${query.toString()}`).catch(() => ({
      success: true,
      page: 1,
      limit: 10,
      total: 0,
      totalPages: 1,
      scans: [],
    }));
  },

  getScan: (id: string) => request<{ success: boolean; scan: ScanItem }>(`/scans/${id}`),

  deleteScan: (id: string) =>
    request<{ success: boolean; message: string }>(`/scans/${id}`, {
      method: 'DELETE',
    }),

  // Analytics with fallback
  getAnalytics: async () => {
    try {
      return await request<AnalyticsData>('/analytics');
    } catch (err) {
      console.warn('Could not load server analytics, using baseline telemetry defaults:', err);
      return DEFAULT_ANALYTICS;
    }
  },

  // Reports
  getReport: (scanId: string) => request<{ success: boolean; report: ForensicReport }>(`/reports/${scanId}`),

  downloadReportTxt: async (scanId: string, filename: string) => {
    const response = await fetch(`${BASE_URL}/reports/${scanId}?format=txt`, {
      credentials: 'include',
    });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  downloadReportJson: async (scanId: string, filename: string) => {
    const response = await fetch(`${BASE_URL}/reports/${scanId}?format=json`, {
      credentials: 'include',
    });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  downloadExportCsv: async () => {
    const response = await fetch(`${BASE_URL}/scans/export/csv`, {
      credentials: 'include',
    });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scamguard-scans-export-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  downloadExportJson: async () => {
    const response = await fetch(`${BASE_URL}/scans/export/json`, {
      credentials: 'include',
    });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scamguard-scans-export-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  // Admin
  getAdminOverview: () => request<AdminOverviewData>('/admin/overview'),
  getAdminUsers: () => request<{ success: boolean; users: any[] }>('/admin/users'),
  getAdminLogs: () => request<{ success: boolean; logs: any[] }>('/admin/audit-logs'),
};
