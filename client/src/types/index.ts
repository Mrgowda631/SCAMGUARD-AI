export interface User {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'admin';
  createdAt: string;
}

export interface ScanIndicator {
  phrase: string;
  reason: string;
}

export interface UrlAnalysisDetail {
  found: boolean;
  urls: string[];
  findings: string[];
}

export interface AnalysisResult {
  // Required structured fields (Phase 5 Standardized Response)
  classification?: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  risk_score: number;
  confidence: number;
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  intent?: string;
  requested_action?: string;
  requestedAction?: string;
  detected_indicators?: string[];
  evidence?: string[];
  explanation: string;
  recommended_action?: string;
  url_analysis?: string | UrlAnalysisDetail;
  analysis_source?: 'AI_AND_HEURISTICS' | 'HEURISTICS_FALLBACK';
  limitations?: string | string[];
  requires_review?: boolean;

  // Legacy/compatibility fields
  prediction: 'scam' | 'suspicious' | 'genuine';
  category: string;
  indicators: ScanIndicator[];
  recommendations: string[];
  summary: string;
  engine: 'openai' | 'gemini' | 'heuristic_fallback';
}

export interface ScanItem {
  id: string;
  userId?: string;
  scanType: 'message' | 'url' | 'social';
  platform?: string | null;
  inputSummary: string;
  inputRaw?: string;
  classification?: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  prediction: 'scam' | 'suspicious' | 'genuine';
  riskScore: number;
  confidence: number;
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  intent?: string;
  requested_action?: string;
  requestedAction?: string;
  detected_indicators?: string[];
  evidence?: string[];
  indicators?: ScanIndicator[];
  explanation?: string;
  recommended_action?: string;
  url_analysis?: string | UrlAnalysisDetail;
  analysis_source?: 'AI_AND_HEURISTICS' | 'HEURISTICS_FALLBACK';
  limitations?: string | string[];
  requires_review?: boolean;
  recommendations?: string[];
  engine: 'openai' | 'gemini' | 'heuristic_fallback';
  createdAt: string;
}

export interface UrlCheckStatus {
  name: string;
  status: 'passed' | 'flagged' | 'unavailable' | 'neutral';
  details: string;
}

export type ThreatVerdictTier = 'High Risk' | 'Potentially Suspicious' | 'No Obvious Threat Detected';

export interface UrlAnalysisResponse {
  url: string;
  normalizedUrl?: string;
  parsed: {
    protocol: string;
    hostname: string;
    pathname: string;
    search: string;
    port?: string;
    isIpAddress: boolean;
    subdomainCount: number;
    tld: string;
  };
  features: {
    hasLookalikeBrand: boolean;
    matchedBrand?: string;
    hasMisleadingSubdomain?: boolean;
    hasPunycode?: boolean;
    hasUnusualPort?: boolean;
    isUrlShortener?: boolean;
    hasHighRiskTld: boolean;
    hasDeceptivePath: boolean;
    hasSuspiciousParams: boolean;
    hasExcessiveSubdomains: boolean;
  };
  verdictTier?: ThreatVerdictTier;
  availableChecks: UrlCheckStatus[];
  unavailableChecks: UrlCheckStatus[];
  analysis: AnalysisResult;
  scanTimestamp?: string;
  disclaimer?: string;
}

export interface AnalyticsSummary {
  totalScans: number;
  scamsDetected: number;
  suspiciousContent: number;
  genuineContent: number;
  avgRiskScore: number;
}

export interface AnalyticsData {
  summary: AnalyticsSummary;
  riskDistribution: { name: string; count: number; color: string }[];
  typeBreakdown: { type: string; count: number }[];
  categoryBreakdown: { category: string; count: number }[];
  dailyActivity: { date: string; day: string; scans: number; scams: number }[];
  recentScans: ScanItem[];
  disclaimer: string;
}

export interface ForensicReport {
  reportId: string;
  scanId: string;
  generatedAt: string;
  scanTimestamp: string;
  scanType: string;
  platform: string;
  classification?: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  prediction: 'scam' | 'suspicious' | 'genuine';
  riskScore: number;
  confidence: number;
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  intent?: string;
  requested_action?: string;
  requestedAction?: string;
  analysisEngine: string;
  inputSummary: string;
  inputRaw?: string;
  indicators: ScanIndicator[];
  evidence?: string[];
  explanation: string;
  recommendations: string[];
  disclaimer: string;
  limitations: string[];
  requires_review?: boolean;
}

export interface AdminTelemetry {
  totalUsers: number;
  totalScans: number;
  totalScams: number;
  totalSuspicious: number;
  totalGenuine: number;
  geminiScans: number;
  heuristicScans: number;
  activeSessions: number;
}

export interface SystemHealth {
  status: string;
  uptimeSeconds: number;
  nodeVersion: string;
  environment: string;
  memoryUsageMb: number;
}

export interface AdminOverviewData {
  telemetry: AdminTelemetry;
  systemHealth: SystemHealth;
  geminiStatus: {
    configured: boolean;
    model: string;
    activeEngine: 'gemini' | 'heuristic_fallback';
  };
  recentLogs: {
    id: string;
    action: string;
    details: string;
    ip_address: string;
    timestamp: string;
  }[];
}
