import { URL } from 'url';
import { AnalysisResult } from './heuristic.js';
import { analyzeContentWithGemini } from './gemini.js';

export interface UrlCheckStatus {
  name: string;
  status: 'passed' | 'flagged' | 'unavailable' | 'neutral';
  details: string;
}

export type ThreatVerdictTier = 'High Risk' | 'Potentially Suspicious' | 'No Obvious Threat Detected';

export interface UrlAnalysisResponse {
  url: string;
  normalizedUrl: string;
  parsed: {
    protocol: string;
    hostname: string;
    pathname: string;
    search: string;
    port: string;
    isIpAddress: boolean;
    subdomainCount: number;
    tld: string;
  };
  features: {
    hasLookalikeBrand: boolean;
    matchedBrand?: string;
    hasMisleadingSubdomain: boolean;
    hasPunycode: boolean;
    hasUnusualPort: boolean;
    isUrlShortener: boolean;
    hasHighRiskTld: boolean;
    hasDeceptivePath: boolean;
    hasSuspiciousParams: boolean;
    hasExcessiveSubdomains: boolean;
    isWhitelistedReputableDomain: boolean;
  };
  verdictTier: ThreatVerdictTier;
  availableChecks: UrlCheckStatus[];
  unavailableChecks: UrlCheckStatus[];
  analysis: AnalysisResult;
  scanTimestamp: string;
  disclaimer: string;
}

// Private / loopback / link-local IP prefixes for SSRF protection
const PRIVATE_IP_REGEX = /^(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|0\.|::1|fe80:|fc00:|localhost)/i;

// Authoritative Whitelisted Reputable Domains (never falsely flagged for having /login or /verify)
const REPUTABLE_DOMAINS = new Set([
  'google.com', 'google.co.in', 'google.co.uk', 'accounts.google.com',
  'github.com', 'microsoft.com', 'live.com', 'office.com', 'outlook.com',
  'apple.com', 'icloud.com', 'amazon.com', 'amazon.in', 'amazon.co.uk',
  'netflix.com', 'youtube.com', 'twitter.com', 'x.com', 'linkedin.com',
  'facebook.com', 'instagram.com', 'whatsapp.com', 'telegram.org',
  'zoom.us', 'dropbox.com', 'slack.com', 'cloudflare.com', 'wikipedia.org',
  'reddit.com', 'paypal.com', 'stripe.com', 'chase.com', 'bankofamerica.com',
  'wellsfargo.com', 'citibank.com', 'capitalone.com', 'fidelity.com',
  'vanguard.com', 'coinbase.com', 'binance.com', 'sbi.co.in', 'hdfcbank.com',
  'icicibank.com', 'fedex.com', 'ups.com', 'usps.com', 'dhl.com',
  'stackoverflow.com', 'gitlab.com', 'bitbucket.org', 'npm.js', 'npmjs.com'
]);

// Common brands targeted for phishing & typosquatting
const TARGETED_BRANDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
  'facebook', 'instagram', 'binance', 'coinbase', 'chase', 'wellsfargo',
  'whatsapp', 'telegram', 'bankofamerica', 'twitter', 'linkedin', 'steam',
  'roblox', 'discord', 'spotify', 'tiktok', 'uber', 'ebay', 'citibank',
  'capitalone', 'fedex', 'usps', 'dhl', 'hdfc', 'icici', 'sbi'
];

// High-risk TLDs frequently abused in malicious campaigns
const HIGH_RISK_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq',
  'country', 'stream', 'kim', 'racing', 'work', 'download', 'fit', 'surf',
  'rest', 'monster', 'icu', 'cam', 'sbs', 'cfd', 'quest', 'tokyo', 'beauty', 'hair'
]);

// Deceptive path tokens commonly used in credential harvesting
const DECEPTIVE_PATHS = [
  'login', 'signin', 'verify', 'update', 'account-update', 'billing',
  'wp-login', 'secure', 'auth', 'confirm', 'wallet', 'claim', 'airdrop',
  'password-reset', 'recover', 'security-checkpoint', 'otp', 'unlock', 'unblock'
];

// Known URL shorteners that obscure the real destination
const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly',
  'buff.ly', 'shorturl.at', 'goo.gl', 'qr.ae', 'v.gd', 'trib.al', 'dlvr.it'
]);

// Sensitive parameter names whose values must NOT be passed to external models
const SENSITIVE_PARAM_NAMES = new Set([
  'token', 'password', 'passwd', 'pwd', 'secret', 'key', 'apikey', 'auth',
  'jwt', 'session', 'sessionid', 'code', 'otp', 'pin', 'access_token',
  'refresh_token', 'credentials', 'hash'
]);

/**
 * Validates and safely normalizes a user-submitted URL.
 * Accepts URLs with or without http(s):// scheme.
 * Enforces strict SSRF protection and protocol whitelist.
 */
export function validateSafeUrl(rawUrl: string): { valid: boolean; error?: string; parsedUrl?: URL; normalizedUrl?: string } {
  if (typeof rawUrl !== 'string') {
    return { valid: false, error: 'URL input must be a valid text string.' };
  }

  let trimmed = rawUrl.trim();
  if (!trimmed) {
    return { valid: false, error: 'URL string is required. Please enter a valid web address.' };
  }

  if (trimmed.length > 2048) {
    return { valid: false, error: 'URL length exceeds safety limit of 2,048 characters.' };
  }

  // Check protocol scheme
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        valid: false,
        error: `Disallowed protocol "${scheme}:". Only secure HTTP and HTTPS web URLs are permitted for safety inspection.`,
      };
    }
  } else {
    // No scheme provided -> normalize by prepending https://
    trimmed = 'https://' + trimmed;
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: 'Malformed URL syntax. Please enter a valid web address (e.g. domain.com/path).' };
  }

  // Double check protocol
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: `Disallowed protocol "${parsed.protocol}". Only HTTP/HTTPS URLs are supported.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname.includes(' ')) {
    return { valid: false, error: 'Invalid hostname detected in URL.' };
  }

  // SSRF Protection: Deny local/internal/private hosts and reserved addresses
  if (
    PRIVATE_IP_REGEX.test(hostname) ||
    hostname === 'localhost' ||
    hostname === '0.0.0.0' ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return {
      valid: false,
      error: 'Scanning private, local, or loopback network addresses is restricted for security reasons.',
    };
  }

  return { valid: true, parsedUrl: parsed, normalizedUrl: parsed.toString() };
}

/**
 * Checks whether a hostname belongs to an authentic whitelisted reputable domain.
 */
function isReputableDomain(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (REPUTABLE_DOMAINS.has(normalized)) return true;

  // Check subdomains of reputable domains (e.g. accounts.google.com, security.github.com)
  for (const domain of REPUTABLE_DOMAINS) {
    if (normalized.endsWith(`.${domain}`)) {
      return true;
    }
  }

  // Check academic or government domains
  if (normalized.endsWith('.gov') || normalized.endsWith('.gov.in') || normalized.endsWith('.edu') || normalized.endsWith('.ac.in') || normalized.endsWith('.mil')) {
    return true;
  }

  return false;
}

/**
 * Checks for brand lookalike, typosquatting, and leetspeak substitution.
 */
function checkLookalike(hostname: string): { matches: boolean; brand?: string; hasMisleadingSubdomain: boolean } {
  const normalized = hostname.toLowerCase();

  // If authentic reputable domain, it is NOT an impersonation
  if (isReputableDomain(normalized)) {
    return { matches: false, hasMisleadingSubdomain: false };
  }

  const parts = normalized.split('.');
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : normalized;

  let matches = false;
  let matchedBrand: string | undefined;
  let hasMisleadingSubdomain = false;

  for (const brand of TARGETED_BRANDS) {
    // If exact brand domain e.g. paypal.com, skip
    if (normalized === `${brand}.com` || normalized.endsWith(`.${brand}.com`)) {
      continue;
    }

    // Check if brand keyword appears in subdomains while base domain is different (e.g. paypal.com.evil.xyz)
    if (parts.length > 2 && parts.slice(0, -2).some(sub => sub.includes(brand))) {
      matches = true;
      matchedBrand = brand;
      hasMisleadingSubdomain = true;
      break;
    }

    // Check hyphenated / compound domains: e.g. paypal-security.com, chase-online.xyz
    if (baseDomain.includes(`${brand}-`) || baseDomain.includes(`-${brand}`)) {
      matches = true;
      matchedBrand = brand;
      break;
    }

    // Leetspeak / homoglyph substitution in base domain: e.g. paypa1, micros0ft
    const leetReplaced = normalized
      .replace(/1/g, 'l')
      .replace(/0/g, 'o')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/8/g, 'b')
      .replace(/vv/g, 'w')
      .replace(/rn/g, 'm');

    if (leetReplaced.includes(brand) && !normalized.includes(brand)) {
      matches = true;
      matchedBrand = brand;
      break;
    }
  }

  return { matches, brand: matchedBrand, hasMisleadingSubdomain };
}

/**
 * Sanitizes URL for external AI analysis by redacting sensitive parameters.
 */
function sanitizeUrlForPrompt(url: URL): string {
  const sanitized = new URL(url.toString());
  for (const key of Array.from(sanitized.searchParams.keys())) {
    if (SENSITIVE_PARAM_NAMES.has(key.toLowerCase())) {
      sanitized.searchParams.set(key, '[REDACTED_SENSITIVE_TOKEN]');
    }
  }
  return sanitized.toString();
}

export interface UrlStructuralAnalysis {
  url: string;
  normalizedUrl: string;
  parsed: {
    protocol: string;
    hostname: string;
    pathname: string;
    search: string;
    port: string;
    isIpAddress: boolean;
    subdomainCount: number;
    tld: string;
  };
  features: {
    hasLookalikeBrand: boolean;
    matchedBrand?: string;
    hasMisleadingSubdomain: boolean;
    hasPunycode: boolean;
    hasUnusualPort: boolean;
    isUrlShortener: boolean;
    hasHighRiskTld: boolean;
    hasDeceptivePath: boolean;
    hasSuspiciousParams: boolean;
    hasExcessiveSubdomains: boolean;
    isWhitelistedReputableDomain: boolean;
  };
  lookalike: { matches: boolean; brand?: string; hasMisleadingSubdomain: boolean };
  structuralRiskScore: number;
  boundedStructuralRisk: number;
  structuralIndicators: { phrase: string; reason: string }[];
  verdictTier: ThreatVerdictTier;
  availableChecks: UrlCheckStatus[];
  unavailableChecks: UrlCheckStatus[];
  isWhitelisted: boolean;
  sanitizedUrlPrompt: string;
}

/**
 * Performs fast, deterministic structural URL inspection without invoking external AI models.
 */
export function analyzeUrlStructure(rawUrl: string): UrlStructuralAnalysis {
  const validation = validateSafeUrl(rawUrl);
  if (!validation.valid || !validation.parsedUrl) {
    throw new Error(validation.error || 'Invalid URL supplied for analysis.');
  }

  const url = validation.parsedUrl;
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname.toLowerCase();
  const search = url.search.toLowerCase();
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');

  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const parts = hostname.split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  const subdomainCount = Math.max(0, parts.length - 2);

  const isWhitelisted = isReputableDomain(hostname);

  // Detect Punycode / IDN
  const hasPunycode = hostname.includes('xn--') || /[^\u0000-\u007F]/.test(hostname);

  // Detect Unusual Ports (non-80 and non-443)
  const hasUnusualPort = Boolean(url.port && url.port !== '80' && url.port !== '443');

  // Detect Known Shortener
  const isUrlShortener = KNOWN_SHORTENERS.has(hostname) || Array.from(KNOWN_SHORTENERS).some(s => hostname.endsWith(`.${s}`));

  // Detect Brand Lookalikes & Misleading Subdomains
  const lookalike = checkLookalike(hostname);

  // High Risk TLD
  const hasHighRiskTld = !isWhitelisted && HIGH_RISK_TLDS.has(tld);

  // Deceptive Path Tokens (ONLY flag on non-whitelisted domains to prevent false positives on GitHub/Google login)
  const hasDeceptivePath = !isWhitelisted && DECEPTIVE_PATHS.some(p => pathname.includes(p));

  // Suspicious Query Parameters (detect open redirects or token leakage on suspicious sites)
  const hasSuspiciousParams = !isWhitelisted && ['redirect', 'return_to', 'wallet', 'target_url', 'forward'].some(
    param => url.searchParams.has(param)
  );

  const hasExcessiveSubdomains = !isWhitelisted && subdomainCount > 2;

  // Compute deterministic indicators
  const structuralIndicators: { phrase: string; reason: string }[] = [];
  let structuralRiskScore = 0;

  if (isWhitelisted) {
    // Whitelisted reputable domain: heavily dampen structural risk
    structuralRiskScore = 0;
  } else {
    if (lookalike.matches) {
      structuralRiskScore += 45;
      structuralIndicators.push({
        phrase: hostname,
        reason: `Brand impersonation / typosquatting targeting "${lookalike.brand}". Deceptively mimics authentic service domain.`,
      });
    }

    if (lookalike.hasMisleadingSubdomain) {
      structuralRiskScore += 25;
      structuralIndicators.push({
        phrase: hostname,
        reason: `Misleading subdomain structure: targeted brand keywords appear in subdomains to confuse victims regarding the actual root domain.`,
      });
    }

    if (hasPunycode) {
      structuralRiskScore += 35;
      structuralIndicators.push({
        phrase: hostname,
        reason: 'Punycode / IDN internationalized domain detected (xn--). Often utilized for visual homograph spoofing attacks.',
      });
    }

    if (isIpAddress) {
      structuralRiskScore += 40;
      structuralIndicators.push({
        phrase: hostname,
        reason: 'Raw IP address used as hostname instead of a domain name to evade domain reputation and blocklist filters.',
      });
    }

    if (isUrlShortener) {
      structuralRiskScore += 25;
      structuralIndicators.push({
        phrase: hostname,
        reason: 'Known URL shortening service. Shortened links conceal the ultimate landing destination and evade heuristic previews.',
      });
    }

    if (hasUnusualPort) {
      structuralRiskScore += 25;
      structuralIndicators.push({
        phrase: `Port :${port}`,
        reason: `Non-standard web port (:${port}) detected. Legitimate public services standardly bind to port 80/443.`,
      });
    }

    if (hasHighRiskTld) {
      structuralRiskScore += 25;
      structuralIndicators.push({
        phrase: `.${tld}`,
        reason: `Top-level domain (.${tld}) has high statistical correlation with disposable spam, malware, and phishing infrastructure.`,
      });
    }

    if (hasDeceptivePath) {
      structuralRiskScore += 20;
      structuralIndicators.push({
        phrase: pathname,
        reason: 'Path on untrusted domain contains credential-harvesting tokens (e.g. login, signin, verify, auth, wallet).',
      });
    }

    if (hasSuspiciousParams) {
      structuralRiskScore += 15;
      structuralIndicators.push({
        phrase: search,
        reason: 'Query string contains sensitive redirection or authentication parameters.',
      });
    }

    if (hasExcessiveSubdomains) {
      structuralRiskScore += 15;
      structuralIndicators.push({
        phrase: hostname,
        reason: `Excessive subdomain nesting (${subdomainCount} levels) used to mask authentic domain hierarchy.`,
      });
    }
  }

  // Available technical audits
  const availableChecks: UrlCheckStatus[] = [
    {
      name: 'SSRF & Private Network Guard',
      status: 'passed',
      details: 'Destination is outside private RFC 1918 subnets, link-local, and loopback boundaries.',
    },
    {
      name: 'Domain Reputation & Authenticity Check',
      status: isWhitelisted ? 'passed' : 'neutral',
      details: isWhitelisted
        ? `Recognized verified authentic domain: ${hostname}`
        : `Standard public domain: ${hostname}`,
    },
    {
      name: 'Hostname & Structure Verification',
      status: isIpAddress ? 'flagged' : 'passed',
      details: isIpAddress
        ? 'URL utilizes a raw numerical IP address instead of a registered domain name (common evasion).'
        : `Domain hostname parsed cleanly: ${hostname}`,
    },
    {
      name: 'Typosquatting & Brand Impersonation',
      status: lookalike.matches ? 'flagged' : 'passed',
      details: lookalike.matches
        ? `Contains brand mimicry targeting "${lookalike.brand}". Likely deceptive imitation.`
        : isWhitelisted
        ? 'Verified authentic brand domain.'
        : 'No deceptive brand typosquatting detected in the hostname.',
    },
    {
      name: 'Punycode & Homograph Inspection',
      status: hasPunycode ? 'flagged' : 'passed',
      details: hasPunycode
        ? 'Punycode prefix (xn--) detected; possible internationalized homoglyph spoofing.'
        : 'Standard ASCII character set utilized across hostname.',
    },
    {
      name: 'Port & Protocol Verification',
      status: hasUnusualPort ? 'flagged' : 'passed',
      details: hasUnusualPort
        ? `Unusual port :${port} detected in URL.`
        : `Standard ${url.protocol} port :${port} utilized.`,
    },
    {
      name: 'URL Shortener Detection',
      status: isUrlShortener ? 'flagged' : 'passed',
      details: isUrlShortener
        ? 'URL shortener identified. Target hides destination endpoint.'
        : 'Direct destination hostname (not a recognized URL shortener).',
    },
    {
      name: 'TLD Reputation Assessment',
      status: hasHighRiskTld ? 'flagged' : 'passed',
      details: hasHighRiskTld
        ? `TLD ".${tld}" has a statistically elevated association with fraudulent campaigns.`
        : `TLD ".${tld}" standard top-level domain classification.`,
    },
    {
      name: 'Deceptive Path & Parameter Audit',
      status: hasDeceptivePath || hasSuspiciousParams ? 'flagged' : 'passed',
      details: [
        hasDeceptivePath ? 'Path contains credential-harvesting keywords.' : null,
        hasSuspiciousParams ? 'Query string contains sensitive token/redirect parameters.' : null,
      ].filter(Boolean).join(' ') || (isWhitelisted ? 'Verified authentic service endpoints.' : 'Path and query parameters appear standard.'),
    },
  ];

  // Unavailable audits (honestly declared per Requirement 8)
  const unavailableChecks: UrlCheckStatus[] = [
    {
      name: 'Active Outbound HTTP Sandbox Crawler',
      status: 'unavailable',
      details: 'Live outbound network fetching is intentionally disabled to eliminate SSRF attack surface and prevent client-side drive-by malware execution.',
    },
    {
      name: 'Registrar WHOIS Domain Age Lookup',
      status: 'unavailable',
      details: 'Live WHOIS API key/RDAP subscriber quota is unconfigured. Domain registration timestamp cannot be independently verified.',
    },
    {
      name: 'Commercial Threat Intelligence Feeds',
      status: 'unavailable',
      details: 'Third-party feeds (VirusTotal Enterprise, Google Safe Browsing API) are currently unconfigured in backend environment.',
    },
  ];

  const boundedStructuralRisk = Math.min(100, Math.max(0, structuralRiskScore));

  let verdictTier: ThreatVerdictTier = 'No Obvious Threat Detected';
  if (boundedStructuralRisk >= 60) {
    verdictTier = 'High Risk';
  } else if (boundedStructuralRisk >= 30) {
    verdictTier = 'Potentially Suspicious';
  }

  // Build sanitized prompt for AI
  const sanitizedUrlString = sanitizeUrlForPrompt(url);
  const sanitizedUrlPrompt = `URL Forensic Inspection:
Target URL: ${sanitizedUrlString}
Parsed Host: ${hostname}
Port: ${port}
Is Raw IP: ${isIpAddress}
Is Verified Whitelisted Domain: ${isWhitelisted}
TLD: .${tld} (${hasHighRiskTld ? 'High Risk' : 'Standard'})
Brand Mimicry: ${lookalike.matches ? `Targeting ${lookalike.brand}` : 'None'}
Misleading Subdomains: ${lookalike.hasMisleadingSubdomain ? 'Yes' : 'No'}
Punycode Homograph: ${hasPunycode ? 'Yes (xn--)' : 'No'}
URL Shortener: ${isUrlShortener ? 'Yes' : 'No'}
Path Keywords: ${hasDeceptivePath ? 'Deceptive auth keywords present' : 'None'}
Query Parameters: ${hasSuspiciousParams ? 'Suspicious auth/redirect parameters present' : 'None'}
Subdomain Depth: ${subdomainCount}
Calculated Structural Risk Score: ${boundedStructuralRisk}/100`;

  return {
    url: rawUrl,
    normalizedUrl: url.toString(),
    parsed: {
      protocol: url.protocol,
      hostname,
      pathname: url.pathname,
      search: url.search,
      port,
      isIpAddress,
      subdomainCount,
      tld,
    },
    features: {
      hasLookalikeBrand: lookalike.matches,
      matchedBrand: lookalike.brand,
      hasMisleadingSubdomain: lookalike.hasMisleadingSubdomain,
      hasPunycode,
      hasUnusualPort,
      isUrlShortener,
      hasHighRiskTld,
      hasDeceptivePath,
      hasSuspiciousParams,
      hasExcessiveSubdomains,
      isWhitelistedReputableDomain: isWhitelisted,
    },
    lookalike,
    structuralRiskScore,
    boundedStructuralRisk,
    structuralIndicators,
    verdictTier,
    availableChecks,
    unavailableChecks,
    isWhitelisted,
    sanitizedUrlPrompt,
  };
}

/**
 * Performs full forensic URL analysis combining deterministic indicators & AI assessment.
 */
export async function analyzeUrl(rawUrl: string): Promise<UrlAnalysisResponse> {
  const struct = analyzeUrlStructure(rawUrl);
  const {
    url,
    normalizedUrl,
    parsed,
    features,
    lookalike,
    structuralRiskScore,
    boundedStructuralRisk,
    structuralIndicators,
    availableChecks,
    unavailableChecks,
    isWhitelisted,
    sanitizedUrlPrompt,
  } = struct;

  let analysis = await analyzeContentWithGemini(sanitizedUrlPrompt, 'url');

  // If reputable domain, ensure risk score does not trigger false positives
  if (isWhitelisted) {
    analysis = {
      ...analysis,
      prediction: 'genuine',
      risk_score: Math.min(15, analysis.risk_score),
      category: 'legitimate',
      explanation: `Verified authentic domain (${parsed.hostname}). Standard official service endpoints.`,
      summary: `Verified authentic domain (${parsed.hostname}). No obvious threat detected.`,
      recommendations: [
        'Always verify SSL/TLS lock icon in your browser address bar.',
        'Ensure you are connecting over HTTPS before submitting login credentials.',
      ],
    };
  } else if (analysis.engine === 'heuristic_fallback' || boundedStructuralRisk > analysis.risk_score) {
    // If running in heuristic fallback or structural risk detected malicious signals:
    const finalScore = Math.max(analysis.risk_score, boundedStructuralRisk);
    let finalPrediction: 'scam' | 'suspicious' | 'genuine' = 'genuine';
    if (finalScore >= 60) {
      finalPrediction = 'scam';
    } else if (finalScore >= 30) {
      finalPrediction = 'suspicious';
    }

    const mergedIndicators = [...structuralIndicators];
    for (const ind of analysis.indicators) {
      if (!mergedIndicators.some(m => m.phrase === ind.phrase)) {
        mergedIndicators.push(ind);
      }
    }

    analysis = {
      ...analysis,
      prediction: finalPrediction,
      risk_score: finalScore,
      category: lookalike.matches
        ? 'phishing'
        : parsed.isIpAddress
        ? 'suspicious_infrastructure'
        : features.isUrlShortener
        ? 'obfuscated_shortener'
        : features.hasDeceptivePath
        ? 'phishing'
        : analysis.category,
      indicators: mergedIndicators,
      explanation: structuralRiskScore > 0
        ? `Structural inspection identified ${structuralIndicators.length} risk vectors. Hostname "${parsed.hostname}" exhibits characteristics correlated with deceptive infrastructure. ${analysis.explanation}`
        : analysis.explanation,
      summary: finalPrediction === 'scam'
        ? `High-risk malicious URL flagged (Score: ${finalScore}/100). Deceptive patterns detected.`
        : finalPrediction === 'suspicious'
        ? `Potentially suspicious URL traits identified (Score: ${finalScore}/100). Exercise heightened caution.`
        : `No obvious threat detected (Score: ${finalScore}/100). Standard structure.`,
    };
  }

  // Derive Three-Tier Verdict:
  let verdictTier: ThreatVerdictTier = 'No Obvious Threat Detected';
  if (analysis.risk_score >= 60 || analysis.prediction === 'scam') {
    verdictTier = 'High Risk';
  } else if (analysis.risk_score >= 30 || analysis.prediction === 'suspicious') {
    verdictTier = 'Potentially Suspicious';
  }

  const scanTimestamp = new Date().toISOString();
  const disclaimer = 'Automated security checks and AI heuristic models cannot guarantee complete safety. Zero-day domains, targeted spear-phishing, or legitimate sites compromised after analysis may evade detection. Always verify the domain and sender before submitting confidential credentials.';

  return {
    url,
    normalizedUrl,
    parsed,
    features,
    verdictTier,
    availableChecks,
    unavailableChecks,
    analysis,
    scanTimestamp,
    disclaimer,
  };
}
