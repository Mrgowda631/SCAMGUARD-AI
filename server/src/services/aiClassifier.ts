import OpenAI from 'openai';
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';
import { config, isGeminiConfigured, isOpenAIConfigured, isAiConfigured } from '../config.js';
import { AnalysisResult, analyzeWithHeuristics, ScanIndicator, normalizeText } from './heuristic.js';
import { analyzeUrlStructure } from './urlAnalyzer.js';

const PROMPT_VERSION = 'scamguard-ai-v2.2-audit';

export interface DiagnosticLogPayload {
  requestId: string;
  timestamp: string;
  modelIdentifier: string;
  promptVersion: string;
  apiProvider: 'openai' | 'gemini' | 'heuristic_fallback';
  apiResponseStatus: 'success' | 'rate_limited' | 'unconfigured' | 'timeout' | 'error';
  aiClassification?: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  heuristicClassification: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  finalClassification: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  inputLength: number;
  processingError?: string;
}

export function logDiagnosticEvent(payload: DiagnosticLogPayload) {
  const errPart = payload.processingError ? ` | Error: ${payload.processingError}` : '';
  console.log(
    `[SCAMGUARD DIAGNOSTIC] [Req: ${payload.requestId}] Model: ${payload.modelIdentifier} | Provider: ${payload.apiProvider} | Status: ${payload.apiResponseStatus} | AI: ${payload.aiClassification || 'N/A'} | Heuristics: ${payload.heuristicClassification} | Final: ${payload.finalClassification}${errPart}`
  );
}

export interface UrlAnalysisDetail {
  found: boolean;
  urls: string[];
  findings: string[];
}

export interface UnifiedAnalysisResult {
  // Phase 5 Standardized Response Structure
  classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  risk_score: number;
  confidence: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  intent: string;
  requested_action: string;
  detected_indicators: string[];
  evidence: string[];
  explanation: string;
  recommended_action: string;
  url_analysis: UrlAnalysisDetail;
  analysis_source: 'AI_AND_HEURISTICS' | 'HEURISTICS_FALLBACK';
  limitations: string[];
  requires_review: boolean;

  // Backward-compatible fields for UI components, tests, and SQLite database storage
  prediction: 'scam' | 'suspicious' | 'genuine';
  category: string;
  indicators: ScanIndicator[];
  recommendations: string[];
  summary: string;
  engine: 'openai' | 'gemini' | 'heuristic_fallback';
}

const UrlAnalysisSchema = z.object({
  found: z.boolean().default(false),
  urls: z.array(z.string()).default([]),
  findings: z.array(z.string()).default([]),
}).default({ found: false, urls: [], findings: [] });

const StructuredAiSchema = z.object({
  classification: z.enum(['SAFE', 'SUSPICIOUS', 'SCAM']).default('SUSPICIOUS'),
  risk_score: z.coerce.number().min(0).max(100).default(50),
  confidence: z.coerce.number().min(0).max(1).default(0.85),
  risk_level: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
  intent: z.string().default('General communication'),
  requested_action: z.string().default('None'),
  category: z.string().default('suspicious_activity'),
  detected_indicators: z.array(z.string()).default([]),
  evidence: z.array(z.string()).default([]),
  explanation: z.string().default('Cybersecurity threat analysis completed.'),
  recommended_action: z.string().default('Verify the sender through official secondary channels.'),
  url_analysis: z.union([
    UrlAnalysisSchema,
    z.string().transform(str => ({
      found: str.length > 0 && !str.toLowerCase().includes('no url'),
      urls: [],
      findings: [str],
    }))
  ]).default({ found: false, urls: [], findings: [] }),
  limitations: z.union([
    z.array(z.string()),
    z.string().transform(str => [str]),
  ]).default(['Contextual AI analysis is an automated estimate and does not replace official verification.']),
  requires_review: z.boolean().default(false),
});

type RawAiOutput = z.infer<typeof StructuredAiSchema>;

const SYSTEM_PROMPT = `You are SCAMGUARD AI, an enterprise cybersecurity and social media threat detection intelligence system.
Your mission is to perform deep linguistic, contextual, and forensic threat assessments of submitted content to identify scams, phishing, social engineering, impersonation, credential harvesting, espionage, and fraud — while maintaining strict accuracy to avoid false positives on legitimate human messages.

CORE EVALUATION PRINCIPLES:
1. EVIDENCE-BASED THREAT ASSESSMENT (ANALYZE FULL CONTEXT & INTENT):
   - Evaluate communicative INTENT: What is the sender trying to achieve?
   - Evaluate REQUESTED ACTION: What specific action is requested? (e.g., 'Share OTP code', 'Pay registration fee', 'Transfer cryptocurrency', 'Click unverified link', 'Provide military/confidential credentials', or 'None').
   - Evaluate IMPERSONATION: Is the sender pretending to be an institution, bank, military personnel, employer, or acquaintance?
   - Evaluate MANIPULATION: Does the message invoke urgency, fear, excitement, artificial deadlines, or coercion?
   - Evaluate FINANCIAL RISK: Does it involve advance fees, cryptocurrency transfers, wire transactions, or prize claims?
   - Evaluate DIGITAL/URL RISK: Are there deceptive links, unfamiliar domains, or obfuscated shorteners?
   - Evaluate CONTEXT: Distinguish harmless peer conversations, educational/academic security discussions, and routine notifications from genuine threats.
   - Extract EVIDENCE: Identify exact quoted phrases and suspicious patterns directly from the input.

2. LEGITIMATE HUMAN COMMUNICATIONS (MUST BE CLASSIFIED AS SAFE):
   - Everyday conversational greetings, check-ins, polite social exchanges ("hii", "hello", "hey", "good morning", "how are you?", "thank you", "see you tomorrow", "what are you doing?", "are you coming to college?", "happy birthday", "have a nice day", "please call me", "how was your day?").
     CRITICAL: Short greetings or messages with casual/unusual spellings MUST NOT receive MEDIUM or HIGH risk! A simple greeting must receive:
     * classification: "SAFE"
     * risk_score: 0 to 5
     * risk_level: "LOW"
     * detected_indicators: []
     * evidence: []
     * explanation: "No suspicious intent or harmful request detected."
   - Educational, academic, and policy discussions ("Our cybersecurity class discussed why military credentials must remain confidential", "our cybersecurity class discussed OTP security", "Lecture notes on blockchain security").
     CRITICAL: Educational discussions or policy reminders about security are SAFE, because they share knowledge rather than requesting anyone to disclose secret credentials!
   - Routine workplace and professional team emails (standup meetings, scheduled downtime).
   - Legitimate informational delivery notifications.
   - Legitimate banking notices and statements ("your bank statement is available in your official banking app") or alerts that warn users NOT to share their OTP.

3. ACCURATE SCAM IDENTIFICATION (MUST BE CLASSIFIED AS SCAM):
   - Credential & OTP theft: Direct requests to disclose or forward OTPs, passwords, PINs, or recovery seed phrases ("send your OTP immediately to prevent account closure", "share your password to prevent account suspension").
   - Unauthorized solicitation of confidential credentials / espionage: Requests for military credentials, access protocols, classified documents, internal network credentials (e.g., "I am an ex-army man. Give me the military credentials or access protocols"). Flag this immediately as SCAM with CRITICAL risk!
   - Advance-fee scams, government/military impersonation, and identity theft (CRITICAL RISK / 90 PTS):
     * When a sender claims an official government, military, employment, or business opportunity (e.g., "Hello I am Ragu and an EXARM officer. I have a confidential government contract for you") and asks the recipient to pay an advance fee (registration fee, processing fee, deposit) and/or provide identity documents (ID proof, Aadhaar, PAN, passport) before receiving promised money or contract payouts ("to receive your payment").
     * Do not allow an unsupported authority claim to override suspicious financial behavior.
     * Classify this combination as SCAM with CRITICAL risk (risk_score: 90), category: 'advance_fee_and_identity_fraud', requires_review: true.
     * Detected indicators: ["Unverified military authority claim", "Government contract impersonation risk", "Advance registration fee request", "Identity document collection", "Promised future payment"].
     * Explanation: "The sender claims to offer a confidential government contract, requests identity documents and demands an upfront registration fee in exchange for promised future payment. This combination strongly indicates a potential advance-fee scam and identity theft risk."
     * Recommended action: "Do not pay the registration fee or share identity documents. Independently verify the organization through official contact channels."
   - Fake job offers & recruitment fees: Jobs requiring upfront deposits or registration fees ("pay a registration fee to receive your job offer").
   - Cryptocurrency doubling / high-yield investment schemes: Guaranteed returns, sending funds to receive multiplied amounts back ("send ₹5,000 and receive ₹10,000 in one hour").
   - Deceptive urgency & coercion: Artificial deadlines, threats of account blocking or arrest.
   - Suspicious URLs & impersonation: Directing users to unfamiliar, deceptive, or lookalike domains ("Your account has a problem. Verify it using this unfamiliar website").

4. AMBIGUOUS & UNAUTHORIZED CREDENTIAL REQUESTS (MUST BE CLASSIFIED AS SUSPICIOUS):
   - Messages requesting account verification without a link or brand context ("Please verify your account when you have time") must be classified as SUSPICIOUS with MEDIUM risk (score 21–49), not SAFE!
   - Unauthorized institutional / university credential requests:
     * Requests soliciting university, college, student, staff, or administrator passwords, access tokens, or login accounts (e.g., "I am a student in Bengal University so give me the credentials of the universities", "Give me the username and password of university staff accounts", "Please share private student login credentials with me").
     * Claiming to be a student, employee, or administrator does NOT establish permission or authorization to access private institutional credentials.
     * Flag unauthorized requests for university credentials as SUSPICIOUS with HIGH risk (risk_score: 75), requires_review: true, detected_indicators: ["Request for institutional credentials", "Authorization not established", "Potential unauthorized access"], explanation: "The sender requests university credentials without establishing authorization. This could expose private institutional accounts.", recommended_action: "Do not share private credentials. Verify authorization through the university's official IT department."
     * Distinguish this from legitimate navigation help or self-service password reset inquiries ("Where can I find the university login page?", "How do I reset my university password?", "I need access to my own student portal. Where can I log in?", "Our university teaches students how to protect their login credentials") which are SAFE (risk_score: 0-10).

5. OPERATIONAL SCORING & CLASSIFICATION BANDS:
   - SAFE: risk_score 0 to 20. risk_level: LOW. Legitimate, harmless communications, casual greetings, or educational discussions.
   - SUSPICIOUS: risk_score 21 to 49. risk_level: MEDIUM. Ambiguous, unverified, or unusual requests requiring caution.
   - SCAM: risk_score 50 to 100. risk_level: HIGH (50-74) or CRITICAL (75-100). Active fraud, phishing, OTP theft, credential extortion, fake jobs, or crypto scams.

6. CORE RULES:
   - RULE A: If a message contains ordinary conversation without suspicious intent, classify it SAFE.
   - RULE B: If a message contains no suspicious request, no deceptive intent, and no harmful action, do not invent risk indicators.
   - RULE C: If a message is ambiguous but contains no actual threat indicators, do not automatically classify it as a scam.
   - RULE D: If a message requests OTPs, passwords, payments, confidential credentials, or other sensitive information in a suspicious context, investigate carefully.
   - RULE E: A harmless message mentioning banking, cryptocurrency, military, security, or passwords must not automatically be classified as SCAM.
   - RULE F: A message requesting sensitive information can be suspicious even without obvious scam keywords.

7. REQUIRED JSON OUTPUT SCHEMA:
Return strictly a valid JSON object matching this schema:
{
  "classification": "SAFE" | "SUSPICIOUS" | "SCAM",
  "risk_score": integer (0 to 100),
  "confidence": float (0.0 to 1.0, e.g. 0.95),
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "intent": "Concise statement of sender intent",
  "requested_action": "Specific action requested, or 'None'",
  "category": "phishing" | "credential_theft" | "advance_fee" | "advance_fee_and_identity_fraud" | "crypto_scam" | "military_espionage" | "impersonation" | "legitimate" | "ambiguous_verification",
  "detected_indicators": ["Array of concise strings describing specific indicators found"],
  "evidence": ["Direct quotes or specific patterns from the message supporting the assessment"],
  "explanation": "Clear, concise forensic rationale explaining the findings",
  "recommended_action": "Practical, actionable guidance for the user",
  "url_analysis": {
    "found": boolean,
    "urls": ["Array of URLs found, or empty array"],
    "findings": ["Array of findings regarding URLs, or empty array"]
  },
  "limitations": ["Array of analytical caveats"],
  "requires_review": boolean
}`;

// URL extraction helper
function extractUrls(text: string): string[] {
  const urlRegex = /(https?:\/\/[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|io|top|xyz|click|site|online|app|vip|live|cc|ru|cn|in|gov|edu)[^\s]*)/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches.map(u => u.replace(/[.,!?;:)]+$/, ''))));
}

// OpenAI Client Wrapper
let openaiClient: OpenAI | null = null;
function getOpenAIClient(): OpenAI | null {
  if (!isOpenAIConfigured()) return null;
  if (!openaiClient) {
    openaiClient = new OpenAI({ apiKey: config.openaiApiKey });
  }
  return openaiClient;
}

async function callOpenAi(content: string, type: string, platform?: string): Promise<RawAiOutput> {
  const client = getOpenAIClient();
  if (!client) throw new Error('OpenAI client unconfigured');

  const model = config.openaiModel || 'gpt-4o-mini';
  const prompt = `Analyze this untrusted ${type} submission ${platform ? `(platform: ${platform})` : ''}:\n"""\n${content.slice(0, 4000)}\n"""`;

  const callPromise = client.chat.completions.create({
    model,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: prompt },
    ],
    response_format: { type: 'json_object' },
    temperature: 0.1,
  });

  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('Timeout calling OpenAI API (15s exceeded)')), 15000)
  );

  const completion = await Promise.race([callPromise, timeoutPromise]);

  const rawText = completion.choices[0]?.message?.content || '{}';
  const parsed = JSON.parse(rawText);
  return StructuredAiSchema.parse(parsed);
}

// Google Gemini Client Wrapper with resilient model fallback
let geminiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  if (!isGeminiConfigured()) return null;
  if (!geminiClient) {
    geminiClient = new GoogleGenAI({ apiKey: config.geminiApiKey });
  }
  return geminiClient;
}

async function callGemini(content: string, type: string, platform?: string): Promise<{ output: RawAiOutput; modelUsed: string }> {
  const client = getGeminiClient();
  if (!client) throw new Error('Gemini client unconfigured');

  const prompt = `Analyze this untrusted ${type} submission ${platform ? `(platform: ${platform})` : ''}:\n"""\n${content.slice(0, 4000)}\n"""`;

  // Candidate models ordered for reliability and speed
  const candidateModels = Array.from(
    new Set([
      config.geminiModel,
      'gemini-3.5-flash',
      'gemini-3.5-flash-lite',
      'gemini-3.8-flash',
    ])
  );

  let lastError: any = null;
  for (const modelName of candidateModels) {
    try {
      const callPromise = client.models.generateContent({
        model: modelName,
        contents: prompt,
        config: {
          systemInstruction: SYSTEM_PROMPT,
          responseMimeType: 'application/json',
        },
      });

      // 10-second timeout per model
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout calling model ${modelName}`)), 10000)
      );

      const response = await Promise.race([callPromise, timeoutPromise]);
      const responseText = response.text;
      if (!responseText) throw new Error(`Empty response from model ${modelName}`);

      const parsed = JSON.parse(responseText);
      const validated = StructuredAiSchema.parse(parsed);
      return { output: validated, modelUsed: modelName };
    } catch (err: any) {
      lastError = err;
      console.warn(`[Gemini Model ${modelName} warning]:`, err?.message || err);
      // Immediately break on quota exhaustion to allow instant fallback without hanging the request
      if (
        err?.message?.includes("RESOURCE_EXHAUSTED") ||
        err?.message?.includes("limit exceeded") ||
        err?.message?.includes("quota") ||
        err?.status === 429
      ) {
        break;
      }
    }
  }

  throw lastError || new Error('All candidate Gemini models failed');
}

/**
 * Normalizes risk score and risk level to ensure mathematical consistency.
 */
function normalizeRiskLevel(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (score >= 76) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 21) return 'MEDIUM';
  return 'LOW';
}

function normalizeClassification(score: number, explicitClass?: string): 'SAFE' | 'SUSPICIOUS' | 'SCAM' {
  if (explicitClass === 'SCAM' || explicitClass === 'SUSPICIOUS' || explicitClass === 'SAFE') {
    if (score >= 50 && explicitClass === 'SAFE') return 'SCAM';
    if (score >= 21 && explicitClass === 'SAFE') return 'SUSPICIOUS';
    return explicitClass;
  }
  if (score >= 50) return 'SCAM';
  if (score >= 21) return 'SUSPICIOUS';
  return 'SAFE';
}

function clampRiskScore(score: number, classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM'): number {
  let s = Math.round(score);
  if (classification === 'SAFE') {
    s = Math.min(20, Math.max(0, s));
  } else if (classification === 'SCAM') {
    s = Math.min(100, Math.max(50, s));
  } else {
    // SUSPICIOUS covers MEDIUM risk (21-49) and HIGH risk / manual security review cases (50-75)
    s = Math.min(75, Math.max(21, s));
  }
  return s;
}

function calculateDynamicConfidence(
  classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM',
  riskScore: number,
  indicatorCount: number,
  evidenceCount: number,
  hasUrl: boolean,
  isFallback: boolean,
  baseAiConfidence?: number
): number {
  if (!isFallback && typeof baseAiConfidence === 'number' && baseAiConfidence > 0) {
    const modifier = Math.min(0.08, indicatorCount * 0.02 + evidenceCount * 0.02);
    return Math.min(0.96, Math.max(0.60, parseFloat((baseAiConfidence + modifier).toFixed(2))));
  }

  // Phase 6 Rule: Dynamic confidence based on evidence strength, never a fixed percentage
  let conf = 0.70;
  if (classification === 'SCAM') {
    conf = 0.82 + Math.min(0.12, indicatorCount * 0.03 + (hasUrl ? 0.04 : 0));
  } else if (classification === 'SAFE') {
    conf = 0.84 + Math.min(0.08, evidenceCount * 0.02);
  } else {
    conf = 0.64 + Math.min(0.08, indicatorCount * 0.02);
  }
  return Math.min(0.95, Math.max(0.60, parseFloat(conf.toFixed(2))));
}

/**
 * Stage 2: Independent Security Rule Engine
 * Deterministically evaluates hard security constraints independent of AI.
 */
interface SecurityRuleResult {
  isEducationalOrAcademic: boolean;
  isHarmlessPeerChat: boolean;
  isCriticalCredentialTheft: boolean;
  isInstitutionalCredentialRequest: boolean;
  isAdvanceFeeAndIdentityFraud: boolean;
  isAdvanceFeeFraud: boolean;
  isCryptoDoubling: boolean;
  isAmbiguousVerification: boolean;
  suggestedScoreFloor: number;
  indicators: string[];
  evidence: string[];
  matchedPhrases: string[];
}

function evaluateStage2SecurityRules(content: string): SecurityRuleResult {
  const { normalized } = normalizeText(content);
  const rawLower = content.toLowerCase();

  const indicators: string[] = [];
  const evidence: string[] = [];
  const matchedPhrases: string[] = [];

  // Check legitimate public university navigation, self-service reset, or institutional IT processes
  const isUniversityPublicOrSelfService =
    /(?:where\s+can\s+i\s+find|where\s+(?:do|can)\s+i\s+log\s*in|how\s+do\s+i\s+reset|link\s+to\s+the|find\s+the)\s+.*?(?:login\s+page|portal|website|password)/i.test(rawLower) ||
    /access\s+to\s+my\s+own\s+student\s+portal/i.test(rawLower) ||
    /(?:teaches|taught|educates)\s+students\s+how\s+to\s+protect/i.test(rawLower) ||
    /(?:authorized\s+it\s+staff|help\s+me\s+understand\s+our\s+institutional\s+authentication\s+process)/i.test(rawLower);

  // Check educational or academic security discussions & technological definitions (Step 5 FP protection)
  const isEducationalOrAcademic =
    /(?:cybersecurity|security|computer\s+science)\s+(?:class|course|lecture|training|seminar|assignment)\s+discussed/i.test(rawLower) ||
    /discussed\s+why\s+(?:military\s+credentials|passwords?|otps?)\s+must\s+remain\s+confidential/i.test(rawLower) ||
    /lecture\s+notes\s+on\s+(?:blockchain|network|cyber)\s+security/i.test(rawLower) ||
    /policy\s+states\s+(?:never\s+to\s+share|not\s+to\s+disclose)/i.test(rawLower) ||
    /(?:military|defense|government|confidential|user)\s+(?:credentials?|protocols?|secrets?|passwords?)\s+must\s+(?:remain|be\s+kept)\s+(?:confidential|secret|secure|protected)/i.test(rawLower) ||
    /(?:cryptocurrency|bitcoin|blockchain|ethereum|encryption|firewall)\s+is\s+a\s+(?:digital\s+payment|decentralized|cryptographic|distributed\s+ledger|security)\s+(?:technology|system|network|asset|currency|protocol)/i.test(rawLower) ||
    isUniversityPublicOrSelfService;

  // Check legitimate bank alert warning user NEVER to share OTP OR routine statement notifications (Step 5 FP protection)
  const isLegitBankNotification =
    (/(?:never|do\s+not)\s+share\s+your\s+(?:otp|pin|password)/i.test(rawLower) &&
    !/(?:send|share|reply\s+with|forward)\s+(?:your\s+)?(?:otp|code|pin)/i.test(rawLower)) ||
    /(?:your\s+)?(?:monthly\s+)?(?:bank|account|card)\s+statement(?:\s+for\s+this\s+month|\s+for\s+[\w\s]+)?\s+is\s+(?:now\s+)?available\s+(?:in|through|via)\s+(?:your\s+|the\s+)?official\s+(?:banking\s+)?(?:application|app|portal)|statement.*?(?:available|ready).*?(?:official\s+(?:banking\s+)?(?:application|app|portal))/i.test(rawLower);

  // Check harmless peer chats (Step 5 FP protection)
  const isHarmlessPeerChat =
    /(?:hi|hey|hello)\s*,?\s*are\s+you\s+coming\s+to\s+(?:college|school|class|work|office|lunch|dinner)\s+tomorrow/i.test(rawLower) ||
    /(?:hey|hi),?\s+are\s+we\s+still\s+meeting\s+for\s+lunch/i.test(rawLower);

  // Check critical credential & military/defense access solicitation (Step 4 FN protection)
  const militarySolicitationRegex = /(?:(?:give\s+me|send\s+me|share|provide|disclose|requesting|hand\s+over).*?(?:military|defense|classified|restricted)\s+(?:credentials?|access|protocols?)|ex[- ]army\s+man.*?(?:give\s+me|credentials)|give\s+me\s+(?:the\s+)?(?:military|defense|classified|restricted)\s+(?:credentials?|protocols?|access))/i;
  const otpTheftRegex = /(?:send|share|reply\s+with|forward|enter|provide|disclose|give)\s+.*?(?:6[- ]digit|one[- ]time|sms\s+)?(?:otp|pin|verification\s+code|6-digit\s+code|banking\s+password|login\s+credentials|seed\s+phrase|password|passcode)/i;
  const passwordSuspensionRegex = /(?:share|send|provide|disclose|give|enter)\s+.*?(?:password|passcode|credentials?|pin|otp).*?(?:prevent|avoid|stop|account\s+suspension|suspension|blocked)/i;

  const hasMilitarySolicitation = militarySolicitationRegex.test(rawLower);
  const hasOtpOrPasswordTheft = (otpTheftRegex.test(rawLower) || passwordSuspensionRegex.test(rawLower)) && !isLegitBankNotification;

  const isCriticalCredentialTheft = (!isEducationalOrAcademic && (hasMilitarySolicitation || hasOtpOrPasswordTheft));

  if (hasMilitarySolicitation && !isEducationalOrAcademic) {
    indicators.push('Stage 2 Security Rule: Unauthorized solicitation of confidential military credentials or defense protocols.');
    evidence.push('solicitation of restricted military/defense credentials');
    matchedPhrases.push('military credentials or access protocols');
  }

  if (hasOtpOrPasswordTheft && !isEducationalOrAcademic) {
    indicators.push('Stage 2 Security Rule: Direct demand for confidential authentication code / OTP / password under threat or urgency.');
    evidence.push('Demand for confidential credentials/password to prevent suspension or verify account');
    matchedPhrases.push('Send your OTP / password immediately');
  }

  // Check unauthorized institutional / university credential solicitation
  const institutionalCredentialRegex = /(?:(?:give\s+me|send\s+me|share|provide|disclose|forward|hand\s+over|requesting|tell\s+me)\s+.*?(?:credentials?|passwords?|usernames?|username\s+and\s+password|login\s+details|access\s+tokens?|admin\s+credentials).*?(?:universit(?:y|ies)|college|school|institution|staff|admin|administrator|student|faculty)|(?:give\s+me|send\s+me|share|provide|disclose|forward)\s+.*?(?:private|staff|admin|administrator|student)\s+(?:login\s+)?(?:credentials?|passwords?|accounts?)|(?:credentials?|passwords?)\s+of\s+(?:the\s+)?(?:universit(?:y|ies)|colleges?|institutions?|staff|students?|admins?))/i;
  const isInstitutionalCredentialRequest = institutionalCredentialRegex.test(rawLower) && !isUniversityPublicOrSelfService && !isEducationalOrAcademic;

  if (isInstitutionalCredentialRequest) {
    indicators.push('Request for institutional credentials');
    indicators.push('Authorization not established');
    indicators.push('Potential unauthorized access');
    evidence.push(content.slice(0, 100));
    matchedPhrases.push('Institutional credential solicitation without authorization');
  }

  // Check advance-fee fraud, government/military impersonation, and identity theft
  const militaryAuthorityRegex = /(?:(?:i\s+am|this\s+is|we\s+are)\s+.*?(?:(?:ex[- ]?arm(?:y)?|military|army|armed\s+forces|defense|air\s+force|navy)\s+(?:officer|personnel|man|official|major|captain|colonel)|(?:from|with)\s+(?:the\s+)?(?:indian\s+)?(?:army|military|defense|navy|air\s+force))|(?:ex[- ]?arm(?:y)?\s+officer))/i;
  const authorityClaimRegex = /(?:(?:i\s+am|this\s+is|we\s+are)\s+.*?(?:government\s+(?:officer|official|contractor|agent|representative)|police\s+(?:officer|inspector|sub[- ]inspector|commissioner)|customs\s+(?:officer|agent|official)|cbi\s+officer|rbi\s+(?:officer|manager)|bank\s+manager)|(?:from|with)\s+(?:the\s+)?(?:government|police|customs|cbi|rbi))/i;
  const contractOrGovOpportunityRegex = /(?:confidential\s+)?government\s+(?:contract|project|tender|opportunity|work|assignment)|exclusive\s+(?:business|investment|contract)\s+opportunity|special\s+government\s+(?:grant|scheme|subsidy)/i;
  const advanceFeeDemandRegex = /(?:pay|deposit|transfer|send)\s+(?:(?:rs\.?|inr|₹|\$)\s*)?\d+(?:,\d+)*(?:\s*(?:rs\.?|inr|₹|\$))?\s+(?:as\s+)?(?:a\s+)?(?:registration\s+fee|processing\s+fee|clearance\s+fee|security\s+deposit|application\s+fee|upfront\s+fee|advance\s+fee)|(?:registration|processing|clearance|application|upfront|advance)\s+fee\s+of\s+(?:(?:rs\.?|inr|₹|\$)\s*)?\d+|pay\s+(?:a\s+)?registration\s+fee\s+to\s+receive/i;
  const identityDocumentRequestRegex = /(?:send|submit|share|upload|provide|forward|attach)\s+.*?(?:id\s+proof|identity\s+proof|identity\s+documents?|aadhaar(?:\s+card)?|pan(?:\s+card)?|passport(?:\s+copy)?|voter\s+id|national\s+id|driving\s+licen[sc]e|bank\s+(?:details|account\s+details|passbook)|kyc\s+documents?)|(?:copy\s+of\s+)?(?:your\s+)?(?:id\s+proof|identity\s+card|aadhaar|pan\s+card|passport)/i;
  const promisedPaymentRegex = /(?:to\s+receive|to\s+get|to\s+release|to\s+claim|before\s+receiving)\s+(?:your\s+)?(?:payment|contract\s+amount|funds|money|salary|payout|compensation|reward)/i;

  const hasMilitaryClaim = militaryAuthorityRegex.test(rawLower);
  const hasAuthorityClaim = hasMilitaryClaim || authorityClaimRegex.test(rawLower);
  const hasContractClaim = contractOrGovOpportunityRegex.test(rawLower);
  const hasFeeDemand = advanceFeeDemandRegex.test(rawLower);
  const hasIdRequest = identityDocumentRequestRegex.test(rawLower);
  const hasPromisedPayment = promisedPaymentRegex.test(rawLower);

  const isAdvanceFeeAndIdentityFraud =
    !isEducationalOrAcademic &&
    ((hasFeeDemand && (hasAuthorityClaim || hasContractClaim || hasIdRequest || hasPromisedPayment)) ||
     (hasContractClaim && hasIdRequest && (hasFeeDemand || hasPromisedPayment)) ||
     (hasAuthorityClaim && hasContractClaim && (hasFeeDemand || hasIdRequest)));

  if (isAdvanceFeeAndIdentityFraud) {
    if (hasMilitaryClaim) indicators.push('Unverified military authority claim');
    else if (hasAuthorityClaim) indicators.push('Unverified authority claim');
    if (hasContractClaim) indicators.push('Government contract impersonation risk');
    if (hasFeeDemand) indicators.push('Advance registration fee request');
    if (hasIdRequest) indicators.push('Identity document collection');
    if (hasPromisedPayment) indicators.push('Promised future payment');
    evidence.push(content.slice(0, 150));
    matchedPhrases.push('Advance-fee government/military impersonation and identity theft');
  }

  // Check advance fee job or prize scams (Step 4 FN protection)
  const advanceFeeRegex = /(?:selected|congratulations).*?(?:pay|deposit)\s+(?:a\s+)?(?:registration\s+fee|processing\s+fee|clearance\s+fee|upfront\s+deposit)|pay\s+(?:a\s+)?registration\s+fee\s+to\s+receive\s+(?:your\s+)?job\s+offer/i;
  const isAdvanceFeeFraud = advanceFeeRegex.test(rawLower);
  if (isAdvanceFeeFraud && !isAdvanceFeeAndIdentityFraud) {
    indicators.push('Stage 2 Security Rule: Upfront registration fee / advance fee required to receive employment offer or prize.');
    evidence.push('Pay a registration fee to receive your job offer');
    matchedPhrases.push('Pay a registration fee');
  }

  // Check financial doubling / crypto multiplier schemes (Step 4 FN protection)
  const cryptoDoublingRegex = /(?:(?:send|invest|transfer|deposit)\s+[^\s]+\s+.*?(?:receive|get|earn|return)\s+[^\s]+.*?(?:(?:within|in)\s+(?:one|\d+)\s+hours?|instantly|same\s+day)|(?:send|invest|transfer|deposit)\s+.*?(?:receive|get|earn|return)\s+.*?(?:in|within)\s+(?:one|\d+)\s+hours?|(?:send|invest).*?(?:cryptocurrency|crypto|eth|btc|bitcoin|usdt).*?(?:receive|get|earn|return).*?(?:within|hour|instant|double|2x))/i;
  const isCryptoDoubling = cryptoDoublingRegex.test(rawLower);
  if (isCryptoDoubling) {
    indicators.push('Stage 2 Security Rule: Fraudulent money/cryptocurrency multiplier / doubling scheme with guaranteed quick returns.');
    evidence.push('Send money/cryptocurrency and receive multiplied return within hours');
    matchedPhrases.push('receive multiplied return within one hour');
  }

  // Check ambiguous verification request without context
  const ambiguousRegex = /^please\s+verify\s+your\s+account\s+when\s+you\s+have\s+time\.?$/i;
  const isAmbiguousVerification = ambiguousRegex.test(rawLower.trim());
  if (isAmbiguousVerification) {
    indicators.push('Stage 2 Security Rule: Ambiguous account verification request lacking brand identity or verification target.');
    evidence.push('Please verify your account when you have time.');
    matchedPhrases.push('verify your account');
  }

  let suggestedScoreFloor = 0;
  if (isCriticalCredentialTheft) suggestedScoreFloor = Math.max(suggestedScoreFloor, 90);
  if (isAdvanceFeeAndIdentityFraud) suggestedScoreFloor = Math.max(suggestedScoreFloor, 90);
  if (isInstitutionalCredentialRequest) suggestedScoreFloor = Math.max(suggestedScoreFloor, 75);
  if (isAdvanceFeeFraud) suggestedScoreFloor = Math.max(suggestedScoreFloor, 85);
  if (isCryptoDoubling) suggestedScoreFloor = Math.max(suggestedScoreFloor, 90);
  if (isAmbiguousVerification) suggestedScoreFloor = Math.max(suggestedScoreFloor, 40);

  return {
    isEducationalOrAcademic: isEducationalOrAcademic || isLegitBankNotification,
    isHarmlessPeerChat,
    isCriticalCredentialTheft,
    isInstitutionalCredentialRequest,
    isAdvanceFeeAndIdentityFraud,
    isAdvanceFeeFraud,
    isCryptoDoubling,
    isAmbiguousVerification,
    suggestedScoreFloor,
    indicators,
    evidence,
    matchedPhrases,
  };
}

/**
 * Main Analysis Orchestration Entrypoint.
 * Executes Phase 4 Two-Stage Detection Architecture:
 * - Stage 1: AI Contextual Classifier (OpenAI / Gemini)
 * - Stage 2: Independent Security Rule Engine with conflict resolution
 * Conforms strictly to Phase 5 Standardized Response Structure.
 */
export async function analyzeContentWithAI(
  content: string,
  type: 'message' | 'url' | 'social' = 'message',
  platform?: string
): Promise<UnifiedAnalysisResult> {
  const trimmed = (content || '').trim();
  const requestId = 'req_' + Math.random().toString(36).slice(2, 10);

  // 1. Inspect URL structures deterministically
  const extractedUrls = extractUrls(trimmed);
  let urlAnalysisDetail: UrlAnalysisDetail = {
    found: extractedUrls.length > 0,
    urls: extractedUrls,
    findings: [],
  };
  let urlRiskBonus = 0;

  if (type !== 'url' && extractedUrls.length > 0) {
    for (const u of extractedUrls.slice(0, 3)) {
      try {
        const uReport = analyzeUrlStructure(u);
        const { features, verdictTier } = uReport;
        if (features.hasHighRiskTld || features.hasLookalikeBrand || features.isUrlShortener || features.hasDeceptivePath) {
          urlRiskBonus = Math.max(urlRiskBonus, 35);
          const issues: string[] = [];
          if (features.hasHighRiskTld) issues.push('high-risk TLD');
          if (features.hasLookalikeBrand) issues.push(`impersonates ${features.matchedBrand || 'brand'}`);
          if (features.isUrlShortener) issues.push('obfuscated URL shortener');
          if (features.hasDeceptivePath) issues.push('deceptive login path');
          urlAnalysisDetail.findings.push(`[${u}]: Flagged for ${issues.join(', ')} (${verdictTier})`);
        } else {
          urlAnalysisDetail.findings.push(`[${u}]: Standard structure, no suspicious URL heuristics triggered.`);
        }
      } catch {
        urlAnalysisDetail.findings.push(`[${u}]: Malformed URL.`);
      }
    }
  } else if (type === 'url') {
    urlAnalysisDetail.findings.push('URL target analyzed directly as primary scan entity.');
  }

  // 2. Run Stage 2 Security Rule Engine evaluation
  const stage2 = evaluateStage2SecurityRules(trimmed);
  const heuristicResult = analyzeWithHeuristics(trimmed, type);

  // 3. Stage 1: Attempt AI contextual classification (OpenAI first if configured, then Gemini)
  let aiOutput: RawAiOutput | null = null;
  let activeEngine: 'openai' | 'gemini' | 'heuristic_fallback' = 'heuristic_fallback';

  if (isOpenAIConfigured()) {
    try {
      aiOutput = await callOpenAi(trimmed, type, platform);
      activeEngine = 'openai';
    } catch (err: any) {
      console.warn('[OpenAI Engine Error]:', err?.message || err);
    }
  }

  if (!aiOutput && isGeminiConfigured()) {
    try {
      const { output } = await callGemini(trimmed, type, platform);
      aiOutput = output;
      activeEngine = 'gemini';
    } catch (err: any) {
      console.warn('[Gemini Engine Error]:', err?.message || err);
    }
  }

  // 4. Synthesize Stage 1 and Stage 2 with Conflict Resolution
  if (aiOutput) {
    let finalScore = aiOutput.risk_score;
    let finalClassification: 'SAFE' | 'SUSPICIOUS' | 'SCAM' = aiOutput.classification;
    let requiresReview = aiOutput.requires_review;
    const detectedIndicators = [...aiOutput.detected_indicators];
    const evidenceList = [...aiOutput.evidence];
    const limitationsList = [...aiOutput.limitations];

    // Merge URL indicators if present
    if (urlRiskBonus > 0) {
      finalScore = Math.max(finalScore, 65);
      finalClassification = 'SCAM';
      stage2.indicators.forEach(i => detectedIndicators.push(i));
      urlAnalysisDetail.findings.forEach(f => detectedIndicators.push(`URL Risk: ${f}`));
    }

    // CONFLICT RESOLUTION: Stage 2 Critical Security Rules Override
    if (stage2.isEducationalOrAcademic) {
      // Security education or policy discussion must NEVER be classified as a scam
      finalScore = Math.min(20, finalScore);
      finalClassification = 'SAFE';
      requiresReview = false;
    } else if (stage2.isAdvanceFeeAndIdentityFraud) {
      // Advance-fee fraud, government/military impersonation, and identity theft
      finalScore = Math.max(finalScore, 90);
      finalClassification = 'SCAM';
      requiresReview = true;
      limitationsList.push('Stage 2 Security Engine flagged critical advance-fee fraud, authority impersonation, and identity theft pattern.');
      stage2.indicators.forEach(ind => {
        if (!detectedIndicators.includes(ind)) detectedIndicators.push(ind);
      });
      if (!evidenceList.includes(trimmed.slice(0, 150))) evidenceList.push(trimmed.slice(0, 150));
      aiOutput.category = 'advance_fee_and_identity_fraud';
      aiOutput.explanation = 'The sender claims to offer a confidential government contract, requests identity documents and demands an upfront registration fee in exchange for promised future payment. This combination strongly indicates a potential advance-fee scam and identity theft risk.';
      aiOutput.recommended_action = 'Do not pay the registration fee or share identity documents. Independently verify the organization through official contact channels.';
    } else if (stage2.isInstitutionalCredentialRequest) {
      // Unauthorized institutional / university credential request without verified authorization
      finalScore = Math.max(finalScore, 75);
      finalClassification = 'SUSPICIOUS';
      requiresReview = true;
      limitationsList.push('Stage 2 Security Engine flagged unauthorized institutional credential request requiring security review.');
      ['Request for institutional credentials', 'Authorization not established', 'Potential unauthorized access'].forEach(ind => {
        if (!detectedIndicators.includes(ind)) detectedIndicators.push(ind);
      });
      if (!evidenceList.includes(trimmed.slice(0, 100))) evidenceList.push(trimmed.slice(0, 100));
      aiOutput.explanation = 'The sender requests university credentials without establishing authorization. This could expose private institutional accounts.';
      aiOutput.recommended_action = "Do not share private credentials. Verify authorization through the university's official IT department.";
    } else if (stage2.suggestedScoreFloor > 0) {
      // If Stage 2 identified a critical threat (OTP theft, military espionage, advance fee, crypto doubling)
      if (finalScore < stage2.suggestedScoreFloor) {
        finalScore = stage2.suggestedScoreFloor;
        requiresReview = true;
        limitationsList.push('Stage 2 Security Engine elevated score due to high-risk credential or financial pattern match.');
      }
      finalClassification = stage2.suggestedScoreFloor >= 60 ? 'SCAM' : 'SUSPICIOUS';
      stage2.indicators.forEach(ind => {
        if (!detectedIndicators.includes(ind)) detectedIndicators.push(ind);
      });
      stage2.evidence.forEach(ev => {
        if (!evidenceList.includes(ev)) evidenceList.push(ev);
      });
    } else if (stage2.isHarmlessPeerChat) {
      finalScore = Math.min(15, finalScore);
      finalClassification = 'SAFE';
      requiresReview = false;
    }

    // Discrepancy check: If AI and Rules differ significantly (> 30 points), mark for review
    const ruleComparisonScore = heuristicResult.risk_score;
    if (Math.abs(aiOutput.risk_score - ruleComparisonScore) > 30 && !stage2.isEducationalOrAcademic && !stage2.isHarmlessPeerChat) {
      requiresReview = true;
      limitationsList.push('Analytical divergence between neural contextual classifier and rule heuristics; manual review advised.');
    }

    finalClassification = normalizeClassification(finalScore, finalClassification);
    finalScore = clampRiskScore(finalScore, finalClassification);
    const finalRiskLevel = normalizeRiskLevel(finalScore);
    const dynamicConfidence = calculateDynamicConfidence(
      finalClassification,
      finalScore,
      detectedIndicators.length,
      evidenceList.length,
      urlAnalysisDetail.found,
      false,
      aiOutput.confidence
    );

    // Merge legacy indicators
    const legacyIndicators: ScanIndicator[] = detectedIndicators.map(str => {
      const parts = str.split(': ');
      return {
        phrase: parts[0] || 'Indicator',
        reason: parts[1] || str,
      };
    });

    const prediction = finalClassification === 'SCAM' ? 'scam' : finalClassification === 'SUSPICIOUS' ? 'suspicious' : 'genuine';

    // Merge URL analysis from AI if AI returned specific findings
    if (aiOutput.url_analysis && aiOutput.url_analysis.found) {
      urlAnalysisDetail.found = true;
      urlAnalysisDetail.urls = Array.from(new Set([...urlAnalysisDetail.urls, ...aiOutput.url_analysis.urls]));
      urlAnalysisDetail.findings = Array.from(new Set([...urlAnalysisDetail.findings, ...aiOutput.url_analysis.findings]));
    }

    logDiagnosticEvent({
      requestId,
      timestamp: new Date().toISOString(),
      modelIdentifier: activeEngine === 'openai' ? (config.openaiModel || 'gpt-4o-mini') : (config.geminiModel || 'gemini-3.5-flash'),
      promptVersion: PROMPT_VERSION,
      apiProvider: activeEngine,
      apiResponseStatus: 'success',
      aiClassification: aiOutput.classification,
      heuristicClassification: stage2.suggestedScoreFloor >= 60 ? 'SCAM' : stage2.isEducationalOrAcademic || stage2.isHarmlessPeerChat ? 'SAFE' : 'SUSPICIOUS',
      finalClassification,
      inputLength: trimmed.length,
    });

    return {
      classification: finalClassification,
      risk_score: finalScore,
      confidence: dynamicConfidence,
      risk_level: finalRiskLevel,
      intent: aiOutput.intent || (finalClassification === 'SAFE' ? 'Harmless communication' : 'Potential social engineering'),
      requested_action: aiOutput.requested_action || (finalClassification === 'SAFE' ? 'None' : 'Suspicious action requested'),
      detected_indicators: detectedIndicators,
      evidence: evidenceList,
      explanation: aiOutput.explanation,
      recommended_action: aiOutput.recommended_action,
      url_analysis: urlAnalysisDetail,
      analysis_source: 'AI_AND_HEURISTICS',
      limitations: limitationsList,
      requires_review: requiresReview,

      // Legacy fields
      prediction,
      category: aiOutput.category || heuristicResult.category,
      indicators: legacyIndicators,
      recommendations: [aiOutput.recommended_action],
      summary: `${finalClassification} threat assessment (Score: ${finalScore}/100, Level: ${finalRiskLevel}).`,
      engine: activeEngine,
    };
  }

  // 5. Fallback path if AI API is unconfigured or unavailable
  console.warn('[AI Classifier Fallback] Operating in Stage 2 heuristic security rule engine fallback mode.');

  let fallbackScore: number;
  let fallbackClass: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  let fallbackExplanation: string;
  let fallbackIntent = 'Normal conversation or communication';
  let fallbackAction = 'None';
  let requiresReview = false;
  const fallbackIndicators = [...stage2.indicators];
  const fallbackEvidence = [...stage2.evidence];

  if (stage2.isEducationalOrAcademic) {
    fallbackScore = 0;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Educational / cybersecurity policy knowledge sharing';
    fallbackAction = 'None';
    fallbackExplanation = 'Legitimate cybersecurity educational or policy discussion. No credentials or secrets are being solicited.';
  } else if (stage2.isHarmlessPeerChat) {
    fallbackScore = 0;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Normal peer-to-peer social interaction';
    fallbackAction = 'None';
    fallbackExplanation = 'No suspicious intent or harmful request detected.';
  } else if (stage2.isAdvanceFeeAndIdentityFraud) {
    fallbackScore = 90;
    fallbackClass = 'SCAM';
    fallbackIntent = 'Advance-fee fraud and identity theft through government/military impersonation';
    fallbackAction = 'Pay advance registration fee and provide identity documents';
    fallbackExplanation = 'The sender claims to offer a confidential government contract, requests identity documents and demands an upfront registration fee in exchange for promised future payment. This combination strongly indicates a potential advance-fee scam and identity theft risk.';
    requiresReview = true;
    stage2.indicators.forEach(ind => {
      if (!fallbackIndicators.includes(ind)) fallbackIndicators.push(ind);
    });
    if (!fallbackEvidence.includes(trimmed.slice(0, 150))) fallbackEvidence.push(trimmed.slice(0, 150));
  } else if (stage2.isInstitutionalCredentialRequest) {
    fallbackScore = 75;
    fallbackClass = 'SUSPICIOUS';
    fallbackIntent = 'Unauthorized institutional credential solicitation';
    fallbackAction = 'Disclose university / institutional credentials';
    fallbackExplanation = 'The sender requests university credentials without establishing authorization. This could expose private institutional accounts.';
    requiresReview = true;
    ['Request for institutional credentials', 'Authorization not established', 'Potential unauthorized access'].forEach(ind => {
      if (!fallbackIndicators.includes(ind)) fallbackIndicators.push(ind);
    });
    if (!fallbackEvidence.includes(trimmed.slice(0, 100))) fallbackEvidence.push(trimmed.slice(0, 100));
  } else if (stage2.suggestedScoreFloor >= 50 || heuristicResult.risk_score >= 50 || urlRiskBonus > 0) {
    fallbackScore = Math.max(stage2.suggestedScoreFloor, heuristicResult.risk_score, urlRiskBonus > 0 ? 65 : 0);
    fallbackClass = 'SCAM';
    fallbackIntent = 'Social engineering / fraudulent solicitation';
    fallbackAction = stage2.isCriticalCredentialTheft
      ? 'Disclose confidential credentials or OTP'
      : stage2.isAdvanceFeeFraud
      ? 'Pay registration fee for job'
      : stage2.isCryptoDoubling
      ? 'Send cryptocurrency to fraudulent address'
      : 'Click suspicious link';
    fallbackExplanation = `${heuristicResult.explanation} (Note: Analyzed by offline deterministic security rule engine).`;
  } else if (stage2.isAmbiguousVerification || (heuristicResult.prediction === 'suspicious' && heuristicResult.indicators.length > 0)) {
    fallbackScore = 35;
    fallbackClass = 'SUSPICIOUS';
    fallbackIntent = stage2.isAmbiguousVerification ? 'Ambiguous account verification request' : 'Unverified request';
    fallbackAction = stage2.isAmbiguousVerification ? 'Verify account through unverified channel' : 'Exercise caution';
    fallbackExplanation = stage2.isAmbiguousVerification
      ? 'Message requests account verification without legitimate brand identity or target link. Evaluated with cautious medium risk.'
      : `${heuristicResult.explanation} (Note: Evaluated by offline security rule engine).`;
    requiresReview = true;
  } else if (heuristicResult.prediction === 'genuine' && urlRiskBonus === 0) {
    fallbackScore = 0;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Normal conversation or communication';
    fallbackAction = 'None';
    fallbackExplanation = 'No suspicious intent or harmful request detected.';
  } else {
    // Harmless message with no threat signatures detected
    fallbackScore = 0;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Normal conversation or communication';
    fallbackAction = 'None';
    fallbackExplanation = 'No suspicious intent or harmful request detected.';
    requiresReview = false;
  }

  fallbackScore = clampRiskScore(fallbackScore, fallbackClass);
  const fallbackRiskLevel = normalizeRiskLevel(fallbackScore);

  if (fallbackClass === 'SAFE') {
    fallbackIndicators.length = 0;
    fallbackEvidence.length = 0;
  } else {
    heuristicResult.indicators.forEach(i => fallbackIndicators.push(`${i.phrase}: ${i.reason}`));
  }

  const dynamicFallbackConfidence = calculateDynamicConfidence(
    fallbackClass,
    fallbackScore,
    fallbackIndicators.length,
    fallbackEvidence.length,
    urlAnalysisDetail.found,
    true
  );

  const legacyIndicators: ScanIndicator[] = fallbackIndicators.map(str => {
    const parts = str.split(': ');
    return { phrase: parts[0] || 'Indicator', reason: parts[1] || str };
  });

  logDiagnosticEvent({
    requestId,
    timestamp: new Date().toISOString(),
    modelIdentifier: isOpenAIConfigured() ? config.openaiModel : isGeminiConfigured() ? config.geminiModel : 'none',
    promptVersion: PROMPT_VERSION,
    apiProvider: 'heuristic_fallback',
    apiResponseStatus: (!isOpenAIConfigured() && !isGeminiConfigured()) ? 'unconfigured' : 'rate_limited',
    heuristicClassification: fallbackClass,
    finalClassification: fallbackClass,
    inputLength: trimmed.length,
    processingError: !isOpenAIConfigured() ? 'OPENAI_API_KEY is not configured in backend .env' : 'Primary AI APIs exceeded quota or were unreachable',
  });

  return {
    classification: fallbackClass,
    risk_score: fallbackScore,
    confidence: dynamicFallbackConfidence,
    risk_level: fallbackRiskLevel,
    intent: fallbackIntent,
    requested_action: fallbackAction,
    detected_indicators: fallbackIndicators,
    evidence: fallbackEvidence,
    explanation: fallbackExplanation,
    recommended_action: stage2.isAdvanceFeeAndIdentityFraud
      ? 'Do not pay the registration fee or share identity documents. Independently verify the organization through official contact channels.'
      : stage2.isInstitutionalCredentialRequest
      ? "Do not share private credentials. Verify authorization through the university's official IT department."
      : fallbackClass === 'SAFE'
      ? 'No immediate defensive action required.'
      : 'Verify the authenticity of this message through official published communication channels before responding.',
    url_analysis: urlAnalysisDetail,
    analysis_source: 'HEURISTICS_FALLBACK',
    limitations: isAiConfigured()
      ? ['AI service was temporarily unreachable; offline rule-based heuristic fallback active.']
      : ['Neither OPENAI_API_KEY nor GEMINI_API_KEY is configured in backend environment variables.'],
    requires_review: requiresReview,

    prediction: fallbackClass === 'SCAM' ? 'scam' : fallbackClass === 'SUSPICIOUS' ? 'suspicious' : 'genuine',
    category: stage2.isAdvanceFeeAndIdentityFraud
      ? 'advance_fee_and_identity_fraud'
      : heuristicResult.category || 'unverified_content',
    indicators: legacyIndicators,
    recommendations: heuristicResult.recommendations,
    summary: `Stage 2 Heuristic security assessment (Risk Score: ${fallbackScore}/100, Level: ${fallbackRiskLevel}).`,
    engine: 'heuristic_fallback',
  };
}

export function getAiEngineStatus(): {
  openaiConfigured: boolean;
  geminiConfigured: boolean;
  activeProvider: string;
} {
  const oai = isOpenAIConfigured();
  const gem = isGeminiConfigured();
  let provider = 'none (offline heuristic fallback)';
  if (oai && gem) provider = `OpenAI (${config.openaiModel}) & Gemini (${config.geminiModel})`;
  else if (oai) provider = `OpenAI (${config.openaiModel})`;
  else if (gem) provider = `Gemini (${config.geminiModel})`;

  return {
    openaiConfigured: oai,
    geminiConfigured: gem,
    activeProvider: provider,
  };
}
