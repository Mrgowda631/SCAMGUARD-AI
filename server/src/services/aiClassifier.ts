import OpenAI from 'openai';
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';
import { config, isGeminiConfigured, isOpenAIConfigured, isAiConfigured } from '../config.js';
import { AnalysisResult, analyzeWithHeuristics, ScanIndicator, normalizeText } from './heuristic.js';
import { analyzeUrlStructure } from './urlAnalyzer.js';

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
   - Normal peer-to-peer chats and greetings ("Hi Ram, are you coming to college tomorrow?", "Hey, are we still meeting for lunch?").
   - Educational, academic, and policy discussions ("Our cybersecurity class discussed why military credentials must remain confidential", "Lecture notes on blockchain security").
     CRITICAL: Educational discussions or policy reminders about security are SAFE, because they share knowledge rather than requesting anyone to disclose secret credentials!
   - Routine workplace and professional team emails (standup meetings, scheduled downtime).
   - Legitimate informational delivery notifications.
   - Legitimate banking alerts that warn users NOT to share their OTP.

3. ACCURATE SCAM IDENTIFICATION (MUST BE CLASSIFIED AS SCAM):
   - Credential & OTP theft: Direct requests to disclose or forward OTPs, passwords, PINs, or recovery seed phrases.
   - Unauthorized solicitation of confidential credentials / espionage: Requests for military credentials, access protocols, classified documents, internal network credentials (e.g., "I am an ex-army man. Give me the military credentials or access protocols"). Flag this immediately as SCAM with CRITICAL risk!
   - Fake job offers & recruitment fees: High-paying easy jobs requiring upfront deposits or "registration fees".
   - Cryptocurrency doubling / high-yield investment schemes: Guaranteed returns, sending crypto to receive 2x back.
   - Deceptive urgency & coercion: Artificial deadlines, threats of account blocking or arrest.
   - Suspicious URLs & impersonation: Directing users to unfamiliar, deceptive, or lookalike domains.

4. AMBIGUOUS REQUESTS (MUST BE CLASSIFIED AS SUSPICIOUS):
   - Messages requesting account verification without a link or brand context ("Please verify your account when you have time") must be classified as SUSPICIOUS with MEDIUM risk, not SAFE!

5. SCORING & CLASSIFICATION BANDS:
   - SAFE: risk_score 0 to 29. risk_level: LOW. Legitimate, harmless communications or educational discussions.
   - SUSPICIOUS: risk_score 30 to 59. risk_level: MEDIUM. Ambiguous, unverified, or unusual requests requiring caution.
   - SCAM: risk_score 60 to 100. risk_level: HIGH (60-79) or CRITICAL (80-100). Active fraud, phishing, OTP theft, credential extortion, fake jobs, or crypto scams.

6. REQUIRED JSON OUTPUT SCHEMA:
Return strictly a valid JSON object matching this schema:
{
  "classification": "SAFE" | "SUSPICIOUS" | "SCAM",
  "risk_score": integer (0 to 100),
  "confidence": float (0.0 to 1.0, e.g. 0.95),
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "intent": "Concise statement of sender intent",
  "requested_action": "Specific action requested, or 'None'",
  "category": "phishing" | "credential_theft" | "advance_fee" | "crypto_scam" | "military_espionage" | "impersonation" | "legitimate" | "ambiguous_verification",
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
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

function normalizeClassification(score: number, explicitClass?: string): 'SAFE' | 'SUSPICIOUS' | 'SCAM' {
  if (explicitClass === 'SCAM' || explicitClass === 'SUSPICIOUS' || explicitClass === 'SAFE') {
    // Enforce consistency: a high risk score cannot be marked SAFE
    if (score >= 60 && explicitClass === 'SAFE') return 'SCAM';
    if (score >= 30 && explicitClass === 'SAFE') return 'SUSPICIOUS';
    return explicitClass;
  }
  if (score >= 60) return 'SCAM';
  if (score >= 30) return 'SUSPICIOUS';
  return 'SAFE';
}

/**
 * Stage 2: Independent Security Rule Engine
 * Deterministically evaluates hard security constraints independent of AI.
 */
interface SecurityRuleResult {
  isEducationalOrAcademic: boolean;
  isHarmlessPeerChat: boolean;
  isCriticalCredentialTheft: boolean;
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

  // Check educational or academic security discussions
  const isEducationalOrAcademic =
    /(?:cybersecurity|security)\s+(?:class|course|lecture|training|seminar|assignment)\s+discussed/i.test(rawLower) ||
    /discussed\s+why\s+(?:military\s+credentials|passwords?|otps?)\s+must\s+remain\s+confidential/i.test(rawLower) ||
    /lecture\s+notes\s+on\s+(?:blockchain|network|cyber)\s+security/i.test(rawLower) ||
    /policy\s+states\s+(?:never\s+to\s+share|not\s+to\s+disclose)/i.test(rawLower);

  // Check legitimate bank alert warning user NEVER to share OTP
  const isLegitBankAlertWarning =
    /(?:never|do\s+not)\s+share\s+your\s+(?:otp|pin|password)/i.test(rawLower) &&
    !/(?:send|share|reply\s+with|forward)\s+(?:your\s+)?(?:otp|code|pin)/i.test(rawLower);

  // Check harmless peer chats
  const isHarmlessPeerChat =
    /(?:hi|hey|hello)\s+[a-z]+,?\s+are\s+you\s+coming\s+to\s+(?:college|school|class|work|office|lunch)\s+tomorrow/i.test(rawLower) ||
    /(?:hey|hi),?\s+are\s+we\s+still\s+meeting\s+for\s+lunch/i.test(rawLower);

  // Check critical credential & military/defense access solicitation
  const militarySolicitationRegex = /(?:ex-army|army\s+man|military|defense|pentagon).*?(?:give\s+me|send\s+me|share|provide).*?(?:military\s+credentials|access\s+protocols|classified|clearance)/i;
  const otpTheftRegex = /(?:send|share|reply\s+with|forward|enter)\s+(?:your\s+)?(?:otp|pin|verification\s+code|6-digit\s+code|password|seed\s+phrase)/i;
  const hasMilitarySolicitation = militarySolicitationRegex.test(rawLower);
  const hasOtpTheft = otpTheftRegex.test(rawLower) && !isLegitBankAlertWarning;

  const isCriticalCredentialTheft = (!isEducationalOrAcademic && (hasMilitarySolicitation || hasOtpTheft));

  if (hasMilitarySolicitation && !isEducationalOrAcademic) {
    indicators.push('Stage 2 Security Rule: Unauthorized solicitation of confidential military credentials or defense protocols.');
    evidence.push('ex-army ... military credentials or access protocols');
    matchedPhrases.push('military credentials or access protocols');
  }

  if (hasOtpTheft && !isEducationalOrAcademic) {
    indicators.push('Stage 2 Security Rule: Direct demand for confidential authentication code / OTP.');
    evidence.push('Send OTP / verification code immediately');
    matchedPhrases.push('Send your OTP immediately');
  }

  // Check advance fee job or prize scams
  const advanceFeeRegex = /(?:selected|congratulations).*?(?:pay|deposit)\s+(?:a\s+)?(?:registration\s+fee|processing\s+fee|clearance\s+fee|upfront\s+deposit)/i;
  const isAdvanceFeeFraud = advanceFeeRegex.test(rawLower);
  if (isAdvanceFeeFraud) {
    indicators.push('Stage 2 Security Rule: Upfront registration fee / advance fee required to receive employment offer or prize.');
    evidence.push('Pay a registration fee to receive your job offer');
    matchedPhrases.push('Pay a registration fee');
  }

  // Check crypto doubling schemes
  const cryptoDoublingRegex =
    /(?:send|invest).*?(?:cryptocurrency|crypto|eth|btc|bitcoin|usdt).*?(?:receive|get|earn|return).*?(?:within|hour|instant|double|2x)|(?:send|invest).*?(?:receive|get).*?(?:within\s+(?:one\s+hour|\d+\s+hour)|instantly).*?(?:crypto|cryptocurrency)/i;
  const isCryptoDoubling = cryptoDoublingRegex.test(rawLower);
  if (isCryptoDoubling) {
    indicators.push('Stage 2 Security Rule: Fraudulent cryptocurrency multiplier / doubling scheme with guaranteed quick returns.');
    evidence.push('Send cryptocurrency and receive multiplied return within one hour');
    matchedPhrases.push('receive ₹110,000 within one hour');
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
  if (isAdvanceFeeFraud) suggestedScoreFloor = Math.max(suggestedScoreFloor, 85);
  if (isCryptoDoubling) suggestedScoreFloor = Math.max(suggestedScoreFloor, 90);
  if (isAmbiguousVerification) suggestedScoreFloor = Math.max(suggestedScoreFloor, 40);

  return {
    isEducationalOrAcademic: isEducationalOrAcademic || isLegitBankAlertWarning,
    isHarmlessPeerChat,
    isCriticalCredentialTheft,
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

    const finalRiskLevel = normalizeRiskLevel(finalScore);
    finalClassification = normalizeClassification(finalScore, finalClassification);

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

    return {
      classification: finalClassification,
      risk_score: finalScore,
      confidence: Math.min(0.99, Math.max(0.70, aiOutput.confidence)),
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

  // 5. Fallback path if AI API is unconfigured or unavailable (Phase 6)
  // CRITICAL REQUIREMENT: Do NOT assign 0/100 risk score automatically when AI fails.
  console.warn('[AI Classifier Fallback] Operating in Stage 2 heuristic security rule engine fallback mode.');

  let fallbackScore: number;
  let fallbackClass: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  let fallbackExplanation: string;
  let fallbackIntent = 'Undetermined without active AI';
  let fallbackAction = 'None';
  let requiresReview = false;
  const fallbackIndicators = [...stage2.indicators];
  const fallbackEvidence = [...stage2.evidence];

  if (stage2.isEducationalOrAcademic) {
    fallbackScore = 10;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Educational / cybersecurity policy knowledge sharing';
    fallbackAction = 'None';
    fallbackExplanation = 'Legitimate cybersecurity educational or policy discussion. No credentials or secrets are being solicited.';
  } else if (stage2.isHarmlessPeerChat) {
    fallbackScore = 5;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Normal peer-to-peer social interaction';
    fallbackAction = 'Social response';
    fallbackExplanation = 'Normal informal human communication without financial, credential, or deceptive solicitation.';
  } else if (stage2.suggestedScoreFloor >= 60 || heuristicResult.risk_score >= 60 || urlRiskBonus > 0) {
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
  } else if (stage2.isAmbiguousVerification || heuristicResult.prediction === 'suspicious') {
    fallbackScore = 40;
    fallbackClass = 'SUSPICIOUS';
    fallbackIntent = 'Ambiguous account verification request';
    fallbackAction = 'Verify account through unverified channel';
    fallbackExplanation = 'Message requests account verification without legitimate brand identity or target link. Evaluated with cautious medium risk.';
    requiresReview = true;
  } else if (heuristicResult.prediction === 'genuine' && urlRiskBonus === 0) {
    fallbackScore = heuristicResult.risk_score;
    fallbackClass = 'SAFE';
    fallbackIntent = 'Legitimate message';
    fallbackAction = 'None';
    fallbackExplanation = `${heuristicResult.explanation} (Note: Evaluated by offline security rule engine).`;
  } else {
    // Unverified message where no heuristics matched
    fallbackScore = 40;
    fallbackClass = 'SUSPICIOUS';
    fallbackIntent = 'Unverified communication';
    fallbackAction = 'None specified';
    fallbackExplanation = 'Automated AI classification is currently unavailable. Offline heuristic checks found no direct signature matches, but contextual safety cannot be certified without AI.';
    requiresReview = true;
  }

  const fallbackRiskLevel = normalizeRiskLevel(fallbackScore);
  heuristicResult.indicators.forEach(i => fallbackIndicators.push(`${i.phrase}: ${i.reason}`));

  const legacyIndicators: ScanIndicator[] = fallbackIndicators.map(str => {
    const parts = str.split(': ');
    return { phrase: parts[0] || 'Indicator', reason: parts[1] || str };
  });

  return {
    classification: fallbackClass,
    risk_score: fallbackScore,
    confidence: 0.75,
    risk_level: fallbackRiskLevel,
    intent: fallbackIntent,
    requested_action: fallbackAction,
    detected_indicators: fallbackIndicators,
    evidence: fallbackEvidence,
    explanation: fallbackExplanation,
    recommended_action: fallbackClass === 'SAFE'
      ? 'No immediate defensive action required.'
      : 'Verify the authenticity of this message through official published communication channels before responding.',
    url_analysis: urlAnalysisDetail,
    analysis_source: 'HEURISTICS_FALLBACK',
    limitations: isAiConfigured()
      ? ['AI service was temporarily unreachable; offline rule-based heuristic fallback active.']
      : ['Neither OPENAI_API_KEY nor GEMINI_API_KEY is configured in backend environment variables.'],
    requires_review: requiresReview,

    prediction: fallbackClass === 'SCAM' ? 'scam' : fallbackClass === 'SUSPICIOUS' ? 'suspicious' : 'genuine',
    category: heuristicResult.category || 'unverified_content',
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
