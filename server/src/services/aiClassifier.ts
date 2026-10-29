import OpenAI from 'openai';
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';
import { config, isGeminiConfigured, isOpenAIConfigured, isAiConfigured } from '../config.js';
import { AnalysisResult, analyzeWithHeuristics, ScanIndicator } from './heuristic.js';
import { analyzeUrlStructure } from './urlAnalyzer.js';

export interface UnifiedAnalysisResult {
  // Required structured fields per specification
  classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  risk_score: number;
  confidence: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detected_indicators: string[];
  explanation: string;
  recommended_action: string;
  url_analysis: string;
  limitations: string;

  // Backward-compatible fields for existing UI components and SQLite storage
  prediction: 'scam' | 'suspicious' | 'genuine';
  category: string;
  indicators: ScanIndicator[];
  recommendations: string[];
  summary: string;
  engine: 'openai' | 'gemini' | 'heuristic_fallback';
}

const StructuredAiSchema = z.object({
  classification: z.enum(['SAFE', 'SUSPICIOUS', 'SCAM']).default('SUSPICIOUS'),
  risk_score: z.coerce.number().min(0).max(100).default(50),
  confidence: z.coerce.number().min(0).max(1).default(0.85),
  risk_level: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
  category: z.string().default('suspicious_activity'),
  detected_indicators: z.array(z.string()).default([]),
  explanation: z.string().default('Cybersecurity threat analysis completed.'),
  recommended_action: z.string().default('Verify the sender through official secondary channels.'),
  url_analysis: z.string().default('No URL detected in the analyzed message.'),
  limitations: z.string().default('Contextual AI analysis is an automated estimate and does not replace official verification.'),
});

type RawAiOutput = z.infer<typeof StructuredAiSchema>;

const SYSTEM_PROMPT = `You are SCAMGUARD AI, an enterprise cybersecurity and social media threat detection intelligence system.
Your mission is to perform deep linguistic, contextual, and forensic threat assessments of submitted content to identify scams, phishing, social engineering, impersonation, credential harvesting, espionage, and fraud — while maintaining strict accuracy to avoid false positives on legitimate human messages.

CORE EVALUATION PRINCIPLES:
1. ANALYZE FULL CONTEXT & INTENT (NOT JUST ISOLATED KEYWORDS):
   - A message mentioning the army, banking, cryptocurrency, OTP, password, or a URL must NOT automatically be classified as a scam.
   - Evaluate communicative intent: Who appears to be communicating? What action are they requesting the recipient to take? Is there deceit, coercion, or risk of loss?
   - Support and correctly identify ordinary human communications:
     * Normal peer-to-peer chats and greetings ("Hi Ram, are you coming to college tomorrow?", "Hey, are we still meeting for lunch?").
     * Educational, academic, and policy discussions ("Our cybersecurity class discussed why military credentials must remain confidential", "Lecture notes on blockchain security").
       CRITICAL: Educational discussions or policy reminders about security are SAFE, because they share knowledge rather than requesting anyone to disclose secret credentials!
     * Routine workplace and professional team emails (standup meetings, scheduled downtime).
     * Legitimate informational delivery notifications.
     * Legitimate banking alerts and statements that warn users NOT to share their OTP.

2. ACCURATE SCAM & THREAT IDENTIFICATION:
   - Credential & OTP theft: Direct requests to disclose or forward OTPs, passwords, PINs, or recovery seed phrases.
   - Unauthorized solicitation of confidential credentials / espionage: Requests for military credentials, access protocols, classified documents, internal network credentials (e.g., "I am an ex-army man. Give me the military credentials or access protocols"). Flag this immediately as SCAM / CRITICAL risk!
   - Fake job offers & recruitment fees: High-paying easy jobs requiring upfront deposits or "registration fees".
   - Cryptocurrency doubling / high-yield investment schemes: Guaranteed returns, sending crypto to receive 2x back.
   - Deceptive urgency & coercion: Artificial deadlines, threats of account blocking or arrest.
   - Suspicious URLs & impersonation: Directing users to unfamiliar, deceptive, or lookalike domains.
   - Ambiguous requests: Messages requesting account verification without a link or brand context ("Please verify your account when you have time") must be classified as SUSPICIOUS with MEDIUM risk, not SAFE!

3. SCORING & CLASSIFICATION BANDS:
   - SAFE: risk_score 0 to 29. risk_level: LOW. Legitimate, harmless communications or educational discussions.
   - SUSPICIOUS: risk_score 30 to 59. risk_level: MEDIUM. Ambiguous, unverified, or unusual requests requiring caution.
   - SCAM: risk_score 60 to 100. risk_level: HIGH (60-79) or CRITICAL (80-100). Active fraud, phishing, OTP theft, credential extortion, fake jobs, or crypto scams.

4. REQUIRED JSON OUTPUT SCHEMA:
Return strictly a valid JSON object with the following fields:
{
  "classification": "SAFE" | "SUSPICIOUS" | "SCAM",
  "risk_score": integer (0 to 100),
  "confidence": float (0.0 to 1.0, e.g. 0.95),
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "category": string (e.g. "phishing", "credential_theft", "fake_job", "crypto_scam", "military_espionage", "legitimate", "ambiguous_verification"),
  "detected_indicators": [array of concise strings explaining exact red flags found, or empty array if safe],
  "explanation": "Clear, concise forensic rationale explaining the findings",
  "recommended_action": "Practical, actionable guidance for the user",
  "url_analysis": "Summary of URL findings if links exist, or 'No URL detected in the analyzed message.'",
  "limitations": "Statement of any analytical uncertainty, e.g. 'Automated analysis cannot verify off-platform physical identity.'"
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

  // Candidate models ordered for reliability and speed (Gemini 3.5-flash / 3.5-flash-lite / 3.8-flash)
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
    // Enforce that a high risk score cannot be marked SAFE
    if (score >= 60 && explicitClass === 'SAFE') return 'SCAM';
    if (score >= 30 && explicitClass === 'SAFE') return 'SUSPICIOUS';
    return explicitClass;
  }
  if (score >= 60) return 'SCAM';
  if (score >= 30) return 'SUSPICIOUS';
  return 'SAFE';
}

/**
 * Main Analysis Orchestration Entrypoint.
 * Combines AI contextual evaluation with deterministic heuristic checks and embedded URL analysis.
 */
export async function analyzeContentWithAI(
  content: string,
  type: 'message' | 'url' | 'social' = 'message',
  platform?: string
): Promise<UnifiedAnalysisResult> {
  const trimmed = (content || '').trim();

  // 1. If not a raw URL scan and content contains URLs, inspect URL structures deterministically
  let urlAnalysisSummary = 'No URL detected in the analyzed message.';
  let urlRiskBonus = 0;
  const urlIndicators: string[] = [];

  if (type !== 'url') {
    const extractedUrls = extractUrls(trimmed);
    if (extractedUrls.length > 0) {
      const findings: string[] = [];
      for (const u of extractedUrls.slice(0, 3)) {
        try {
          const uReport = analyzeUrlStructure(u);
          const { features, verdictTier } = uReport;
          if (features.hasHighRiskTld || features.hasLookalikeBrand || features.isUrlShortener || features.hasDeceptivePath) {
            urlRiskBonus = Math.max(urlRiskBonus, 25);
            const issues: string[] = [];
            if (features.hasHighRiskTld) issues.push('high-risk TLD');
            if (features.hasLookalikeBrand) issues.push(`impersonates ${features.matchedBrand || 'brand'}`);
            if (features.isUrlShortener) issues.push('obfuscated URL shortener');
            if (features.hasDeceptivePath) issues.push('deceptive login path');
            findings.push(`[${u}]: Flagged for ${issues.join(', ')} (${verdictTier})`);
            urlIndicators.push(`Suspicious URL (${u}): ${issues.join(', ')}`);
          } else {
            findings.push(`[${u}]: Standard structure, no known malicious heuristics triggered.`);
          }
        } catch {
          findings.push(`[${u}]: Malformed URL.`);
        }
      }
      urlAnalysisSummary = findings.join(' | ');
    }
  } else {
    urlAnalysisSummary = 'URL target analyzed directly.';
  }

  // 2. Run offline heuristic analysis as complementary ground truth
  const heuristicResult = analyzeWithHeuristics(trimmed, type);

  // 3. Attempt AI classification (OpenAI first if configured, then Gemini)
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

  // 4. Synthesize results
  if (aiOutput) {
    // Combine AI score with URL heuristic bonus if applicable
    let finalScore = Math.min(100, Math.max(0, aiOutput.risk_score + urlRiskBonus));

    // If heuristic caught a verified critical threat (like direct OTP harvesting, military credential solicitation, or extortion) that AI missed, elevate
    const hasCriticalHeuristic =
      heuristicResult.risk_score >= 60 &&
      heuristicResult.indicators.some(i => {
        const r = i.reason.toLowerCase();
        return (
          r.includes('otp') ||
          r.includes('pin') ||
          r.includes('arrest') ||
          r.includes('seed phrase') ||
          r.includes('military') ||
          r.includes('classified') ||
          r.includes('protocol') ||
          r.includes('registration fee') ||
          r.includes('doubling')
        );
      });
    if (hasCriticalHeuristic && finalScore < 75) {
      finalScore = Math.max(finalScore, 85);
    }

    const finalClassification = normalizeClassification(finalScore, aiOutput.classification);
    const finalRiskLevel = normalizeRiskLevel(finalScore);

    // Merge detected indicators without duplicates
    const allIndicatorsSet = new Set<string>();
    aiOutput.detected_indicators.forEach(ind => allIndicatorsSet.add(ind));
    urlIndicators.forEach(ind => allIndicatorsSet.add(ind));
    heuristicResult.indicators.forEach(ind => allIndicatorsSet.add(`${ind.phrase}: ${ind.reason}`));
    const finalDetectedIndicators = Array.from(allIndicatorsSet);

    // Map to ScanIndicator[] for backward compatibility
    const legacyIndicators: ScanIndicator[] = finalDetectedIndicators.map(str => {
      const parts = str.split(': ');
      return {
        phrase: parts[0] || 'Indicator',
        reason: parts[1] || str,
      };
    });

    const prediction = finalClassification === 'SCAM' ? 'scam' : finalClassification === 'SUSPICIOUS' ? 'suspicious' : 'genuine';

    return {
      classification: finalClassification,
      risk_score: finalScore,
      confidence: Math.min(0.99, Math.max(0.65, aiOutput.confidence)),
      risk_level: finalRiskLevel,
      detected_indicators: finalDetectedIndicators,
      explanation: aiOutput.explanation,
      recommended_action: aiOutput.recommended_action,
      url_analysis: urlAnalysisSummary,
      limitations: aiOutput.limitations,

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
  // CRITICAL REQUIREMENT: Do NOT assign 0/100 risk score automatically when AI fails.
  console.warn('[AI Classifier Fallback] Operating in heuristic fallback mode.');

  const heuristicHasThreats = heuristicResult.risk_score > 25 || heuristicResult.indicators.length > 0 || urlRiskBonus > 0;

  let fallbackScore: number;
  let fallbackClass: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  let fallbackExplanation: string;

  if (heuristicHasThreats) {
    fallbackScore = Math.min(100, Math.max(heuristicResult.risk_score, urlRiskBonus));
    fallbackClass = fallbackScore >= 60 ? 'SCAM' : 'SUSPICIOUS';
    fallbackExplanation = `${heuristicResult.explanation} (Note: Offline heuristic rule-matching was used because AI service was unavailable.)`;
  } else {
    // If no heuristic matched and AI failed, assign a cautious moderate score rather than declaring 0/100 safe
    fallbackScore = 40;
    fallbackClass = 'SUSPICIOUS';
    fallbackExplanation = 'Automated AI classification is currently unavailable. Offline heuristic checks found no direct signature matches, but contextual safety cannot be verified without AI.';
  }

  const fallbackRiskLevel = normalizeRiskLevel(fallbackScore);
  const fallbackLegacyIndicators = heuristicResult.indicators;
  const fallbackStringIndicators = fallbackLegacyIndicators.map(i => `${i.phrase}: ${i.reason}`).concat(urlIndicators);

  return {
    classification: fallbackClass,
    risk_score: fallbackScore,
    confidence: 0.70, // Cautious confidence for heuristic fallback
    risk_level: fallbackRiskLevel,
    detected_indicators: fallbackStringIndicators,
    explanation: fallbackExplanation,
    recommended_action: 'Verify the authenticity of this message through official published communication channels.',
    url_analysis: urlAnalysisSummary,
    limitations: isAiConfigured()
      ? 'AI service was temporarily unreachable; offline rule-based heuristic fallback active.'
      : 'Neither OPENAI_API_KEY nor GEMINI_API_KEY is configured in backend environment variables.',

    prediction: fallbackClass === 'SCAM' ? 'scam' : fallbackClass === 'SUSPICIOUS' ? 'suspicious' : 'genuine',
    category: heuristicResult.category || 'unverified_content',
    indicators: fallbackLegacyIndicators,
    recommendations: heuristicResult.recommendations,
    summary: `Heuristic assessment (Risk Score: ${fallbackScore}/100, Level: ${fallbackRiskLevel}).`,
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
