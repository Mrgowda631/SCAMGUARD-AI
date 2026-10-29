import { GoogleGenAI, Type } from '@google/genai';
import { z } from 'zod';
import { config, isGeminiConfigured } from '../config.js';
import { AnalysisResult, analyzeWithHeuristics } from './heuristic.js';

// Schema for validating AI analysis response with flexible coercion
const RawAiResponseSchema = z.object({
  prediction: z.string().default('suspicious'),
  risk_score: z.coerce.number().min(0).max(100).default(50),
  confidence: z.coerce.number().min(0).max(1).default(0.85),
  category: z.string().default('suspicious_activity'),
  indicators: z.array(
    z.object({
      phrase: z.string(),
      reason: z.string(),
    })
  ).default([]),
  explanation: z.string().default('AI threat analysis completed.'),
  recommendations: z.array(z.string()).default([
    'Exercise caution before interacting with this content.',
    'Do not share sensitive credentials or payment information.',
  ]),
  summary: z.string().default('Threat assessment completed.'),
});

let geminiClient: GoogleGenAI | null = null;

function getClient(): GoogleGenAI | null {
  if (!isGeminiConfigured()) {
    return null;
  }
  if (!geminiClient) {
    geminiClient = new GoogleGenAI({ apiKey: config.geminiApiKey });
  }
  return geminiClient;
}

export function getGeminiStatus(): {
  configured: boolean;
  model: string;
  activeEngine: 'gemini' | 'heuristic_fallback';
} {
  const configured = isGeminiConfigured();
  return {
    configured,
    model: config.geminiModel,
    activeEngine: configured ? 'gemini' : 'heuristic_fallback',
  };
}

const SYSTEM_INSTRUCTION = `You are SCAMGUARD AI, an enterprise-grade cybersecurity and social media threat detection intelligence system.
Your mission is to perform deep linguistic, contextual, and forensic threat assessments of submitted content to identify scams, phishing, social engineering, impersonation, credential harvesting, and fraud — while maintaining strict accuracy to avoid false positives on legitimate human messages.

CORE EVALUATION PRINCIPLES:
1. ANALYZE FULL CONTEXT & INTENT:
   - Do NOT classify a message as a scam merely because it contains words like "money", "bank", "urgent", "offer", "payment", or "click".
   - Evaluate the entire communicative intent: Who appears to be communicating? What action are they requesting the recipient to take? Is there deceit, coercion, or risk of loss?
   - Support and correctly identify ordinary human communications:
     * Normal peer-to-peer chats and greetings between friends or family ("Hey, are we still meeting for lunch?", "Can you send me $15 for dinner on Venmo?").
     * College, school, and academic messages (assignments, lecture slides, exam schedules, library due notices).
     * Routine workplace and professional team emails (standup meetings, project specs, Jira maintenance, scheduled downtime).
     * Legitimate informational delivery notifications ("Your Amazon package is out for delivery today with tracking #1234").
     * Legitimate banking alerts and statements ("Your account XX1234 was credited with $200. Avail Bal: $1,500. Never share your OTP with anyone").
       CRITICAL: Messages that explicitly warn the user NOT to share their OTP/PIN are legitimate security notices, NOT phishing attempts!

2. ACCURATE SCAM IDENTIFICATION:
   Detect real-world fraud and social engineering vectors:
   - Credential & OTP theft: Direct requests to disclose or forward OTPs, passwords, PINs, or recovery seed phrases.
   - Deceptive urgency & coercion: Artificial deadlines ("account will be closed in 24 hours"), arrest threats, utility disconnection threats.
   - Institutional or authority impersonation: Fake Meta/Instagram copyright notices, bank fraud departments, IRS/tax police, customs officers.
   - Family emergency impersonation: "Hi mom, my phone broke, I'm at the hospital and need money transferred urgently".
   - Advance-fee & lottery fraud: Unsolicited prize claims requiring upfront fees or taxes.
   - High-yield investment & crypto scams: Guaranteed returns, 100% risk-free profit, doubling crypto giveaways, VIP trading bots.
   - Fake remote jobs & task scams: Liking YouTube/TikTok videos for $300-$800/day, requiring upfront deposit or telegram tasks.
   - Romance & fake parcel scams: Online lover with valuable luggage detained at airport customs requiring customs fee.
   - Technical support scareware: Fake virus alerts prompting calls to 1-800 numbers or AnyDesk/TeamViewer installations.
   - Obfuscated language & links: Spaced-out letters, character substitutions, shortened or raw IP URLs.

3. PREDICTION CLASSIFICATION:
   - "scam": High probability of hostile malicious intent or fraud (risk_score 60-100).
   - "suspicious": Ambiguous, atypical, or unverified claims requiring heightened scrutiny (risk_score 30-59).
   - "genuine": Benign, legitimate communication without threat markers (risk_score 0-29).

4. OUTPUT FORMAT:
   Return strictly valid JSON complying with the requested schema. Provide extracted indicators with concise forensic reasons, realistic confidence, and tailored recommendations.`;

function normalizePrediction(rawPrediction: string, riskScore: number): 'scam' | 'suspicious' | 'genuine' {
  const lower = rawPrediction.toLowerCase().trim();
  if (lower.includes('scam') || lower.includes('phish') || lower.includes('fraud') || lower.includes('malicious')) {
    return 'scam';
  }
  if (lower.includes('suspic') || lower.includes('warn') || lower.includes('caution') || lower.includes('deceptive')) {
    return 'suspicious';
  }
  if (lower.includes('genuin') || lower.includes('benign') || lower.includes('legit') || lower.includes('safe')) {
    return 'genuine';
  }
  if (riskScore >= 60) return 'scam';
  if (riskScore >= 30) return 'suspicious';
  return 'genuine';
}

import { analyzeContentWithAI } from './aiClassifier.js';

export async function analyzeContentWithGemini(
  content: string,
  type: 'message' | 'url' | 'social' = 'message',
  platform?: string
): Promise<AnalysisResult> {
  return analyzeContentWithAI(content, type, platform);
}


