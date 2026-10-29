import { Router, Request, Response } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { getDatabase } from '../db/database.js';
import { requireAuth } from '../middleware/auth.js';
import { detectRateLimiter } from '../middleware/rateLimiter.js';
import { analyzeContentWithAI } from '../services/aiClassifier.js';
import { analyzeUrl, validateSafeUrl } from '../services/urlAnalyzer.js';

export const detectRouter = Router();

// Zod schemas
const ContentScanSchema = z.object({
  content: z.string().min(1, 'Text content is required for analysis').max(10000, 'Content exceeds maximum limit of 10,000 characters'),
  platform: z.string().optional(),
});

const UrlScanSchema = z.object({
  url: z.string().min(1, 'URL is required').max(2048, 'URL length exceeds maximum limit'),
});

const SocialScanSchema = z.object({
  content: z.string().min(1, 'Post/bio/message text is required').max(10000),
  platform: z.enum(['instagram', 'twitter', 'telegram', 'facebook', 'linkedin', 'other']),
});

// Helper to save scan in database
function saveScanRecord(
  userId: string,
  scanType: 'message' | 'url' | 'social',
  inputRaw: string,
  inputSummary: string,
  platform: string | null,
  analysis: any
): string {
  const db = getDatabase();
  const scanId = crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO scans (
      id, user_id, scan_type, platform, input_summary, input_raw,
      prediction, risk_score, confidence, category, indicators_json,
      explanation, recommendations_json, engine, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    scanId,
    userId,
    scanType,
    platform,
    inputSummary.slice(0, 160),
    inputRaw,
    analysis.prediction,
    analysis.risk_score,
    analysis.confidence,
    analysis.category,
    JSON.stringify(analysis.indicators || []),
    analysis.explanation,
    JSON.stringify(analysis.recommendations || []),
    analysis.engine,
    now
  );

  return scanId;
}

// 1. Message & Content Scanner
detectRouter.post('/detect', detectRateLimiter, async (req: Request, res: Response) => {
  const parsed = ContentScanSchema.parse(req.body);
  const trimmed = parsed.content.trim();

  if (trimmed.length === 0) {
    res.status(400).json({
      success: false,
      error: 'Text content cannot be blank or whitespace only.',
    });
    return;
  }

  // Execute AI analysis
  const analysis = await analyzeContentWithAI(trimmed, 'message', parsed.platform);

  // Summary headline
  const summary = trimmed.length > 80 ? trimmed.substring(0, 80) + '...' : trimmed;

  const userId = req.user ? req.user.id : 'guest-analyst';

  // Persist scan
  const scanId = saveScanRecord(
    userId,
    'message',
    trimmed,
    summary,
    parsed.platform || null,
    analysis
  );

  res.json({
    success: true,
    scanId,
    timestamp: new Date().toISOString(),
    analysis,
  });
});

// 2. URL Security Scanner
detectRouter.post('/detect-url', detectRateLimiter, async (req: Request, res: Response) => {
  const parsed = UrlScanSchema.parse(req.body);

  const safeCheck = validateSafeUrl(parsed.url);
  if (!safeCheck.valid) {
    res.status(400).json({
      success: false,
      error: safeCheck.error,
    });
    return;
  }

  // Perform technical & AI URL analysis
  const urlReport = await analyzeUrl(parsed.url);

  const userId = req.user ? req.user.id : 'guest-analyst';

  // Persist scan
  const scanId = saveScanRecord(
    userId,
    'url',
    parsed.url,
    urlReport.url,
    null,
    urlReport.analysis
  );

  res.json({
    success: true,
    scanId,
    timestamp: new Date().toISOString(),
    urlReport,
  });
});

// 3. Social Media Post Analyzer
detectRouter.post('/detect-social', detectRateLimiter, async (req: Request, res: Response) => {
  const parsed = SocialScanSchema.parse(req.body);
  const trimmed = parsed.content.trim();

  // Execute AI analysis with social platform context
  const analysis = await analyzeContentWithAI(trimmed, 'social', parsed.platform);

  // Summary
  const summary = `[${parsed.platform.toUpperCase()}] ${trimmed.substring(0, 70)}...`;

  const userId = req.user ? req.user.id : 'guest-analyst';

  // Persist scan
  const scanId = saveScanRecord(
    userId,
    'social',
    trimmed,
    summary,
    parsed.platform,
    analysis
  );

  res.json({
    success: true,
    scanId,
    platform: parsed.platform,
    timestamp: new Date().toISOString(),
    analysis,
  });
});
