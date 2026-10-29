import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
dotenv.config({ path: path.resolve(process.cwd(), '../.env') });

export const config = {
  port: parseInt(process.env.PORT || '8000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProd: process.env.NODE_ENV === 'production',
  frontendOrigin: process.env.FRONTEND_ORIGIN || 'http://localhost:8080',
  sessionSecret: process.env.SESSION_SECRET || 'scamguard-default-dev-secret-change-in-prod-2026',
  geminiApiKey: process.env.GEMINI_API_KEY || '',
  geminiModel: process.env.GEMINI_MODEL || 'gemini-3.8-flash',
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  openaiModel: process.env.OPENAI_MODEL || 'gpt-4o-mini',
  databasePath: process.env.DATABASE_URL || path.resolve(process.cwd(), 'scamguard.db'),
  adminEmail: process.env.ADMIN_EMAIL || 'admin@scamguard.local',
  adminPassword: process.env.ADMIN_PASSWORD || 'AdminSecurePass2026!',
  adminName: process.env.ADMIN_NAME || 'System Administrator',
};

export function isGeminiConfigured(): boolean {
  return typeof config.geminiApiKey === 'string' && config.geminiApiKey.trim().length > 10;
}

export function isOpenAIConfigured(): boolean {
  return typeof config.openaiApiKey === 'string' && config.openaiApiKey.trim().length > 10;
}

export function isAiConfigured(): boolean {
  return isOpenAIConfigured() || isGeminiConfigured();
}
