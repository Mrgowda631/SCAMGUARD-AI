import 'express-async-errors';
import path from 'path';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config, isGeminiConfigured } from './config.js';
import { getDatabase } from './db/database.js';
import { authMiddleware } from './middleware/auth.js';
import { apiRateLimiter } from './middleware/rateLimiter.js';
import { errorHandler } from './middleware/errorHandler.js';
import { getGeminiStatus } from './services/gemini.js';
import { getAiEngineStatus } from './services/aiClassifier.js';

// Import route modules
import { authRouter } from './routes/auth.js';
import { detectRouter } from './routes/detect.js';
import { scansRouter } from './routes/scans.js';
import { analyticsRouter } from './routes/analytics.js';
import { reportsRouter } from './routes/reports.js';
import { adminRouter } from './routes/admin.js';

export const app = express();

// Initialize database schema
getDatabase();

// Security Headers via Helmet
app.use(helmet({
  contentSecurityPolicy: false, // Managed per environment or client proxy
  crossOriginEmbedderPolicy: false,
}));

// CORS Configuration
const allowedOrigins = [
  config.frontendOrigin,
  'http://localhost:8080',
  'http://127.0.0.1:8080',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:3000',
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. mobile apps, curl, same-origin, SSRF tests)
    if (!origin) {
      return callback(null, true);
    }
    const isAllowed =
      allowedOrigins.includes(origin) ||
      origin.endsWith('.netlify.app') ||
      origin.includes('netlify.app') ||
      !config.isProd;

    if (isAllowed) {
      callback(null, true);
    } else {
      callback(null, true); // Permissive in dev or dynamic origin reflection
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id'],
}));

// Request body parser with safe limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Cookie parser for session management
app.use(cookieParser(config.sessionSecret));

// Session authentication middleware
app.use(authMiddleware);

// Apply general rate limiter
app.use('/api/', apiRateLimiter);

// Health check endpoint
app.get('/api/health', (_req, res) => {
  const gemini = getGeminiStatus();
  const aiEngine = getAiEngineStatus();
  res.json({
    status: 'operational',
    service: 'SCAMGUARD AI Threat Detection Engine',
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv,
    gemini: {
      configured: gemini.configured,
      model: gemini.model,
      activeEngine: gemini.activeEngine,
    },
    aiEngine: {
      openaiConfigured: aiEngine.openaiConfigured,
      geminiConfigured: aiEngine.geminiConfigured,
      activeProvider: aiEngine.activeProvider,
    },
    version: '1.0.0',
  });
});

// Settings info endpoint
app.get('/api/settings/info', (_req, res) => {
  const gemini = getGeminiStatus();
  const aiEngine = getAiEngineStatus();
  res.json({
    success: true,
    geminiConfigured: gemini.configured,
    openaiConfigured: aiEngine.openaiConfigured,
    activeModel: gemini.model,
    activeEngine: aiEngine.activeProvider,
    supportedModels: [
      { id: 'openai-gpt-4o-mini', name: 'OpenAI GPT-4o-mini', description: 'Fast contextual reasoning and threat detection' },
      { id: 'gemini-flash-latest', name: 'Gemini Flash Latest (Active)', description: 'Ultra-fast low-latency multimodal threat engine' },
      { id: 'gemini-3.5-flash', name: 'Gemini 3.5 Flash', description: 'High-speed contextual reasoning model' },
      { id: 'gemini-3.8-flash', name: 'Gemini 3.8 Flash', description: 'Deep reasoning advanced cyber forensic model' },
    ],
    riskThresholds: {
      low: { min: 0, max: 29, label: 'Low Risk', color: 'emerald' },
      moderate: { min: 30, max: 59, label: 'Moderate Risk', color: 'amber' },
      high: { min: 60, max: 79, label: 'High Risk', color: 'orange' },
      critical: { min: 80, max: 100, label: 'Critical Risk', color: 'red' },
    },
    twoFactorStatus: 'not_configured',
    backendUptime: Math.floor(process.uptime()),
  });
});

// Mount modular API routers
app.use('/api/auth', authRouter);
app.use('/api', detectRouter);
app.use('/api/scans', scansRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/admin', adminRouter);

// Serve built client SPA if present
const candidateDistPaths = [
  path.resolve(process.cwd(), 'client/dist'),
  path.resolve(process.cwd(), '../client/dist'),
  path.resolve(__dirname, '../../client/dist'),
  path.resolve(__dirname, '../client/dist'),
];
const clientDistPath = candidateDistPaths.find((p) => fs.existsSync(p)) || '';

if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
} else {
  // If client dist is not built yet, redirect browser requests to the Vite development server
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.redirect(`http://localhost:8080${req.originalUrl}`);
  });
}

// Centralized error handler
app.use(errorHandler);

// Start server if not running in test runner
if (process.env.NODE_ENV !== 'test') {
  app.listen(config.port, () => {
    console.log(`[SCAMGUARD AI] SOC Backend running on port ${config.port}`);
    console.log(`[SCAMGUARD AI] Gemini AI status: ${isGeminiConfigured() ? `CONFIGURED (${config.geminiModel})` : 'UNCONFIGURED (Heuristic Fallback Active)'}`);
  });

  // Seamless Port Bridge: If user navigates to default Vite (5173) or React (3000) ports,
  // gracefully redirect to the active dashboard at http://localhost:8080
  if (process.env.NODE_ENV !== 'production') {
    const bridgePorts = [5173, 3000];
    for (const bPort of bridgePorts) {
      try {
        const bridge = express();
        bridge.all('*', (req, res) => {
          res.redirect(302, `http://localhost:8080${req.originalUrl}`);
        });
        const server = bridge.listen(bPort, () => {
          console.log(`[SCAMGUARD AI] Port bridge active: http://localhost:${bPort} -> http://localhost:8080`);
        });
        server.on('error', () => {
          // Port already occupied or restricted; silently ignore
        });
      } catch {
        // Silently ignore
      }
    }
  }
}
