import { Router, Request, Response } from 'express';
import { getDatabase } from '../db/database.js';
import { requireAdmin } from '../middleware/auth.js';
import { getGeminiStatus } from '../services/gemini.js';
import { config } from '../config.js';

export const adminRouter = Router();

// Apply requireAdmin middleware to ALL admin routes
adminRouter.use(requireAdmin);

// 1. Overview metrics
adminRouter.get('/overview', (req: Request, res: Response) => {
  const db = getDatabase();

  // User counts
  const userCountStmt = db.prepare('SELECT COUNT(*) as totalUsers FROM users');
  const userCount = (userCountStmt.get() as any)?.totalUsers || 0;

  // Scan counts
  const scanTotalsStmt = db.prepare(`
    SELECT
      COUNT(*) as totalScans,
      SUM(CASE WHEN prediction = 'scam' THEN 1 ELSE 0 END) as totalScams,
      SUM(CASE WHEN prediction = 'suspicious' THEN 1 ELSE 0 END) as totalSuspicious,
      SUM(CASE WHEN prediction = 'genuine' THEN 1 ELSE 0 END) as totalGenuine,
      SUM(CASE WHEN engine = 'gemini' THEN 1 ELSE 0 END) as geminiScans,
      SUM(CASE WHEN engine = 'heuristic_fallback' THEN 1 ELSE 0 END) as heuristicScans
    FROM scans
  `);
  const scanTotals = scanTotalsStmt.get() as any;

  // Active sessions count
  const sessionCountStmt = db.prepare('SELECT COUNT(*) as activeSessions FROM sessions WHERE expires_at > ?');
  const activeSessions = (sessionCountStmt.get(Date.now()) as any)?.activeSessions || 0;

  // Recent system audit logs
  const auditStmt = db.prepare(`
    SELECT id, user_id, action, details, ip_address, timestamp
    FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT 10
  `);
  const recentLogs = auditStmt.all() as any[];

  // Gemini service status
  const geminiStatus = getGeminiStatus();

  res.json({
    success: true,
    telemetry: {
      totalUsers: userCount,
      totalScans: scanTotals?.totalScans || 0,
      totalScams: scanTotals?.totalScams || 0,
      totalSuspicious: scanTotals?.totalSuspicious || 0,
      totalGenuine: scanTotals?.totalGenuine || 0,
      geminiScans: scanTotals?.geminiScans || 0,
      heuristicScans: scanTotals?.heuristicScans || 0,
      activeSessions,
    },
    systemHealth: {
      status: 'operational',
      uptimeSeconds: Math.floor(process.uptime()),
      nodeVersion: process.version,
      environment: config.nodeEnv,
      memoryUsageMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    },
    geminiStatus,
    recentLogs,
  });
});

// 2. User list (strictly without sensitive passwords or tokens)
adminRouter.get('/users', (req: Request, res: Response) => {
  const db = getDatabase();

  const usersStmt = db.prepare(`
    SELECT
      u.id, u.name, u.email, u.role, u.created_at, u.last_login_at,
      COUNT(s.id) as scan_count
    FROM users u
    LEFT JOIN scans s ON u.id = s.user_id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `);
  const users = usersStmt.all() as any[];

  res.json({
    success: true,
    users: users.map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
      createdAt: u.created_at,
      lastLoginAt: u.last_login_at,
      scanCount: u.scan_count || 0,
    })),
  });
});

// 3. System audit logs
adminRouter.get('/audit-logs', (req: Request, res: Response) => {
  const db = getDatabase();

  const auditStmt = db.prepare(`
    SELECT id, user_id, action, details, ip_address, timestamp
    FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT 50
  `);
  const logs = auditStmt.all() as any[];

  res.json({
    success: true,
    logs,
  });
});
