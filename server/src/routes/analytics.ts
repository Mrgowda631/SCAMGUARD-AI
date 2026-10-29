import { Router, Request, Response } from 'express';
import { getDatabase } from '../db/database.js';
import { requireAuth } from '../middleware/auth.js';

export const analyticsRouter = Router();

analyticsRouter.get('/', (req: Request, res: Response) => {
  const db = getDatabase();
  const userId = req.user?.id;
  const whereClause = userId ? 'WHERE user_id = ?' : '';
  const params = userId ? [userId] : [];

  // 1. Overall totals
  const totalsStmt = db.prepare(`
    SELECT
      COUNT(*) as totalScans,
      SUM(CASE WHEN prediction = 'scam' THEN 1 ELSE 0 END) as scamsDetected,
      SUM(CASE WHEN prediction = 'suspicious' THEN 1 ELSE 0 END) as suspiciousContent,
      SUM(CASE WHEN prediction = 'genuine' THEN 1 ELSE 0 END) as genuineContent,
      AVG(risk_score) as avgRiskScore
    FROM scans
    ${whereClause}
  `);
  const totals = (params.length > 0 ? totalsStmt.get(...params) : totalsStmt.get()) as any;

  // 2. Risk Level distribution
  const riskStmt = db.prepare(`
    SELECT
      SUM(CASE WHEN risk_score < 30 THEN 1 ELSE 0 END) as lowRisk,
      SUM(CASE WHEN risk_score >= 30 AND risk_score < 60 THEN 1 ELSE 0 END) as moderateRisk,
      SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as highRisk,
      SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as criticalRisk
    FROM scans
    ${whereClause}
  `);
  const riskDist = (params.length > 0 ? riskStmt.get(...params) : riskStmt.get()) as any;

  // 3. Scan Type breakdown
  const typeStmt = db.prepare(`
    SELECT scan_type, COUNT(*) as count
    FROM scans
    ${whereClause}
    GROUP BY scan_type
  `);
  const typeRows = (params.length > 0 ? typeStmt.all(...params) : typeStmt.all()) as any[];

  // 4. Category breakdown
  const categoryStmt = db.prepare(`
    SELECT category, COUNT(*) as count
    FROM scans
    ${whereClause}
    GROUP BY category
    ORDER BY count DESC
    LIMIT 10
  `);
  const categoryRows = (params.length > 0 ? categoryStmt.all(...params) : categoryStmt.all()) as any[];

  // 5. 7-day scan activity
  // Generate dates for the past 7 days
  const dailyActivity: { date: string; day: string; scans: number; scams: number }[] = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0];
    const dayName = d.toLocaleDateString('en-US', { weekday: 'short' });

    const dayWhere = userId ? 'WHERE user_id = ? AND created_at LIKE ?' : 'WHERE created_at LIKE ?';
    const dayParams = userId ? [userId, `${dateStr}%`] : [`${dateStr}%`];
    const dayStmt = db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN prediction = 'scam' THEN 1 ELSE 0 END) as scamCount
      FROM scans
      ${dayWhere}
    `);
    const dayData = dayStmt.get(...dayParams) as any;

    dailyActivity.push({
      date: dateStr,
      day: dayName,
      scans: dayData?.total || 0,
      scams: dayData?.scamCount || 0,
    });
  }

  // 6. Recent 5 scans
  const recentWhere = userId ? 'WHERE user_id = ?' : '';
  const recentParams = userId ? [userId] : [];
  const recentStmt = db.prepare(`
    SELECT id, scan_type, platform, input_summary, prediction, risk_score, category, engine, created_at
    FROM scans
    ${recentWhere}
    ORDER BY created_at DESC
    LIMIT 5
  `);
  const recentScans = (recentParams.length > 0 ? recentStmt.all(...recentParams) : recentStmt.all()) as any[];

  res.json({
    success: true,
    dataScope: userId ? 'user_scan_history' : 'global_system_telemetry',
    disclaimer: userId
      ? 'Telemetry derived strictly from recorded analyst scans in this account database.'
      : 'Global platform telemetry derived from public forensic threat detections across all analysts.',
    summary: {
      totalScans: totals?.totalScans || 0,
      scamsDetected: totals?.scamsDetected || 0,
      suspiciousContent: totals?.suspiciousContent || 0,
      genuineContent: totals?.genuineContent || 0,
      avgRiskScore: Math.round(totals?.avgRiskScore || 0),
    },
    riskDistribution: [
      { name: 'Low Risk (0-29)', count: riskDist?.lowRisk || 0, color: '#10B981' },
      { name: 'Moderate Risk (30-59)', count: riskDist?.moderateRisk || 0, color: '#F59E0B' },
      { name: 'High Risk (60-79)', count: riskDist?.highRisk || 0, color: '#F97316' },
      { name: 'Critical Risk (80-100)', count: riskDist?.criticalRisk || 0, color: '#EF4444' },
    ],
    typeBreakdown: typeRows.map(r => ({
      type: r.scan_type,
      count: r.count,
    })),
    categoryBreakdown: categoryRows.map(r => ({
      category: r.category,
      count: r.count,
    })),
    dailyActivity,
    recentScans,
  });
});
