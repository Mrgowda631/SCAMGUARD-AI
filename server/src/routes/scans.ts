import { Router, Request, Response } from 'express';
import { getDatabase } from '../db/database.js';
import { requireAuth } from '../middleware/auth.js';

export const scansRouter = Router();

// List scans with filters, search, sorting & pagination
scansRouter.get('/', requireAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const userId = req.user!.id;

  const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 10));
  const offset = (page - 1) * limit;

  const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
  const scanType = typeof req.query.scanType === 'string' ? req.query.scanType : 'all';
  const prediction = typeof req.query.prediction === 'string' ? req.query.prediction : 'all';
  const sortBy = req.query.sortBy === 'risk_score' ? 'risk_score' : 'created_at';
  const sortOrder = req.query.sortOrder === 'asc' ? 'ASC' : 'DESC';

  const whereConditions: string[] = ['user_id = ?'];
  const params: any[] = [userId];

  if (search) {
    whereConditions.push('(input_summary LIKE ? OR category LIKE ? OR explanation LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  if (scanType !== 'all') {
    whereConditions.push('scan_type = ?');
    params.push(scanType);
  }

  if (prediction !== 'all') {
    whereConditions.push('prediction = ?');
    params.push(prediction);
  }

  const whereClause = whereConditions.join(' AND ');

  // Get total count
  const countStmt = db.prepare(`SELECT COUNT(*) as total FROM scans WHERE ${whereClause}`);
  const countRow = countStmt.get(...params) as any;
  const total = countRow ? countRow.total : 0;

  // Get paginated scans
  const listStmt = db.prepare(`
    SELECT id,
           scan_type as scanType,
           platform,
           input_summary as inputSummary,
           prediction,
           risk_score as riskScore,
           confidence,
           category,
           engine,
           created_at as createdAt
    FROM scans
    WHERE ${whereClause}
    ORDER BY ${sortBy} ${sortOrder}
    LIMIT ? OFFSET ?
  `);
  const scans = listStmt.all(...params, limit, offset) as any[];

  res.json({
    success: true,
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
    scans,
  });
});

// Get single scan detail
scansRouter.get('/:id', requireAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const scanId = req.params.id;
  const userId = req.user!.id;
  const isAdmin = req.user!.role === 'admin';

  const stmt = db.prepare(`
    SELECT * FROM scans WHERE id = ?
  `);
  const scan = stmt.get(scanId) as any;

  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan record not found.' });
    return;
  }

  // Enforce access control
  if (scan.user_id !== userId && !isAdmin) {
    res.status(403).json({ success: false, error: 'Access denied to this scan record.' });
    return;
  }

  res.json({
    success: true,
    scan: {
      id: scan.id,
      userId: scan.user_id,
      scanType: scan.scan_type,
      platform: scan.platform,
      inputSummary: scan.input_summary,
      inputRaw: scan.input_raw,
      prediction: scan.prediction,
      riskScore: scan.risk_score,
      confidence: scan.confidence,
      category: scan.category,
      indicators: JSON.parse(scan.indicators_json || '[]'),
      explanation: scan.explanation,
      recommendations: JSON.parse(scan.recommendations_json || '[]'),
      engine: scan.engine,
      createdAt: scan.created_at,
    },
  });
});

// Delete a scan
scansRouter.delete('/:id', requireAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const scanId = req.params.id;
  const userId = req.user!.id;
  const isAdmin = req.user!.role === 'admin';

  // Check ownership
  const stmt = db.prepare('SELECT user_id FROM scans WHERE id = ?');
  const scan = stmt.get(scanId) as any;

  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan record not found.' });
    return;
  }

  if (scan.user_id !== userId && !isAdmin) {
    res.status(403).json({ success: false, error: 'Access denied. You cannot delete this record.' });
    return;
  }

  const deleteStmt = db.prepare('DELETE FROM scans WHERE id = ?');
  deleteStmt.run(scanId);

  res.json({
    success: true,
    message: 'Scan record deleted successfully.',
  });
});

// Export scans as JSON
scansRouter.get('/export/json', requireAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const userId = req.user!.id;

  const stmt = db.prepare(`
    SELECT id, scan_type, platform, input_summary, prediction, risk_score, confidence, category, engine, created_at, explanation, indicators_json, recommendations_json
    FROM scans
    WHERE user_id = ?
    ORDER BY created_at DESC
  `);
  const scans = stmt.all(userId) as any[];

  const formatted = scans.map(s => ({
    id: s.id,
    scanType: s.scan_type,
    platform: s.platform,
    inputSummary: s.input_summary,
    prediction: s.prediction,
    riskScore: s.risk_score,
    confidence: s.confidence,
    category: s.category,
    engine: s.engine,
    createdAt: s.created_at,
    explanation: s.explanation,
    indicators: JSON.parse(s.indicators_json || '[]'),
    recommendations: JSON.parse(s.recommendations_json || '[]'),
  }));

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="scamguard-scans-${Date.now()}.json"`);
  res.send(JSON.stringify(formatted, null, 2));
});

// Export scans as CSV
scansRouter.get('/export/csv', requireAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const userId = req.user!.id;

  const stmt = db.prepare(`
    SELECT id, scan_type, platform, input_summary, prediction, risk_score, confidence, category, engine, created_at
    FROM scans
    WHERE user_id = ?
    ORDER BY created_at DESC
  `);
  const scans = stmt.all(userId) as any[];

  const headers = ['ID', 'Scan Type', 'Platform', 'Summary', 'Prediction', 'Risk Score', 'Confidence', 'Category', 'Engine', 'Created At'];
  const rows = scans.map(s => [
    s.id,
    s.scan_type,
    s.platform || 'N/A',
    `"${(s.input_summary || '').replace(/"/g, '""')}"`,
    s.prediction,
    s.risk_score,
    s.confidence,
    s.category,
    s.engine,
    s.created_at,
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="scamguard-scans-${Date.now()}.csv"`);
  res.send(csvContent);
});
