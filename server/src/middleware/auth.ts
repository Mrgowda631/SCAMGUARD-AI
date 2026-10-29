import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { getDatabase } from '../db/database.js';
import { config } from '../config.js';

export interface UserSession {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'admin';
  createdAt: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: UserSession;
      sessionId?: string;
    }
  }
}

export const SESSION_COOKIE_NAME = 'scamguard_session';
export const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function createSession(userId: string, userAgent?: string, ipAddress?: string): string {
  const db = getDatabase();
  const sessionId = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_DURATION_MS;

  const stmt = db.prepare(`
    INSERT INTO sessions (id, user_id, expires_at, created_at, user_agent, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(sessionId, userId, expiresAt, new Date(now).toISOString(), userAgent || '', ipAddress || '');

  return sessionId;
}

export function destroySession(sessionId: string): void {
  const db = getDatabase();
  const stmt = db.prepare('DELETE FROM sessions WHERE id = ?');
  stmt.run(sessionId);
}

export function destroyAllUserSessions(userId: string): void {
  const db = getDatabase();
  const stmt = db.prepare('DELETE FROM sessions WHERE user_id = ?');
  stmt.run(userId);
}

export function setSessionCookie(res: Response, sessionId: string): void {
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: config.isProd, // true in production (HTTPS)
    sameSite: config.isProd ? 'none' : 'lax', // 'none' allows cross-origin cookies between Netlify and backend
    maxAge: SESSION_DURATION_MS,
    path: '/',
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: config.isProd ? 'none' : 'lax',
    path: '/',
  });
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const sessionId = req.cookies?.[SESSION_COOKIE_NAME] || req.headers['x-session-id'];

  if (!sessionId || typeof sessionId !== 'string') {
    return next();
  }

  try {
    const db = getDatabase();
    const now = Date.now();

    // Query session joined with user
    const stmt = db.prepare(`
      SELECT s.id as session_id, s.expires_at, u.id, u.name, u.email, u.role, u.created_at
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = ?
    `);

    const result = stmt.get(sessionId) as any;

    if (!result) {
      return next();
    }

    if (result.expires_at < now) {
      // Session expired, delete it
      destroySession(sessionId);
      clearSessionCookie(res);
      return next();
    }

    req.sessionId = sessionId;
    req.user = {
      id: result.id,
      name: result.name,
      email: result.email,
      role: result.role,
      createdAt: result.created_at,
    };

    next();
  } catch (err) {
    console.error('Session validation error:', err);
    next();
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required. Please log in to proceed.',
    });
    return;
  }
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required.',
    });
    return;
  }

  if (req.user.role !== 'admin') {
    res.status(403).json({
      success: false,
      error: 'Access denied. Administrator privileges required.',
    });
    return;
  }

  next();
}
