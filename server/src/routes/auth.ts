import { Router, Request, Response } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { getDatabase } from '../db/database.js';
import {
  hashPassword,
  comparePassword,
  createSession,
  destroySession,
  destroyAllUserSessions,
  setSessionCookie,
  clearSessionCookie,
  requireAuth,
} from '../middleware/auth.js';
import { authRateLimiter } from '../middleware/rateLimiter.js';
import { validateStrongPassword } from '../utils/passwordValidator.js';

export const authRouter = Router();

const RegisterSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(64),
  email: z.string().email('Please enter a valid email address').toLowerCase().trim(),
  password: z.string().superRefine((val, ctx) => {
    const check = validateStrongPassword(val);
    if (!check.valid) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: check.error || 'Password does not meet strong security requirements.',
      });
    }
  }),
});

const LoginSchema = z.object({
  email: z.string().email('Please enter a valid email address').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required'),
});

const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string().superRefine((val, ctx) => {
    const check = validateStrongPassword(val);
    if (!check.valid) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: check.error || 'New password does not meet strong security requirements.',
      });
    }
  }),
});

// Register
authRouter.post('/register', authRateLimiter, async (req: Request, res: Response) => {
  const parsed = RegisterSchema.parse(req.body);
  const db = getDatabase();

  // Check if email already registered
  const existingStmt = db.prepare('SELECT id FROM users WHERE email = ?');
  const existing = existingStmt.get(parsed.email);

  if (existing) {
    res.status(409).json({
      success: false,
      error: 'An account with this email address already exists.',
    });
    return;
  }

  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(parsed.password);
  const now = new Date().toISOString();

  // Insert user
  const insertStmt = db.prepare(`
    INSERT INTO users (id, name, email, password_hash, role, created_at, last_login_at)
    VALUES (?, ?, ?, ?, 'user', ?, ?)
  `);
  insertStmt.run(userId, parsed.name, parsed.email, passwordHash, now, now);

  // Create session
  const sessionId = createSession(
    userId,
    req.headers['user-agent'] as string,
    req.ip
  );
  setSessionCookie(res, sessionId);

  // Audit log
  const auditStmt = db.prepare(`
    INSERT INTO audit_logs (id, user_id, action, details, ip_address, timestamp)
    VALUES (?, ?, 'USER_REGISTER', ?, ?, ?)
  `);
  auditStmt.run(crypto.randomUUID(), userId, `Account registered: ${parsed.email}`, req.ip || '', now);

  res.status(201).json({
    success: true,
    message: 'Account registered successfully.',
    sessionId,
    user: {
      id: userId,
      name: parsed.name,
      email: parsed.email,
      role: 'user',
      createdAt: now,
    },
  });
});

// Login
authRouter.post('/login', authRateLimiter, async (req: Request, res: Response) => {
  const parsed = LoginSchema.parse(req.body);

  // Enforce password policy: Reject weak passwords that are only words, only numbers, or lack special characters
  const pwdCheck = validateStrongPassword(parsed.password);
  if (!pwdCheck.valid) {
    res.status(401).json({
      success: false,
      error: 'Weak password rejected: Password must include alphabets (uppercase & lowercase), numbers, and special characters to log in.',
    });
    return;
  }

  const db = getDatabase();

  const userStmt = db.prepare(`
    SELECT id, name, email, password_hash, role, created_at
    FROM users
    WHERE email = ?
  `);
  const user = userStmt.get(parsed.email) as any;

  if (!user) {
    res.status(401).json({
      success: false,
      error: 'Invalid email or password credentials.',
    });
    return;
  }

  const passwordValid = await comparePassword(parsed.password, user.password_hash);
  if (!passwordValid) {
    res.status(401).json({
      success: false,
      error: 'Invalid email or password credentials.',
    });
    return;
  }

  const now = new Date().toISOString();

  // Update last login
  const updateStmt = db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?');
  updateStmt.run(now, user.id);

  // Create session
  const sessionId = createSession(
    user.id,
    req.headers['user-agent'] as string,
    req.ip
  );
  setSessionCookie(res, sessionId);

  // Audit log
  const auditStmt = db.prepare(`
    INSERT INTO audit_logs (id, user_id, action, details, ip_address, timestamp)
    VALUES (?, ?, 'USER_LOGIN', ?, ?, ?)
  `);
  auditStmt.run(crypto.randomUUID(), user.id, `User authenticated: ${user.email}`, req.ip || '', now);

  res.json({
    success: true,
    message: 'Authentication successful.',
    sessionId,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.created_at,
    },
  });
});

// Logout
authRouter.post('/logout', (req: Request, res: Response) => {
  if (req.sessionId) {
    destroySession(req.sessionId);
  }
  clearSessionCookie(res);

  res.json({
    success: true,
    message: 'Logged out successfully.',
  });
});

// Get current user profile
authRouter.get('/me', requireAuth, (req: Request, res: Response) => {
  res.json({
    success: true,
    user: req.user,
  });
});

// Change password
authRouter.post('/change-password', requireAuth, async (req: Request, res: Response) => {
  const parsed = ChangePasswordSchema.parse(req.body);
  const db = getDatabase();

  const userStmt = db.prepare('SELECT password_hash FROM users WHERE id = ?');
  const user = userStmt.get(req.user!.id) as any;

  const validOld = await comparePassword(parsed.currentPassword, user.password_hash);
  if (!validOld) {
    res.status(400).json({
      success: false,
      error: 'Current password provided is incorrect.',
    });
    return;
  }

  const newHash = await hashPassword(parsed.newPassword);
  const updateStmt = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
  updateStmt.run(newHash, req.user!.id);

  // Keep current session, revoke others
  const sessionsStmt = db.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?');
  sessionsStmt.run(req.user!.id, req.sessionId || '');

  res.json({
    success: true,
    message: 'Password updated successfully. Other active sessions were invalidated.',
  });
});

// Get active sessions
authRouter.get('/sessions', requireAuth, (req: Request, res: Response) => {
  const db = getDatabase();
  const stmt = db.prepare(`
    SELECT id, created_at, expires_at, user_agent, ip_address
    FROM sessions
    WHERE user_id = ?
    ORDER BY created_at DESC
  `);
  const sessions = stmt.all(req.user!.id) as any[];

  res.json({
    success: true,
    sessions: sessions.map(s => ({
      id: s.id,
      createdAt: s.created_at,
      expiresAt: s.expires_at,
      userAgent: s.user_agent,
      ipAddress: s.ip_address,
      isCurrent: s.id === req.sessionId,
    })),
  });
});
