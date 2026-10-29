import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';
import { config } from '../config.js';

let dbInstance: DatabaseSync | null = null;

export function getDatabase(): DatabaseSync {
  if (dbInstance) {
    return dbInstance;
  }

  // Determine path
  let dbPath = config.databasePath;
  if (dbPath.startsWith('file:')) {
    dbPath = dbPath.replace(/^file:/, '');
  }
  let resolvedPath = path.resolve(process.cwd(), dbPath);
  if (!fs.existsSync(resolvedPath)) {
    const serverSubPath = path.resolve(process.cwd(), 'server', dbPath);
    if (fs.existsSync(serverSubPath)) {
      resolvedPath = serverSubPath;
    } else {
      const parentPath = path.resolve(process.cwd(), '..', dbPath);
      if (fs.existsSync(parentPath)) {
        resolvedPath = parentPath;
      }
    }
  }

  // Ensure directory exists
  const dir = path.dirname(resolvedPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  dbInstance = new DatabaseSync(resolvedPath);
  initSchema(dbInstance);
  return dbInstance;
}

export function initSchema(db: DatabaseSync): void {
  // Enable foreign keys, WAL mode for concurrency, and busy timeout
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA busy_timeout = 5000;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL,
      last_login_at TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      user_agent TEXT,
      ip_address TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      scan_type TEXT NOT NULL,
      platform TEXT,
      input_summary TEXT NOT NULL,
      input_raw TEXT NOT NULL,
      prediction TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      confidence REAL NOT NULL,
      category TEXT NOT NULL,
      indicators_json TEXT NOT NULL,
      explanation TEXT NOT NULL,
      recommendations_json TEXT NOT NULL,
      engine TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_prediction ON scans(prediction);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
  `);

  // Ensure standard guest analyst user exists for unauthenticated public scans
  const guestCheck = db.prepare('SELECT id FROM users WHERE id = ?').get('guest-analyst');
  if (!guestCheck) {
    db.prepare(`
      INSERT INTO users (id, name, email, password_hash, role, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      'guest-analyst',
      'Guest Security Analyst',
      'guest@scamguard.local',
      '$2a$12$e8Y6E.rX3hYd2C1P1E7l.eQz5uK1X2Y3Z4A5B6C7D8E9F0G1H2I3J',
      'user',
      new Date().toISOString()
    );
  }
}

export function closeDatabase(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}
