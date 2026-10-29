import crypto from 'crypto';
import { getDatabase, closeDatabase } from '../db/database.js';
import { hashPassword } from '../middleware/auth.js';
import { config } from '../config.js';

async function seedAdmin() {
  console.log('--- SCAMGUARD AI Administrator Account Initialization ---');

  const email = (process.env.ADMIN_EMAIL || config.adminEmail).toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD || config.adminPassword;
  const name = process.env.ADMIN_NAME || config.adminName;

  if (!email || !email.includes('@')) {
    console.error('Error: A valid ADMIN_EMAIL must be provided.');
    process.exit(1);
  }

  if (!password || password.length < 8) {
    console.error('Error: ADMIN_PASSWORD must be at least 8 characters.');
    process.exit(1);
  }

  const db = getDatabase();

  // Check if admin user already exists
  const checkStmt = db.prepare('SELECT id, email, role FROM users WHERE email = ?');
  const existing = checkStmt.get(email) as any;

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();

  if (existing) {
    console.log(`User ${email} already exists. Elevating to 'admin' and updating password hash...`);
    const updateStmt = db.prepare(`
      UPDATE users
      SET role = 'admin', password_hash = ?, name = ?
      WHERE id = ?
    `);
    updateStmt.run(passwordHash, name, existing.id);
    console.log(`Successfully updated administrator: ${email}`);
  } else {
    console.log(`Creating new administrator account for: ${email}...`);
    const userId = crypto.randomUUID();
    const insertStmt = db.prepare(`
      INSERT INTO users (id, name, email, password_hash, role, created_at, last_login_at)
      VALUES (?, ?, ?, ?, 'admin', ?, ?)
    `);
    insertStmt.run(userId, name, email, passwordHash, now, now);
    console.log(`Successfully created administrator [${email}] (ID: ${userId})`);
  }

  closeDatabase();
  console.log('Admin account initialization completed successfully.');
}

seedAdmin().catch(err => {
  console.error('Admin seeding failed:', err);
  process.exit(1);
});
