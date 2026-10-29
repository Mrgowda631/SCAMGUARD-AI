import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/index.js';
import { getDatabase } from '../src/db/database.js';

describe('Authentication & Access Control', () => {
  beforeAll(() => {
    getDatabase();
  });

  const testEmail = `analyst_${Date.now()}@test.local`;
  const testPassword = 'ScamGuard#Auth2026!';
  let sessionCookie: string;

  it('registers a new user and sets session cookie', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Test Analyst',
        email: testEmail,
        password: testPassword,
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.user.email).toBe(testEmail);
    expect(res.body.user.role).toBe('user');

    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    expect(cookies[0]).toContain('scamguard_session');
    sessionCookie = cookies[0];
  });

  // Password Security Policy Tests
  it('rejects weak password "Sanjay Kumar" on registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Weak User',
        email: `weak_${Date.now()}@test.local`,
        password: 'Sanjay Kumar',
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('rejects weak password with only numbers on registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Numbers User',
        email: `nums_${Date.now()}@test.local`,
        password: '1234567890',
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('rejects weak password missing special characters on registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'No Special User',
        email: `nospec_${Date.now()}@test.local`,
        password: 'Password1234',
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('rejects weak password "Sanjay Kumar" on login attempt', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: testEmail,
        password: 'Sanjay Kumar',
      });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toContain('Weak password rejected');
  });

  it('rejects duplicate registration with same email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Duplicate',
        email: testEmail,
        password: 'AnotherGuard#Secure2026!',
      });

    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);
  });

  it('authenticates user with valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: testEmail,
        password: testPassword,
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.user.email).toBe(testEmail);
  });

  it('rejects invalid password attempt', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: testEmail,
        password: 'WrongSecret#999!',
      });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  it('accesses /api/auth/me with session cookie', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Cookie', sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(testEmail);
  });

  it('blocks regular user from accessing admin overview (403 Forbidden)', async () => {
    const res = await request(app)
      .get('/api/admin/overview')
      .set('Cookie', sessionCookie);

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  it('denies unauthenticated access to protected scan endpoints (401)', async () => {
    const res = await request(app)
      .get('/api/scans');

    expect(res.status).toBe(401);
  });
});
