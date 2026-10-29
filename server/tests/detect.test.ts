import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/index.js';
import { getDatabase } from '../src/db/database.js';

describe('Scam Detection & Cross-User Isolation', () => {
  beforeAll(() => {
    getDatabase();
  });

  let user1Cookie: string;
  let user2Cookie: string;
  let user1ScanId: string;

  beforeAll(async () => {
    // Register User 1
    const res1 = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Analyst Alice',
        email: `alice_${Date.now()}@cyber.local`,
        password: 'ScamGuard#Alice2026!',
      });
    user1Cookie = res1.headers['set-cookie'][0];

    // Register User 2
    const res2 = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Analyst Bob',
        email: `bob_${Date.now()}@cyber.local`,
        password: 'ScamGuard#Bob2026!',
      });
    user2Cookie = res2.headers['set-cookie'][0];
  });

  it('allows User 1 to submit content for scam analysis', async () => {
    const res = await request(app)
      .post('/api/detect')
      .set('Cookie', user1Cookie)
      .send({
        content: 'URGENT: Click here to verify your account or it will be suspended.',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.scanId).toBeDefined();
    expect(res.body.analysis).toBeDefined();
    expect(['scam', 'suspicious']).toContain(res.body.analysis.prediction);
    user1ScanId = res.body.scanId;
  });

  it('allows User 1 to read their own scan', async () => {
    const res = await request(app)
      .get(`/api/scans/${user1ScanId}`)
      .set('Cookie', user1Cookie);

    expect(res.status).toBe(200);
    expect(res.body.scan.id).toBe(user1ScanId);
  });

  it('strictly blocks User 2 from viewing User 1 scan record (403 Forbidden)', async () => {
    const res = await request(app)
      .get(`/api/scans/${user1ScanId}`)
      .set('Cookie', user2Cookie);

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  it('strictly blocks User 2 from deleting User 1 scan record (403 Forbidden)', async () => {
    const res = await request(app)
      .delete(`/api/scans/${user1ScanId}`)
      .set('Cookie', user2Cookie);

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  it('exports user scans in CSV format', async () => {
    const res = await request(app)
      .get('/api/scans/export/csv')
      .set('Cookie', user1Cookie);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.text).toContain('Scan Type');
  });

  it('exports user scans in JSON format', async () => {
    const res = await request(app)
      .get('/api/scans/export/json')
      .set('Cookie', user1Cookie);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    const parsed = JSON.parse(res.text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(0);
  });
});
