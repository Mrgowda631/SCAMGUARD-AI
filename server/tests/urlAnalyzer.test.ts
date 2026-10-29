import { describe, it, expect } from 'vitest';
import { validateSafeUrl, analyzeUrl } from '../src/services/urlAnalyzer.js';

describe('URL Security Scanner & SSRF Guard', { timeout: 35000 }, () => {
  it('blocks loopback and localhost SSRF attempts', () => {
    const localhost = validateSafeUrl('http://localhost:8000/admin');
    expect(localhost.valid).toBe(false);
    expect(localhost.error).toContain('private, local, or loopback');

    const loopback = validateSafeUrl('http://127.0.0.1:3000');
    expect(loopback.valid).toBe(false);
  });

  it('blocks private network RFC 1918 subnets', () => {
    const res1 = validateSafeUrl('http://192.168.1.1/router-login');
    expect(res1.valid).toBe(false);

    const res2 = validateSafeUrl('https://10.0.0.5/api');
    expect(res2.valid).toBe(false);

    const res3 = validateSafeUrl('http://172.16.0.1');
    expect(res3.valid).toBe(false);
  });

  it('rejects unsafe protocols like file: and javascript:', () => {
    const fileProto = validateSafeUrl('file:///etc/passwd');
    expect(fileProto.valid).toBe(false);

    const jsProto = validateSafeUrl('javascript:alert(1)');
    expect(jsProto.valid).toBe(false);
  });

  it('detects brand lookalike typosquatting', async () => {
    const result = await analyzeUrl('https://paypa1-security-verification.xyz/login.php');
    expect(result.features.hasLookalikeBrand).toBe(true);
    expect(result.features.matchedBrand).toBe('paypal');
    expect(result.features.hasHighRiskTld).toBe(true);
    expect(result.features.hasDeceptivePath).toBe(true);
    expect(result.verdictTier).toBe('High Risk');
    expect(result.availableChecks.some(c => c.name.includes('SSRF') && c.status === 'passed')).toBe(true);
    expect(result.unavailableChecks.some(c => c.name.includes('Crawler') && c.status === 'unavailable')).toBe(true);
  });

  it('safely normalizes URLs provided without http/https protocol prefix', async () => {
    const norm = validateSafeUrl('github.com/security');
    expect(norm.valid).toBe(true);
    expect(norm.parsedUrl?.protocol).toBe('https:');
    expect(norm.parsedUrl?.hostname).toBe('github.com');
  });

  it('detects punycode homograph attack indicators', async () => {
    const result = await analyzeUrl('https://xn--pple-43d.com/login');
    expect(result.features.hasPunycode).toBe(true);
    expect(result.availableChecks.some(c => c.name.includes('Punycode') && c.status === 'flagged')).toBe(true);
  });

  it('detects non-standard web ports', async () => {
    const result = await analyzeUrl('http://phishing-domain.com:8443/auth');
    expect(result.features.hasUnusualPort).toBe(true);
    expect(result.parsed.port).toBe('8443');
    expect(result.availableChecks.some(c => c.name.includes('Port') && c.status === 'flagged')).toBe(true);
  });

  it('detects known URL shorteners', async () => {
    const result = await analyzeUrl('https://bit.ly/3xY7zq');
    expect(result.features.isUrlShortener).toBe(true);
    expect(result.availableChecks.some(c => c.name.includes('Shortener') && c.status === 'flagged')).toBe(true);
  });

  it('classifies benign standard URLs as No Obvious Threat Detected with defensive disclaimer', async () => {
    const result = await analyzeUrl('https://www.github.com/features');
    expect(result.verdictTier).toBe('No Obvious Threat Detected');
    expect(result.disclaimer).toContain('cannot guarantee complete safety');
  });
});

