import { describe, it, expect } from 'vitest';
import { analyzeWithHeuristics } from '../src/services/heuristic.js';

describe('Deterministic Heuristic Engine', () => {
  it('identifies urgent phishing messages with OTP harvesting', () => {
    const text = 'URGENT: Your bank account will be suspended within 24 hours. Send the OTP verification code immediately to unlock.';
    const result = analyzeWithHeuristics(text, 'message');

    expect(result.prediction).toBe('scam');
    expect(result.risk_score).toBeGreaterThanOrEqual(50);
    expect(result.engine).toBe('heuristic_fallback');
    expect(result.indicators.length).toBeGreaterThan(0);
    expect(result.indicators.some(i => i.phrase.toLowerCase().includes('otp') || i.phrase.toLowerCase().includes('urgent'))).toBe(true);
  });

  it('identifies crypto doubling schemes', () => {
    const text = 'Send 1 BTC to our giveaway address and receive 2 BTC back guaranteed returns risk free profit.';
    const result = analyzeWithHeuristics(text, 'message');

    expect(result.prediction).toBe('scam');
    expect(result.category).toBe('crypto_scam');
    expect(result.risk_score).toBeGreaterThanOrEqual(60);
  });

  it('classifies benign messages as genuine', () => {
    const text = 'Hi Sarah, are we still meeting tomorrow at 2 PM at the library to review the cybersecurity lecture slides?';
    const result = analyzeWithHeuristics(text, 'message');

    expect(result.prediction).toBe('genuine');
    expect(result.risk_score).toBeLessThan(30);
    expect(result.category).toBe('legitimate');
  });

  it('safely handles empty or whitespace input', () => {
    const result = analyzeWithHeuristics('   ', 'message');
    expect(result.prediction).toBe('genuine');
    expect(result.risk_score).toBe(0);
  });
});
