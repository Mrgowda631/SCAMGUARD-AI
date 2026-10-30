import { describe, it, expect } from 'vitest';
import { analyzeWithHeuristics } from '../src/services/heuristic.js';
import { analyzeUrl } from '../src/services/urlAnalyzer.js';
import { analyzeContentWithAI } from '../src/services/aiClassifier.js';

describe('SCAMGUARD AI â€” Enhanced Detection Accuracy & Context Verification', () => {
  // ==========================================
  // SECTION 1: BENIGN & LEGITIMATE HUMAN MESSAGES (NO FALSE POSITIVES)
  // ==========================================

  it('1. Correctly classifies casual conversation between friends as genuine', () => {
    const text = "Hey man! Are we still meeting for lunch at Chipotle today around 1 PM? Let me know!";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(30);
  });

  it('2. Correctly classifies ordinary greetings as genuine', () => {
    const text = "Good morning everyone! Hope you have a wonderful and productive week ahead.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(20);
  });

  it('3. Correctly classifies college and educational messages as genuine', () => {
    const text = "Prof. Sharma announced that the Web Security assignment is due this Friday by 5 PM. Don't forget to submit your report via the college portal.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(30);
  });

  it('4. Correctly classifies workplace and IT maintenance communications as genuine', () => {
    const text = "Hi team, please find attached the Q3 financial metrics report. Also, Jira maintenance is scheduled this Saturday from 2 AM to 4 AM. No password change or action is required on your part.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(30);
  });

  it('5. Correctly classifies authentic delivery notifications as genuine', () => {
    const text = "Your Amazon package with tracking #9482910 is out for delivery today. Delivery agent will arrive by 4 PM. No action is required.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(30);
  });

  it('6. Does NOT flag legitimate bank alerts containing security warnings ("Never share your OTP")', () => {
    const text = "Your HDFC Bank account XX4912 has been credited with $500.00 on 17-Oct-2026. Avail Bal: $3,420.00. NEVER share your OTP or PIN with anyone.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(30);
    // Crucial: The warning advising the user NOT to share OTP must not be treated as OTP harvesting!
    expect(res.indicators.some(i => i.reason.includes('Directly asks the recipient to disclose'))).toBe(false);
  });

  it('7. Does NOT flag casual peer-to-peer dinner bill splitting as a scam', () => {
    const text = "Hey, can you send me $15 for the pizza last night on Venmo when you get a chance?";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('genuine');
    expect(res.risk_score).toBeLessThan(30);
  });

  // ==========================================
  // SECTION 2: REAL-WORLD SCAMS DETECTED ACCURATELY (NO FALSE NEGATIVES)
  // ==========================================

  it('8. Flags urgent bank account phishing as scam', () => {
    const text = "URGENT: Your Chase bank account will be suspended within 24 hours due to suspicious activity. Click here to verify your account immediately at http://chase-update.top/login";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.indicators.length).toBeGreaterThan(0);
  });

  it('9. Flags social engineering OTP theft attempts as scam', () => {
    const text = "Hey, I accidentally sent my 6-digit verification code to your phone number. Can you quickly read the code back to me? It's very urgent!";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.indicators.some(i => i.phrase.toLowerCase().includes('code') || i.reason.includes('one-time password'))).toBe(true);
  });

  it('10. Flags "Hi Mum" / family emergency distress impersonation as scam', () => {
    const text = "Hi mom, I lost my phone and broke my card. I am stranded at the hospital using a friend's phone. Please transfer $350 immediately to my friend's UPI so I can pay the emergency doctor.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.category).toBe('impersonation');
  });

  it('11. Flags unsolicited lottery and prize notifications as scam', () => {
    const text = "CONGRATULATIONS! You have won $1,000,000 in the International Apple Lottery! To claim your cash prize, contact agent Smith to pay your customs processing tax.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.category).toBe('advance_fee');
  });

  it('12. Flags crypto doubling giveaways as scam', () => {
    const text = "Official Binance Giveaway: Send 1 ETH to contract address below and receive 2x back instantly! 100% risk-free guaranteed daily returns.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.category).toBe('crypto_scam');
  });

  it('13. Flags task-based remote job recruitment as scam', () => {
    const text = "Hello! We have remote part-time vacancies liking YouTube videos for $300-$800 daily payout. No experience needed. Deposit $50 refundable registration fee on Telegram to start.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.category).toBe('fake_job');
  });

  it('14. Flags romance customs clearance / diplomat box scams as scam', () => {
    const text = "My dearest love, I sent you a consignment box with jewelry and gold from Dubai. The customs officer at the airport is demanding a $600 agent clearance fee to release the valuable parcel. Please help pay!";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
  });

  it('15. Flags electricity power disconnection scams as scam', () => {
    const text = "Dear customer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid electricity bill. Contact our power officer at 9876543210 immediately to pay.";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
  });

  it('16. Detects obfuscated / leetspeak threats as scam', () => {
    const text = "U-R-G-E-N-T: Y0ur acc0unt w!ll be susp3nd3d within 24 hours. C1ick here to v-e-r-i-f-y your p@ssword!";
    const res = analyzeWithHeuristics(text, 'message');
    expect(res.prediction).toBe('scam');
    expect(res.risk_score).toBeGreaterThanOrEqual(60);
  });

  // ==========================================
  // SECTION 3: URL SCANNER ACCURACY
  // ==========================================

  it('17. Accurately identifies authentic GitHub login as No Obvious Threat Detected', async () => {
    const res = await analyzeUrl('https://github.com/login');
    expect(res.features.isWhitelistedReputableDomain).toBe(true);
    expect(res.verdictTier).toBe('No Obvious Threat Detected');
    expect(res.analysis.prediction).toBe('genuine');
    expect(res.analysis.risk_score).toBeLessThan(30);
  }, 35000);

  it('18. Accurately identifies authentic Google Accounts as No Obvious Threat Detected', async () => {
    const res = await analyzeUrl('https://accounts.google.com/signin');
    expect(res.features.isWhitelistedReputableDomain).toBe(true);
    expect(res.verdictTier).toBe('No Obvious Threat Detected');
    expect(res.analysis.prediction).toBe('genuine');
  }, 35000);

  it('19. Accurately flags typosquatted PayPal domain on suspicious TLD as High Risk', async () => {
    const res = await analyzeUrl('https://paypa1-security-verification.xyz/login.php');
    expect(res.features.hasLookalikeBrand).toBe(true);
    expect(res.features.matchedBrand).toBe('paypal');
    expect(res.verdictTier).toBe('High Risk');
    expect(res.analysis.prediction).toBe('scam');
    expect(res.analysis.risk_score).toBeGreaterThanOrEqual(60);
  }, 35000);

  // ==========================================
  // SECTION 4: USER SPECIFICATION 8 BENCHMARK CASES
  // ==========================================
  describe('Requirement 8 Benchmark Scenarios (AI Analysis)', { timeout: 35000 }, () => {
    it('Case A (Harmless): "Hi Ram, are you coming to college tomorrow?" is SAFE', async () => {
      const res = await analyzeContentWithAI('Hi Ram, are you coming to college tomorrow?');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThan(30);
    });

    it('Case B (Phishing): "Your bank account will be blocked. Send your OTP immediately to verify your account." is SCAM', async () => {
      const res = await analyzeContentWithAI('Your bank account will be blocked. Send your OTP immediately to verify your account.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(60);
    });

    it('Case C (Fake job): "Congratulations, you are selected. Pay a registration fee to receive your job offer." is SCAM', async () => {
      const res = await analyzeContentWithAI('Congratulations, you are selected. Pay a registration fee to receive your job offer.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(60);
    });

    it('Case D (Crypto scam): "Send â‚¹5,000 in cryptocurrency and receive â‚¹10,000 within one hour." is SCAM', async () => {
      const res = await analyzeContentWithAI('Send â‚¹5,000 in cryptocurrency and receive â‚¹10,000 within one hour.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(60);
    });

    it('Case E (Suspicious credential request): "I am an ex-army man. Give me the military credentials or access protocols." is SCAM', async () => {
      const res = await analyzeContentWithAI('I am an ex-army man. Give me the military credentials or access protocols.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(60);
    });

    it('Case F (Security discussion): "Our cybersecurity class discussed why military credentials must remain confidential." is SAFE', async () => {
      const res = await analyzeContentWithAI('Our cybersecurity class discussed why military credentials must remain confidential.');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThan(30);
    });

    it('Case G (Ambiguous): "Please verify your account when you have time." is SUSPICIOUS', async () => {
      const res = await analyzeContentWithAI('Please verify your account when you have time.');
      expect(res.classification).toBe('SUSPICIOUS');
      expect(res.risk_score).toBeGreaterThanOrEqual(30);
      expect(res.risk_score).toBeLessThan(60);
    });

    it('Case H (Suspicious link): "Your account has a problem. Verify it using this unfamiliar website." is SCAM or SUSPICIOUS', async () => {
      const res = await analyzeContentWithAI('Your account has a problem. Verify it using this unfamiliar website.');
      expect(['SCAM', 'SUSPICIOUS']).toContain(res.classification);
      expect(res.risk_score).toBeGreaterThanOrEqual(30);
    });

    it('20. Returns all Phase 5 standardized response fields with correct types', async () => {
      const res = await analyzeContentWithAI('Hi Ram, are you coming to college tomorrow?');

      expect(['SAFE', 'SUSPICIOUS', 'SCAM']).toContain(res.classification);
      expect(typeof res.risk_score).toBe('number');
      expect(res.risk_score).toBeGreaterThanOrEqual(0);
      expect(res.risk_score).toBeLessThanOrEqual(100);
      expect(typeof res.confidence).toBe('number');
      expect(typeof res.intent).toBe('string');
      expect(typeof res.requested_action).toBe('string');
      expect(Array.isArray(res.detected_indicators)).toBe(true);
      expect(Array.isArray(res.evidence)).toBe(true);
      expect(typeof res.explanation).toBe('string');
      expect(typeof res.recommended_action).toBe('string');
      expect(typeof res.url_analysis).toBe('object');
      expect(typeof res.url_analysis.found).toBe('boolean');
      expect(Array.isArray(res.url_analysis.urls)).toBe(true);
      expect(Array.isArray(res.url_analysis.findings)).toBe(true);
      expect(['AI_AND_HEURISTICS', 'HEURISTICS_FALLBACK']).toContain(res.analysis_source);
      expect(Array.isArray(res.limitations)).toBe(true);
      expect(typeof res.requires_review).toBe('boolean');
    });

    it('21. Elevates critical defense credential solicitation and sets high risk score', async () => {
      const res = await analyzeContentWithAI('I am an ex-army man. Give me the military credentials or access protocols.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(80);
      expect(res.risk_level).toBe('CRITICAL');
      expect(res.detected_indicators.length).toBeGreaterThan(0);
    });

    it('22. Flags ambiguous requests as SUSPICIOUS with requires_review=true and medium risk', async () => {
      const res = await analyzeContentWithAI('Please verify your account when you have time.');
      expect(res.classification).toBe('SUSPICIOUS');
      expect(res.risk_score).toBeGreaterThanOrEqual(30);
      expect(res.risk_score).toBeLessThan(60);
      expect(res.requires_review).toBe(true);
    });
  });
  // ==========================================
  // SECTION 6: FALSE NEGATIVE & FALSE POSITIVE RIGOROUS AUDIT
  // ==========================================
  describe('Step 4 & 5 Audit: False Negatives and False Positives Verification', { timeout: 35000 }, () => {
    // False Negatives (Must all be SCAM)
    it('FN1: Bank account blocked + OTP demand is SCAM', async () => {
      const res = await analyzeContentWithAI('Your bank account will be blocked. Send your OTP immediately.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(80);
    });

    it('FN2: Registration fee for job offer is SCAM', async () => {
      const res = await analyzeContentWithAI('Pay a registration fee to receive your job offer.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(80);
    });

    it('FN3: Send 5000 receive 10000 in one hour is SCAM', async () => {
      const res = await analyzeContentWithAI('Send ₹5,000 and receive ₹10,000 within one hour.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(80);
    });

    it('FN4: Share banking password to prevent suspension is SCAM', async () => {
      const res = await analyzeContentWithAI('Share your banking password to prevent account suspension.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(80);
    });

    it('FN5: Solicit confidential military credentials and protocols is SCAM', async () => {
      const res = await analyzeContentWithAI('Give me confidential military credentials and restricted access protocols.');
      expect(res.classification).toBe('SCAM');
      expect(res.risk_score).toBeGreaterThanOrEqual(80);
    });

    // False Positives (Must all be SAFE)
    it('FP1: College chat is SAFE', async () => {
      const res = await analyzeContentWithAI('Hi, are you coming to college tomorrow?');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThanOrEqual(25);
    });

    it('FP2: Cybersecurity class discussed OTP protection is SAFE', async () => {
      const res = await analyzeContentWithAI('Our cybersecurity class discussed OTP protection.');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThanOrEqual(25);
    });

    it('FP3: Military credentials must remain confidential is SAFE', async () => {
      const res = await analyzeContentWithAI('Military credentials must remain confidential.');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThanOrEqual(25);
    });

    it('FP4: Monthly bank statement notification is SAFE', async () => {
      const res = await analyzeContentWithAI('Your monthly bank statement is available in your official banking application.');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThanOrEqual(25);
    });

    it('FP5: Cryptocurrency is a digital payment technology is SAFE', async () => {
      const res = await analyzeContentWithAI('Cryptocurrency is a digital payment technology.');
      expect(res.classification).toBe('SAFE');
      expect(res.risk_score).toBeLessThanOrEqual(25);
    });
  });
});
