const testCases = [
  { id: 1, text: 'hii', expected: 'SAFE' },
  { id: 2, text: 'hello', expected: 'SAFE' },
  { id: 3, text: 'good morning', expected: 'SAFE' },
  { id: 4, text: 'thank you', expected: 'SAFE' },
  { id: 5, text: 'how are you?', expected: 'SAFE' },
  { id: 6, text: 'see you tomorrow', expected: 'SAFE' },
  { id: 7, text: 'are you coming to college?', expected: 'SAFE' },
  { id: 8, text: 'please call me', expected: 'SAFE' },
  { id: 9, text: 'send your OTP immediately to prevent account closure', expected: 'SCAM' },
  { id: 10, text: 'pay a registration fee to receive your job offer', expected: 'SCAM or SUSPICIOUS' },
  { id: 11, text: 'send ₹5,000 and receive ₹10,000 in one hour', expected: 'SCAM' },
  { id: 12, text: 'our cybersecurity class discussed OTP security', expected: 'SAFE' },
  { id: 13, text: 'your bank statement is available in your official banking app', expected: 'SAFE' },
  { id: 14, text: 'share your password to prevent account suspension', expected: 'SCAM' },
];

async function run() {
  console.log('='.repeat(70));
  console.log('SCAMGUARD AI — 14 REQUIRED ACCURACY & FALSE-POSITIVE TESTS');
  console.log('='.repeat(70));

  let passed = 0;
  for (const tc of testCases) {
    try {
      const res = await fetch('http://localhost:8080/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: tc.text }),
      });
      const data = await res.json();
      const a = data.analysis;

      let isMatch = false;
      if (tc.expected.includes('or')) {
        isMatch = tc.expected.includes(a.classification);
      } else {
        isMatch = a.classification === tc.expected;
      }

      if (isMatch) passed++;
      const statusIcon = isMatch ? 'PASS' : 'FAIL';

      console.log(`[Test ${tc.id}] [${statusIcon}] "${tc.text}"`);
      console.log(`  -> Classification: ${a.classification} (Expected: ${tc.expected})`);
      console.log(`  -> Score: ${a.risk_score}/100 | Level: ${a.risk_level} | Conf: ${a.confidence}`);
      console.log(`  -> Intent: ${a.intent}`);
      console.log(`  -> Indicators: ${JSON.stringify(a.detected_indicators)}`);
      console.log(`  -> Explanation: ${a.explanation}`);
      console.log('-'.repeat(70));
    } catch (err) {
      console.error(`[Test ${tc.id}] ERROR:`, err.message);
    }
  }

  console.log(`Summary: ${passed} / ${testCases.length} tests passed.`);
}

run();
