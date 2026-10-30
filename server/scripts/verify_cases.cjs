const testCases = [
  { id: 'A', name: 'Harmless', text: 'Hi Ram, are you coming to college tomorrow?' },
  { id: 'B', name: 'Phishing', text: 'Your bank account will be blocked. Send your OTP immediately to verify your account.' },
  { id: 'C', name: 'Fake job', text: 'Congratulations, you are selected. Pay a registration fee to receive your job offer.' },
  { id: 'D', name: 'Crypto scam', text: 'Send ₹5,000 in cryptocurrency and receive ₹10,000 within one hour.' },
  { id: 'E', name: 'Credential request', text: 'I am an ex-army man. Give me the military credentials or access protocols.' },
  { id: 'F', name: 'Security discussion', text: 'Our cybersecurity class discussed why military credentials must remain confidential.' },
  { id: 'G', name: 'Ambiguous', text: 'Please verify your account when you have time.' },
  { id: 'H', name: 'Suspicious link', text: 'Your account has a problem. Verify it using this unfamiliar website: http://security-verify-login.com' }
];

async function run() {
  for (const tc of testCases) {
    try {
      const res = await fetch('http://localhost:8080/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: tc.text })
      });
      const data = await res.json();
      const a = data.analysis;
      console.log(`[Test ${tc.id}] ${tc.name}`);
      console.log(`  Message: "${tc.text}"`);
      console.log(`  Classification: ${a.classification} | Risk Score: ${a.risk_score}/100 | Risk Level: ${a.risk_level} | Confidence: ${a.confidence}`);
      console.log(`  Intent: ${a.intent}`);
      console.log(`  Requested Action: ${a.requested_action}`);
      console.log(`  Indicators: ${JSON.stringify(a.detected_indicators)}`);
      console.log(`  Explanation: ${a.explanation}`);
      console.log(`  Recommended Action: ${a.recommended_action}`);
      console.log(`  URL Analysis: ${JSON.stringify(a.url_analysis)}`);
      console.log(`  Analysis Source: ${a.analysis_source}`);
      console.log('--------------------------------------------------');
    } catch (e) {
      console.error(`[Test ${tc.id}] FAILED:`, e.message);
    }
  }
}
run();
