import React, { useState } from 'react';
import {
  BookOpen,
  ShieldAlert,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Award,
  RotateCcw,
} from 'lucide-react';

interface ScamTopic {
  id: string;
  title: string;
  badge: string;
  overview: string;
  howItWorks: string;
  warningSigns: string[];
  example: string;
  prevention: string[];
  recoverySteps: string[];
}

export const AwarenessHub: React.FC = () => {
  const [expandedTopic, setExpandedTopic] = useState<string | null>('phishing');

  // Interactive Quiz State
  const [selectedAnswers, setSelectedAnswers] = useState<Record<number, number>>({});
  const [submittedQuiz, setSubmittedQuiz] = useState(false);

  const topics: ScamTopic[] = [
    {
      id: 'phishing',
      title: 'Phishing & Smishing (SMS Phishing)',
      badge: 'High Frequency',
      overview: 'Deceptive emails and SMS messages engineered to look like trusted banks, postal services, or cloud providers.',
      howItWorks: 'Attackers create lookalike login pages and send high-urgency notifications claiming an account is suspended or a package is on hold.',
      warningSigns: [
        'Generic greetings or urgent deadlines ("within 24 hours")',
        'Unusual senders with altered domains (e.g. support@chase-alert-notice.com)',
        'Direct requests to input passwords, OTPs, or credit card numbers',
        'Suspicious shortened links (e.g. bit.ly, tinyurl) or high-risk TLDs (.xyz, .top)',
      ],
      example: '"USPS ALERT: Package #US98218 cannot be delivered due to missing house number. Update your address & pay $1.50 redelivery fee at https://usps-redelivery-tracking.top within 12 hours."',
      prevention: [
        'Never click links in unexpected SMS messages or emails.',
        'Navigate directly to official apps or bookmarked portals in your browser.',
        'Enable multi-factor authentication (MFA/2FA) utilizing authenticator apps or security keys.',
      ],
      recoverySteps: [
        'Immediately change passwords for any compromised accounts from a clean device.',
        'Contact your bank or card issuer to freeze impacted accounts or dispute unauthorized charges.',
        'Report the phishing URL to Google Safe Browsing and your national cyber crime portal.',
      ],
    },
    {
      id: 'crypto',
      title: 'Cryptocurrency & Investment Fraud',
      badge: 'Critical Financial Impact',
      overview: 'Fraudulent investment schemes promising guaranteed high returns, fake token airdrops, and doubled deposits.',
      howItWorks: 'Scammers advertise automated trading bots, fake liquidity mining pools, or impersonate influential figures promising 2x-5x returns on deposited crypto assets.',
      warningSigns: [
        'Promises of "guaranteed profit" or "100% risk-free daily returns"',
        'Requests to deposit crypto to a personal wallet address or non-custodial contract',
        'Unsolicited DMs on Telegram, Discord, or X offering insider investment tips',
        'Inability to withdraw funds without paying exorbitant "withdrawal tax" or "gas fees"',
      ],
      example: '"Send 0.5 BTC to Vitalik Buterin\'s promotional contract address and receive 1.0 BTC back immediately to celebrate the Ethereum upgrade."',
      prevention: [
        'Remember that in legitimate finance, there is no such thing as guaranteed high profit without risk.',
        'Never send digital assets to unknown wallet addresses.',
        'Verify legitimate crypto platforms through reputable trackers (CoinMarketCap, CoinGecko).',
      ],
      recoverySteps: [
        'Disconnect your Web3 wallet from any suspicious dApps immediately.',
        'Transfer any remaining assets to a newly generated cold storage or hardware wallet.',
        'File an IC3 (FBI) or national cyber fraud report with transaction hashes and wallet addresses.',
      ],
    },
    {
      id: 'fake-jobs',
      title: 'Fake Jobs & Recruitment Scams',
      badge: 'Targeting Students & Jobseekers',
      overview: 'Fabricated remote employment offers designed to steal upfront registration fees or recruit victims as money mules.',
      howItWorks: 'Victims are contacted via WhatsApp or Telegram offering high pay for minimal work (e.g., liking YouTube videos or optimizing hotel ratings). After small payouts, victims are tricked into depositing thousands.',
      warningSigns: [
        'Unrealistic compensation (e.g. $500/day for 1 hour of copying text)',
        'Interviews conducted entirely through encrypted messaging apps without face-to-face contact',
        'Demands for payment for "work equipment", "starter training materials", or "security deposits"',
        'Company uses free generic email addresses (@gmail.com instead of corporate domain)',
      ],
      example: '"Hi! I am recruiter from Adecco Group. We offer remote task jobs paying $80/hour. Just like 10 TikTok videos daily. Deposit $50 starter balance to activate your task dashboard."',
      prevention: [
        'Research the recruiting company independently through LinkedIn and official websites.',
        'Legitimate employers will never ask an applicant to pay fees for employment.',
        'Verify the recruiter identity by emailing the official HR department.',
      ],
      recoverySteps: [
        'Cease all communications and do not transfer further funds.',
        'Notify your banking institution if bank or debit card details were provided.',
        'Block the recruiter across messaging channels.',
      ],
    },
    {
      id: 'impersonation',
      title: 'Impersonation & Account Takeover',
      badge: 'Identity Theft',
      overview: 'Attackers impersonating Instagram, Meta, Apple, or Google support personnel to hijack social media and cloud accounts.',
      howItWorks: 'The attacker sends a warning that your account has violated copyright policies or is eligible for verification, directing you to enter your credentials or forward verification codes.',
      warningSigns: [
        'DMs from unverified profiles claiming to be "Official Support Team"',
        'Friends asking you to receive a "voting link" or forward a 6-digit SMS code',
        'Urgent threats of permanent profile suspension within 24 hours',
        'Requests to alter your profile email to an attacker-controlled address',
      ],
      example: '"Instagram Help Team: Your post violates copyright law. If you do not verify ownership at https://instagram-appeal-team.xyz within 24h, your account will be permanently terminated."',
      prevention: [
        'Platform security teams will never DM you on their own platform asking for passwords or OTPs.',
        'Check legitimate notifications directly inside the app settings (e.g. Settings > Security > Emails from Instagram).',
        'Never forward one-time SMS verification codes to anyone, including family members.',
      ],
      recoverySteps: [
        'Use the official platform account recovery flow (e.g. instagram.com/hacked).',
        'Revoke unauthorized sessions and third-party app permissions.',
        'Warn your contacts via alternate channels that your account was compromised.',
      ],
    },
    {
      id: 'romance',
      title: 'Romance & Emotional Manipulation',
      badge: 'High Psychological Coercion',
      overview: 'Cybercriminals cultivating artificial romantic relationships over weeks or months to manipulate victims into sending money.',
      howItWorks: 'Profiles on dating platforms or Instagram build emotional trust, claim to be working overseas (military, oil rig, doctor), and invent medical or customs crises requiring financial assistance.',
      warningSigns: [
        'Refusal to meet in person or participate in live video calls due to "camera issues"',
        'Proclamation of intense love and commitment very early in communication',
        'Sudden emergency requiring financial aid (medical surgery, customs clearance fee, travel ticket)',
        'Requests for payment via cryptocurrency, Western Union, or prepaid gift cards',
      ],
      example: '"My love, my deployment ends next week, but my equipment is held at customs and they require a $1,200 clearance fee. If you send it via Apple gift card, I will be with you tomorrow."',
      prevention: [
        'Perform reverse image searches on profile pictures using Google Lens.',
        'Never send money or financial gifts to someone you have only communicated with online.',
        'Consult trusted friends or family members when an online acquaintance requests money.',
      ],
      recoverySteps: [
        'Cut off all communication immediately; do not let the scammer manipulate you further.',
        'Collect chat logs, profile screenshots, and payment receipts.',
        'File an official report with cyber crime law enforcement.',
      ],
    },
    {
      id: 'tech-support',
      title: 'Tech-Support & Remote Access Scams',
      badge: 'Malware / System Takeover',
      overview: 'Fabricated browser popups and phone calls claiming your computer is infected with viruses or compromised by hackers.',
      howItWorks: 'Loud browser alerts with flashing sirens display toll-free numbers. Scammers convince victims to install remote desktop tools (AnyDesk, TeamViewer) and take over banking sessions.',
      warningSigns: [
        'Full-screen browser warnings claiming "VIRUS DETECTED: Call Microsoft Support Now"',
        'Unsolicited calls from "Windows Helpdesk" claiming your IP is transmitting errors',
        'Pressure to download remote control utilities like AnyDesk, UltraViewer, or TeamViewer',
        'Demand for hundreds of dollars for lifetime anti-virus warranties',
      ],
      example: '"CRITICAL ALERT: Windows Defender has detected Trojan Spyware. Access to this PC has been blocked. Call Certified Microsoft Technician at 1-800-555-0144 immediately."',
      prevention: [
        'Legitimate tech companies (Microsoft, Apple, Google) never display phone numbers in popups or call unprompted.',
        'If a webpage locks your screen, close the browser tab using Task Manager (Ctrl + Shift + Esc).',
        'Never permit remote desktop access to unsolicited callers.',
      ],
      recoverySteps: [
        'Disconnect the computer from Wi-Fi or unplug the Ethernet cable immediately.',
        'Uninstall any remote access software installed during the call.',
        'Change all banking and email passwords from an unaffected device.',
      ],
    },
    {
      id: 'fake-shopping',
      title: 'Fake Shopping & Payment Requests',
      badge: 'E-commerce Fraud',
      overview: 'Fraudulent storefronts offering luxury goods, electronics, or trending products at 80% discounts.',
      howItWorks: 'Scammers advertise heavily on Facebook and Instagram with stolen product photos. Once paid, no item is delivered, or counterfeit low-value items are sent while credit card data is stolen.',
      warningSigns: [
        'Prices that are unrealistically low (e.g. brand new PS5 or iPhone 16 for $99)',
        'Domain registered only days or weeks ago with no customer reviews on Trustpilot',
        'Only payment method accepted is Zelle, Venmo, Wire Transfer, or Crypto',
        'Missing physical contact address, customer service phone, or legitimate refund policy',
      ],
      example: '"GOING OUT OF BUSINESS SALE: All Dyson vacuums and luxury handbags 90% off today only! Pay with Zelle for free express shipping."',
      prevention: [
        'Shop only through verified retailers with established reputations.',
        'Check domain registration date using WHOIS lookup tools.',
        'Always pay with credit cards that offer buyer protection and chargeback guarantees.',
      ],
      recoverySteps: [
        'Contact your credit card issuer immediately to report unauthorized transaction and request chargeback.',
        'Monitor credit reports and consider placing a fraud alert on your credit file.',
      ],
    },
    {
      id: 'otp-theft',
      title: 'OTP, Credential & Identity Theft',
      badge: 'Critical Account Breach',
      overview: 'Tactics designed to trick victims into handing over one-time passwords, 2FA codes, and government IDs.',
      howItWorks: 'Scammers call pretending to be your bank fraud team. While talking, they trigger a password reset on your bank and ask you to "read the verification code to cancel the charge."',
      warningSigns: [
        'Caller claiming: "We sent an OTP to cancel the fraud; please read it to me."',
        'The SMS message explicitly states: "Do NOT share this code with anyone, including bank representatives."',
        'Caller creates extreme urgency and tells you not to hang up or check your online banking.',
      ],
      example: '"Hello, this is Bank Fraud Prevention. We see a $900 transfer attempt. We just sent a 6-digit cancellation OTP to your phone. Please read it to me so I can reverse the transfer."',
      prevention: [
        'Remember the Golden Rule: OTPs are NEVER shared with anyone. Banks never ask for your OTP over phone.',
        'If suspicious, hang up immediately and call the official phone number printed on the back of your debit card.',
      ],
      recoverySteps: [
        'Call your bank fraud department immediately using the number on your card.',
        'Instruct them to freeze all digital banking access, cards, and outgoing transfers.',
        'File an identity theft affidavit with local authorities.',
      ],
    },
  ];

  const goldenRules = [
    {
      number: '01',
      title: 'Stop & Verify Before You Click',
      desc: 'Never click links in unexpected emails, text messages, or direct messages. Type official website URLs directly into your browser address bar.',
    },
    {
      number: '02',
      title: 'OTPs & Passwords Are Confidentially Yours',
      desc: 'Legitimate banks, government agencies, and tech companies will NEVER ask for your one-time passwords, PINs, or recovery phrases over phone or chat.',
    },
    {
      number: '03',
      title: 'Urgency Is the Scammer’s Weapon',
      desc: 'Any message asserting that your account will be deleted "within 24 hours" or requiring "immediate action" is leveraging psychological pressure. Slow down.',
    },
    {
      number: '04',
      title: 'No Such Thing as Guaranteed High Profit',
      desc: 'High returns without risk do not exist. Any crypto giveaway, doubling scheme, or task-based online job offering hundreds of dollars daily is fraudulent.',
    },
    {
      number: '05',
      title: 'Use Strong MFA on All Accounts',
      desc: 'Protect accounts with hardware security keys or authenticator apps (TOTP) instead of SMS, which can be intercepted via SIM-swapping.',
    },
  ];

  const quizQuestions = [
    {
      question: 'A representative from your bank calls stating a suspicious $500 charge occurred and asks you to read the 6-digit SMS code you just received to cancel it. What should you do?',
      options: [
        'Read the code immediately to prevent the fraudulent charge.',
        'Hang up, check your banking app directly, or call the number on the back of your card.',
        'Tell them only the first 3 digits of the code.',
        'Forward the SMS to the representative via WhatsApp.',
      ],
      correct: 1,
      explanation: 'Banks will NEVER ask you to recite an SMS OTP over the phone. That code was actually triggered by the scammer attempting to log into or drain your account.',
    },
    {
      question: 'Which of the following domain names is most likely a malicious typosquatting lookalike?',
      options: [
        'https://accounts.google.com/signin',
        'https://paypa1-security-verification.xyz/login',
        'https://www.chase.com/personal',
        'https://support.apple.com/en-us',
      ],
      correct: 1,
      explanation: '"paypa1-security-verification.xyz" uses the digit "1" instead of the letter "l" and a high-risk disposable TLD (.xyz). Legitimate PayPal is strictly paypal.com.',
    },
    {
      question: 'You receive an Instagram message from a close friend asking you to take a screenshot of a 6-digit code Instagram texted you to help them win an ambassador contest. What is happening?',
      options: [
        'Your friend genuinely needs your support in an online contest.',
        'Your friend\'s account is hijacked, and the scammer is using their profile to reset your password and take over your account.',
        'Instagram has launched a new community referral feature.',
        'It is safe to share as long as you do not give your password.',
      ],
      correct: 1,
      explanation: 'This is a classic account takeover vector. The scammer selected "Forgot Password" for your profile and is tricking you into sending the recovery code.',
    },
    {
      question: 'A remote recruiter offers you a part-time job paying $600/day for liking YouTube videos, but asks for a $50 refundable registration fee. What is this?',
      options: [
        'A standard online employment trial.',
        'A legitimate freelance marketing gig.',
        'A task-based recruitment scam designed to steal your upfront deposit.',
        'A guaranteed opportunity with high return.',
      ],
      correct: 2,
      explanation: 'Legitimate employers never demand upfront registration or activation fees from job applicants. Any job offering hundreds of dollars for simple clicks is a scam.',
    },
  ];

  const handleSelectOption = (qIdx: number, oIdx: number) => {
    if (submittedQuiz) return;
    setSelectedAnswers(prev => ({ ...prev, [qIdx]: oIdx }));
  };

  const calculateScore = () => {
    let score = 0;
    quizQuestions.forEach((q, idx) => {
      if (selectedAnswers[idx] === q.correct) score++;
    });
    return score;
  };

  return (
    <div className="space-y-10 max-w-5xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="space-y-2 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <h1 className="text-xl font-bold font-mono text-slate-100">
            Scam Awareness & Cyber Defense Hub
          </h1>
        </div>
        <p className="text-xs text-slate-400">
          Comprehensive threat intelligence knowledge base covering top digital fraud tactics, five golden rules for safe browsing, and interactive cyber defense quiz.
        </p>
      </div>

      {/* 5 Golden Rules */}
      <div className="space-y-4">
        <div className="flex items-center space-x-2">
          <Lightbulb className="w-5 h-5 text-amber-400" />
          <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
            The Five Golden Rules of Cyber Defense
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {goldenRules.map(rule => (
            <div
              key={rule.number}
              className="cyber-card p-4 border border-slate-800 flex flex-col justify-between space-y-2 relative overflow-hidden"
            >
              <span className="text-2xl font-black font-mono text-cyan-500/20 absolute -right-1 -top-1">
                {rule.number}
              </span>
              <div>
                <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  Rule {rule.number}
                </span>
                <h3 className="text-xs font-bold text-slate-100 mt-1">
                  {rule.title}
                </h3>
                <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                  {rule.desc}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 8 Attack Types Accordion */}
      <div className="space-y-4">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
            Primary Social Engineering & Fraud Threat Vectors ({topics.length})
          </h2>
        </div>

        <div className="space-y-3">
          {topics.map(t => {
            const isExpanded = expandedTopic === t.id;
            return (
              <div
                key={t.id}
                className="cyber-card border border-slate-800 rounded-xl overflow-hidden transition-all"
              >
                <button
                  type="button"
                  onClick={() => setExpandedTopic(isExpanded ? null : t.id)}
                  className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/40 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <span className="text-xs font-mono font-bold text-slate-200">
                      {t.title}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 hidden sm:inline">
                      {t.badge}
                    </span>
                  </div>
                  {isExpanded ? (
                    <ChevronUp className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  )}
                </button>

                {isExpanded && (
                  <div className="p-5 pt-1 border-t border-slate-800/80 space-y-4 text-xs animate-fade-in">
                    <p className="text-slate-300 font-medium">{t.overview}</p>

                    <div>
                      <h4 className="font-mono text-cyan-400 font-bold uppercase text-[10px] tracking-wider mb-1">
                        How the Scheme Operates:
                      </h4>
                      <p className="text-slate-400 leading-relaxed">{t.howItWorks}</p>
                    </div>

                    <div>
                      <h4 className="font-mono text-amber-400 font-bold uppercase text-[10px] tracking-wider mb-1">
                        Critical Red Flags & Warning Indicators:
                      </h4>
                      <ul className="list-disc list-inside space-y-1 text-slate-300">
                        {t.warningSigns.map((w, idx) => (
                          <li key={idx}>{w}</li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h4 className="font-mono text-slate-400 font-bold uppercase text-[10px] tracking-wider mb-1">
                        Real-World Illustrative Scenario:
                      </h4>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300">
                        {t.example}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                      <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-900/30 space-y-1.5">
                        <span className="font-mono font-bold text-emerald-400 uppercase text-[10px]">
                          Preventative Safeguards:
                        </span>
                        <ul className="space-y-1 text-slate-300 text-[11px]">
                          {t.prevention.map((p, idx) => (
                            <li key={idx} className="flex items-start space-x-1.5">
                              <span className="text-emerald-400 font-bold">✓</span>
                              <span>{p}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div className="p-3.5 rounded-lg bg-red-950/20 border border-red-900/30 space-y-1.5">
                        <span className="font-mono font-bold text-red-400 uppercase text-[10px]">
                          If You Already Responded / Fell Victim:
                        </span>
                        <ul className="space-y-1 text-slate-300 text-[11px]">
                          {t.recoverySteps.map((r, idx) => (
                            <li key={idx} className="flex items-start space-x-1.5">
                              <span className="text-red-400 font-bold">!</span>
                              <span>{r}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Interactive Cyber Defense Quiz */}
      <div className="cyber-card p-6 border border-slate-800 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center space-x-2">
              <Award className="w-5 h-5 text-cyan-400" />
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-100">
                Interactive Cyber Threat Awareness Quiz
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Test your ability to spot deceptive phishing, impersonation, and fraudulent social engineering vectors.
            </p>
          </div>

          {submittedQuiz && (
            <div className="flex items-center space-x-3">
              <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/60 px-3 py-1.5 rounded-lg border border-cyan-800/50">
                Score: {calculateScore()} / {quizQuestions.length} ({Math.round((calculateScore() / quizQuestions.length) * 100)}%)
              </span>
              <button
                type="button"
                onClick={() => {
                  setSelectedAnswers({});
                  setSubmittedQuiz(false);
                }}
                className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Retry</span>
              </button>
            </div>
          )}
        </div>

        <div className="space-y-6">
          {quizQuestions.map((q, qIdx) => {
            const userAnswer = selectedAnswers[qIdx];
            const isAnswered = userAnswer !== undefined;
            const isCorrect = userAnswer === q.correct;

            return (
              <div key={qIdx} className="space-y-3 p-4 rounded-xl bg-slate-950/50 border border-slate-800 text-xs">
                <p className="font-semibold text-slate-200">
                  <span className="font-mono text-cyan-400 mr-1.5">Q{qIdx + 1}.</span>
                  {q.question}
                </p>

                <div className="space-y-2">
                  {q.options.map((opt, oIdx) => {
                    const isSelected = userAnswer === oIdx;
                    let optionStyle = 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800';

                    if (submittedQuiz) {
                      if (oIdx === q.correct) {
                        optionStyle = 'bg-emerald-950/50 border-emerald-500 text-emerald-300 font-semibold';
                      } else if (isSelected && !isCorrect) {
                        optionStyle = 'bg-red-950/50 border-red-500 text-red-300 line-through';
                      } else {
                        optionStyle = 'bg-slate-950/40 border-slate-800/50 text-slate-500';
                      }
                    } else if (isSelected) {
                      optionStyle = 'bg-cyan-950/50 border-cyan-500 text-cyan-300 font-semibold';
                    }

                    return (
                      <button
                        key={oIdx}
                        type="button"
                        onClick={() => handleSelectOption(qIdx, oIdx)}
                        className={`w-full text-left p-3 rounded-lg border transition-all flex items-center justify-between text-xs ${optionStyle}`}
                      >
                        <span>{opt}</span>
                        {submittedQuiz && oIdx === q.correct && (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 ml-2" />
                        )}
                      </button>
                    );
                  })}
                </div>

                {submittedQuiz && (
                  <div className="mt-2 p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-[11px] leading-relaxed">
                    <strong className="text-cyan-400 font-mono">Forensic Rationale: </strong>
                    {q.explanation}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {!submittedQuiz && (
          <div className="flex justify-end pt-2">
            <button
              type="button"
              onClick={() => setSubmittedQuiz(true)}
              disabled={Object.keys(selectedAnswers).length < quizQuestions.length}
              className="px-6 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wide text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 disabled:opacity-40 transition-all shadow-glow-cyan"
            >
              Submit Quiz & Evaluate Score
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
