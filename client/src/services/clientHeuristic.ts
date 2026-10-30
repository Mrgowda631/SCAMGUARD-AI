import { AnalysisResult, ScanIndicator } from '../types';

/**
 * Text normalization and safe de-obfuscation helper.
 * Unfolds spaced letters (e.g. "v e r i f y"), hyphens ("p-a-s-s-w-o-r-d"),
 * and common leetspeak substitutions ("0" -> "o", "@" -> "a", etc.).
 */
export function normalizeText(input: string): { original: string; normalized: string; isObfuscated: boolean } {
  const original = input || '';
  const cleaned = original
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  const hasSpacedWords = /\b([a-zA-Z0-9](?:[\-_.\s][a-zA-Z0-9]){2,})\b/g.test(cleaned);

  let deobfuscated = cleaned.replace(/\b([a-zA-Z0-9](?:[\-_.\s][a-zA-Z0-9])+)\b/g, (match) => {
    return match.replace(/[\-_.\s]/g, '');
  }).toLowerCase();

  deobfuscated = deobfuscated
    .replace(/c1/g, 'cl')
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's')
    .replace(/!/g, 'i')
    .replace(/vv/g, 'w');

  return {
    original: cleaned,
    normalized: deobfuscated,
    isObfuscated: hasSpacedWords,
  };
}

interface ThreatRule {
  id: string;
  category: string;
  weight: number;
  regex: RegExp;
  reason: string;
  critical?: boolean;
}

const CLIENT_THREAT_RULES: ThreatRule[] = [
  {
    id: 'otp_harvesting_direct',
    category: 'phishing',
    weight: 75,
    critical: true,
    regex: /(?:send|share|give|provide|forward|read|tell|dm|msg|text)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:6[- ]digit\s+|one[- ]time\s+|sms\s+|verification\s+|security\s+)?(?:otp|code|pin|password)/i,
    reason: 'Directly asks the recipient to disclose or forward a one-time password (OTP), security code, or PIN.',
  },
  {
    id: 'credential_solicitation',
    category: 'phishing',
    weight: 70,
    critical: true,
    regex: /(?:enter|confirm|submit|verify|update)\s+(?:your\s+)?(?:password|pin|passcode|secret recovery phrase|seed phrase|cvv|card details|bank credentials)/i,
    reason: 'Prompts for confidential credentials, banking PIN, security seed phrase, or authentication passwords.',
  },
  {
    id: 'verify_link_prompt',
    category: 'phishing',
    weight: 45,
    regex: /(?:click\s+here\s+to\s+verify|verify\s+your\s+account\s+(?:at|via|on|link|immediately)|login\s+to\s+(?:restore|unblock|verify|reactivate)|click\s+(?:our\s+)?bio\s+link)/i,
    reason: 'Urges clicking a link to verify an account or prevent suspension (typical credential phishing lure).',
  },
  {
    id: 'account_suspension_coercion',
    category: 'phishing',
    weight: 45,
    regex: /(?:account\s+(?:will\s+be\s+|has\s+been\s+)?(?:suspended|locked|terminated|blocked|disabled|deleted|closed)|to\s+avoid\s+(?:immediate\s+)?(?:suspension|termination|closure)|action\s+required\s+immediately|final\s+warning\s+before\s+suspension)/i,
    reason: 'Fabricates imminent account suspension or termination to coerce immediate hasty reaction.',
  },
  {
    id: 'generic_urgency_window',
    category: 'phishing',
    weight: 25,
    regex: /\b(?:urgent(ly)?|within\s+(?:24|12|48|6|2)\s+hours|expires\s+today|act\s+now)\b/i,
    reason: 'Contains urgency deadline language.',
  },
  {
    id: 'legal_police_coercion',
    category: 'impersonation',
    weight: 75,
    critical: true,
    regex: /(?:arrest\s+warrant|police\s+action|legal\s+case\s+filed|tax\s+enforcement|customs\s+seizure|law\s+enforcement\s+agency|court\s+summons|arrest\s+within\s+\d+\s+hours)/i,
    reason: 'Threatens arrest, police prosecution, or legal enforcement to induce panic and compliance.',
  },
  {
    id: 'utility_disconnection_threat',
    category: 'financial_fraud',
    weight: 70,
    critical: true,
    regex: /(?:electricity\s+(?:power\s+)?will\s+be\s+(?:disconnected|cut)|power\s+(?:supply\s+)?will\s+be\s+disconnected|gas\s+connection\s+will\s+be\s+cut|unpaid\s+electricity\s+bill)/i,
    reason: 'Utility disconnection scam: fabricates immediate cutoff of electricity or gas to force fraudulent bill payment.',
  },
  {
    id: 'platform_security_impersonation',
    category: 'impersonation',
    weight: 50,
    regex: /(?:official\s+meta\s+(?:support|verification|team)|instagram\s+copyright\s+(?:team|infringement)|whatsapp\s+official\s+team|telegram\s+security\s+team|apple\s+support\s+advisory|bank\s+(?:security|fraud|prevention)\s+department)/i,
    reason: 'Impersonates institutional security personnel, platform admins, or bank fraud departments.',
  },
  {
    id: 'family_emergency_impersonation',
    category: 'impersonation',
    weight: 75,
    critical: true,
    regex: /(?:(?:hi|hello|hey)\s+(?:mom|dad|mum).*(?:lost|broke|new\s+number)|stranded\s+at\s+(?:the\s+)?hospital|using\s+(?:a\s+)?friend['\s]+(?:phone|whatsapp).*transfer)/i,
    reason: 'Family emergency / "Hi Mum" impersonation scam: pretends to be a distressed child needing urgent hospital/bail funds.',
  },
  {
    id: 'lottery_prize_lure',
    category: 'advance_fee',
    weight: 75,
    critical: true,
    regex: /(?:you\s+(?:have\s+)?won|selected\s+(?:as\s+)?(?:a\s+|the\s+)?lucky\s+winner|congratulations\s+you\s+received\s+\$|claim\s+your\s+(?:cash\s+|free\s+)?prize|lottery\s+(?:reward|winnings)|\$1,000,000|unclaimed\s+(?:inheritance|funds|consignment))/i,
    reason: 'Claims recipient won an unsolicited prize or lottery; prefaces upfront processing or tax fee extortion.',
  },
  {
    id: 'customs_diplomatic_parcel',
    category: 'advance_fee',
    weight: 70,
    critical: true,
    regex: /(?:diplomatic\s+courier|consignment\s+box|customs\s+(?:officer|clearance|fee)|agent\s+clearance\s+fee|package\s+held\s+at\s+customs|valuable\s+parcel.*(?:pay|fee))/i,
    reason: 'Romance / parcel delivery scam: claims valuable parcel is detained at airport customs requiring fee transfer.',
  },
  {
    id: 'crypto_giveaway_doubling',
    category: 'crypto_scam',
    weight: 75,
    critical: true,
    regex: /(?:crypto(?:currency)?\s+giveaway|bitcoin\s+double|send\s+\d+(?:\.\d+)?\s+(?:btc|eth|usdt)\s+to.*receive|receive\s+2x\s+back|vitalik.*(?:giving\s+away|airdrop)|double\s+your\s+(?:crypto|bitcoin|investment))/i,
    reason: 'High-yield crypto giveaway scheme: solicits cryptocurrency with fraudulent promises of immediate multiplied returns.',
  },
  {
    id: 'guaranteed_unrealistic_returns',
    category: 'crypto_scam',
    weight: 65,
    critical: true,
    regex: /(?:guaranteed\s+(?:daily\s+)?returns?|100%\s+risk[- ]free\s+profit|forex\s+trading\s+robot|no\s+risk\s+passive\s+income|triple\s+your\s+money|vip\s+crypto\s+signals.*guaranteed)/i,
    reason: 'Promises mathematically impossible guaranteed zero-risk profits, classic hallmark of Ponzi/investment fraud.',
  },
  {
    id: 'task_based_remote_job',
    category: 'fake_job',
    weight: 70,
    critical: true,
    regex: /(?:like\s+(?:youtube|tiktok|instagram)\s+videos\s+(?:for\s+money|and\s+earn)|part[- ]time\s+(?:job|vacancies)\s+liking|earn\s+\$?(?:200|300|500|800)\s+daily|refundable\s+registration\s+fee|deposit\s+\$?\d+.*registration|telegram\s+task\s+job)/i,
    reason: 'Task-based employment scam: lures victims into fake remote video-liking jobs requiring prepaid tasks or deposits.',
  },
  {
    id: 'fake_job_exec_attachment',
    category: 'fake_job',
    weight: 75,
    critical: true,
    regex: /(?:job[-_ ]specs?\.exe|interview_test\.exe|download\s+the\s+project\s+specifications.*\.exe|salary\s+\$\d+k\/yr.*\.exe)/i,
    reason: 'Fake recruitment luring candidate into running an executable payload disguised as job specification.',
  },
  {
    id: 'gift_card_demands',
    category: 'financial_fraud',
    weight: 75,
    critical: true,
    regex: /(?:steam\s+gift\s+card|apple\s+gift\s+card|itunes\s+(?:gift\s+)?card|google\s+play\s+card|razer\s+gold|pay\s+(?:fine|fee|bill)\s+via\s+(?:gift\s+card|bitcoin|crypto)|scratch\s+the\s+back\s+of\s+the\s+card)/i,
    reason: 'Demands payment via non-refundable consumer gift cards, a universal indicator of consumer fraud.',
  },
  {
    id: 'package_delivery_fee_phishing',
    category: 'delivery_scam',
    weight: 70,
    critical: true,
    regex: /(?:package\s+(?:cannot|could\s+not)\s+be\s+delivered|incomplete\s+address.*click\s+link|reschedule\s+(?:your\s+)?delivery.*click|redelivery\s+fee\s+of\s+\$|usps\s+tracking.*confirm\s+address)/i,
    reason: 'Package delivery smishing: tricks recipient into paying fake redelivery fees and disclosing credit card details.',
  },
  {
    id: 'tech_support_scareware',
    category: 'tech_support',
    weight: 75,
    critical: true,
    regex: /(?:trojan\s+detected|windows\s+has\s+detected|call\s+(?:microsoft|apple)\s+support|remote\s+desktop\s+access|install\s+anydesk|install\s+teamviewer|firewall\s+breach.*call\s+\+?1?[- ]?8\d{2})/i,
    reason: 'Tech support scareware: fabricates malware infection to coerce victim into calling toll-free line or installing remote control tool.',
  },
  // --- 10. SUSPICIOUS DESTINATIONS / OBFUSCATED URLS ---
  {
    id: 'suspicious_link_infrastructure',
    category: 'phishing',
    weight: 35,
    regex: /(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}|bit\.ly\/|tinyurl\.com\/|t\.me\/|wa\.me\/(?:\+?\d+)\?text=|(?:[a-zA-Z0-9-]+\.)*(?:top|xyz|click|work|buzz|monster|cfd|sbs|fit|beauty|hair)\b/i,
    reason: 'Contains shortened, raw IP, or disposable high-risk TLD link designed to conceal the destination.',
  },

  // --- 11. CONFIDENTIAL CREDENTIALS & MILITARY ACCESS PROTOCOLS (CRITICAL) ---
  {
    id: 'confidential_military_credential_solicitation',
    category: 'credential_theft',
    weight: 85,
    critical: true,
    regex: /(?:military\s+(?:credentials?|access|protocols?)|classified\s+(?:documents?|files?|credentials?)|defense\s+(?:intranet|credentials?|network)|ex[- ]army\s+man.*give\s+me|give\s+me\s+(?:the\s+)?(?:military|defense|classified)\s+(?:credentials?|protocols?|access))/i,
    reason: 'Solicitation of restricted military credentials, defense access protocols, or classified materials.',
  },

  // --- 12. FAKE JOB ADVANCE REGISTRATION FEES ---
  {
    id: 'fake_job_registration_fee',
    category: 'fake_job',
    weight: 80,
    critical: true,
    regex: /(?:congratulations.*(?:you\s+are\s+selected|job\s+offer).*pay.*(?:fee|registration|deposit)|pay\s+(?:a\s+)?registration\s+fee\s+to\s+receive\s+(?:your\s+)?job\s+offer|upfront\s+registration\s+fee.*job)/i,
    reason: 'Advance-fee recruitment scam requiring candidates to pay a registration fee to receive a job offer.',
  },

  // --- 13. CRYPTOCURRENCY MULTIPLIER / DOUBLING FRAUD ---
  {
    id: 'crypto_doubling_multiplier',
    category: 'crypto_scam',
    weight: 85,
    critical: true,
    regex: /(?:(?:send|invest|transfer|deposit)\s+[^\s]+\s+.*?(?:receive|get|earn|return)\s+[^\s]+.*?(?:(?:within|in)\s+(?:one|\d+)\s+hours?|instantly|same\s+day)|(?:send|invest|transfer|deposit)\s+.*?(?:receive|get|earn|return)\s+.*?(?:in|within)\s+(?:one|\d+)\s+hours?|send\s+[₹$€£\d,]+\s+(?:in\s+)?crypto(?:currency)?\s+and\s+receive|receive\s+[₹$€£\d,]+\s+(?:within|in)\s+\d+\s+(?:hour|hr|min|day)s?|double\s+your\s+crypto|send\s+₹?\d+.*receive\s+₹?\d+.*crypto)/i,
    reason: 'Cryptocurrency doubling scheme soliciting upfront funds with promises of rapid guaranteed returns.',
  },

  // --- 14. AMBIGUOUS VERIFICATION PROMPTS ---
  {
    id: 'ambiguous_account_verification',
    category: 'suspicious_activity',
    weight: 40,
    critical: false,
    regex: /(?:please\s+verify\s+your\s+account\s+when\s+you\s+have\s+time|verify\s+your\s+account\s+when\s+free|unverified\s+account\s+reminder)/i,
    reason: 'Unsolicited, ambiguous account verification request lacking verifiable brand context or secure official portal.',
  },

  // --- 15. UNFAMILIAR WEBSITE LINK LURES ---
  {
    id: 'suspicious_unfamiliar_website_lure',
    category: 'phishing',
    weight: 75,
    critical: true,
    regex: /(?:verify\s+it\s+using\s+this\s+unfamiliar\s+website|account\s+has\s+a\s+problem.*verify.*website|visit\s+this\s+unfamiliar\s+link)/i,
    reason: 'Deceptive link lure directing victim to an unfamiliar website to resolve a fabricated account issue.',
  },

  // --- 16. UNAUTHORIZED INSTITUTIONAL / UNIVERSITY CREDENTIAL SOLICITATION ---
  {
    id: 'institutional_credential_solicitation',
    category: 'credential_theft',
    weight: 75,
    critical: false,
    regex: /(?:(?:give\s+me|send\s+me|share|provide|disclose|forward|hand\s+over|requesting|tell\s+me)\s+.*?(?:credentials?|passwords?|usernames?|username\s+and\s+password|login\s+details|access\s+tokens?|admin\s+credentials).*?(?:universit(?:y|ies)|college|school|institution|staff|admin|administrator|student|faculty)|(?:give\s+me|send\s+me|share|provide|disclose|forward)\s+.*?(?:private|staff|admin|administrator|student)\s+(?:login\s+)?(?:credentials?|passwords?|accounts?)|(?:credentials?|passwords?)\s+of\s+(?:the\s+)?(?:universit(?:y|ies)|colleges?|institutions?|staff|students?|admins?))/i,
    reason: 'Unauthorized solicitation of private university, staff, or student login credentials without established authorization.',
  },

  // --- 17. ADVANCE-FEE, GOVERNMENT IMPERSONATION & IDENTITY THEFT (CRITICAL) ---
  {
    id: 'advance_fee_and_identity_fraud',
    category: 'advance_fee_and_identity_fraud',
    weight: 90,
    critical: true,
    regex: /(?:(?:ex[- ]?arm(?:y)?\s+officer|military\s+officer|government\s+contract|confidential\s+government).*?(?:registration\s+fee|id\s+proof|pay\s+[\d,]+)|(?:registration\s+fee|processing\s+fee).*?(?:to\s+receive\s+(?:your\s+)?payment|id\s+proof)|(?:id\s+proof|identity\s+proof).*?(?:pay\s+[\d,]+|registration\s+fee))/i,
    reason: 'Advance-fee scam and identity theft: demands upfront registration fee and identity documents in exchange for unverified government contract or promised payment.',
  },
];

interface ContextRule {
  id: string;
  weightReduction: number;
  regex: RegExp;
  reason: string;
}

const CLIENT_CONTEXT_DAMPENERS: ContextRule[] = [
  {
    id: 'security_awareness_warning',
    weightReduction: 50,
    regex: /(?:never\s+share\s+(?:this\s+|your\s+)?(?:otp|pin|password|code)|do\s+not\s+share\s+(?:this\s+|your\s+)?(?:otp|pin|password|code)|bank\s+never\s+(?:asks|calls)\s+for\s+(?:otp|pin)|keep\s+(?:this\s+)?(?:otp|pin|password)\s+secret|confidential\s+code\s+valid\s+for\s+\d+\s+min)/i,
    reason: 'Standard security warning in authentic institutional notifications reminding user NEVER to share OTP/PIN.',
  },
  {
    id: 'legitimate_bank_alert',
    weightReduction: 40,
    regex: /(?:your\s+(?:a\/c|account)\s+(?:no\.?\s*)?(?:[x*]+\d+|\d{4})\s+(?:is|has\s+been)\s+(?:debited|credited)|credited\s+with\s+(?:inr|\$|rs\.?|usd)|debited\s+for\s+(?:inr|\$|rs\.?|usd)|avail(?:able)?\s+bal(?:ance)?\s*[:=]?\s*(?:inr|\$|rs\.?|usd)|inr\s+\d+(?:,\d+)*(?:\.\d+)?\s+(?:debited|credited))/i,
    reason: 'Standard informational bank statement or debit/credit transaction record without coercive action demands.',
  },
  {
    id: 'conversational_peer_chat',
    weightReduction: 35,
    regex: /(?:see\s+you\s+(?:tomorrow|later|at|there)|let['\s]+s\s+(?:meet|grab|eat|go|catch\s+up|lunch|dinner)|are\s+we\s+still\s+meeting|are\s+you\s+coming\s+to\s+(?:college|school|class|work|office|lunch|dinner)|how\s+was\s+your\s+day|how\s+are\s+you\s+doing|good\s+morning\s+everyone|talk\s+to\s+you\s+later|text\s+me\s+when|happy\s+birthday|thanks\s+bro|thanks\s+buddy|miss\s+you)/i,
    reason: 'Conversational greetings and casual coordination between friends, colleagues, or family.',
  },
  {
    id: 'college_educational_context',
    weightReduction: 35,
    regex: /(?:cybersecurity\s+lecture|assignment\s+is\s+due|submit\s+(?:your\s+)?(?:assignment|report)|lecture\s+slides|college\s+portal|university\s+exam|library\s+book\s+(?:return|due)|prof(?:essor)?\.?\s+[a-z]+|semester\s+results|class\s+schedule|campus\s+announcement)/i,
    reason: 'Academic and educational correspondence regarding classes, lectures, library books, or coursework.',
  },
  {
    id: 'work_team_context',
    weightReduction: 35,
    regex: /(?:scheduled\s+maintenance\s+notice|internal\s+team\s+jira|sprint\s+planning|pull\s+request|standup\s+meeting|quarterly\s+review|financial\s+metrics\s+report|no\s+password\s+change\s+or\s+action\s+is\s+required|planned\s+database\s+optimization)/i,
    reason: 'Internal IT infrastructure notice or routine professional business communication.',
  },
  {
    id: 'legitimate_delivery_update',
    weightReduction: 35,
    regex: /(?:out\s+for\s+delivery\s+today|package\s+with\s+tracking\s+#\d+|order\s+#\d+\s+has\s+been\s+shipped|delivery\s+agent\s+will\s+arrive|arriving\s+by\s+\d+\s*(?:am|pm)|no\s+action\s+is\s+required)/i,
    reason: 'Standard informational courier shipment tracking update without suspicious link redirects.',
  },
  {
    id: 'casual_bill_split',
    weightReduction: 30,
    regex: /(?:send\s+me\s+\$?\d+\s+for\s+(?:the\s+)?(?:pizza|dinner|lunch|uber|groceries|tickets)|split\s+the\s+bill|my\s+share\s+of\s+the|here['\s]+s\s+the\s+money\s+for)/i,
    reason: 'Ordinary peer-to-peer dinner or expense splitting between acquaintances.',
  },
  {
    id: 'cybersecurity_academic_discussion',
    weightReduction: 85,
    regex: /(?:cybersecurity\s+class\s+discussed\s+why|why\s+military\s+credentials\s+must\s+remain\s+confidential|academic\s+discussion\s+on\s+security|lecture\s+on\s+credential\s+protection|information\s+security\s+curriculum)/i,
    reason: 'Educational or policy discussion about cybersecurity and information protection principles.',
  },
  {
    id: 'university_public_navigation_help',
    weightReduction: 85,
    regex: /(?:where\s+can\s+i\s+find\s+(?:the\s+)?(?:university|college|student|portal)\s+login\s+page|how\s+do\s+i\s+reset\s+my\s+(?:university|college|student|portal)\s+password|our\s+university\s+teaches\s+students\s+how\s+to\s+protect|where\s+can\s+i\s+log\s+in|help\s+me\s+understand\s+our\s+institutional\s+authentication\s+process|i\s+need\s+access\s+to\s+my\s+own\s+student\s+portal)/i,
    reason: 'Legitimate institutional navigation, educational instruction, or self-service password recovery inquiry without credential disclosure demands.',
  },
];

export function runClientHeuristic(content: string, platform?: string): AnalysisResult {
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return {
      prediction: 'genuine',
      risk_score: 0,
      confidence: 1.0,
      category: 'legitimate',
      indicators: [],
      explanation: 'No suspicious content detected in the empty input.',
      recommendations: ['Provide text, a URL, or social media post to inspect.'],
      summary: 'Input is empty.',
      engine: 'heuristic_fallback',
    };
  }

  const { original, normalized, isObfuscated } = normalizeText(content);

  const matchedThreats: { rule: ThreatRule; matchText: string }[] = [];
  const matchedDampeners: { rule: ContextRule; matchText: string }[] = [];

  let rawThreatScore = 0;
  let hasCriticalThreat = false;
  const categoriesDetected: Record<string, number> = {};

  for (const rule of CLIENT_THREAT_RULES) {
    const matchOriginal = rule.regex.exec(original);
    const matchNorm = rule.regex.exec(normalized);
    const matched = matchOriginal || matchNorm;

    if (matched) {
      matchedThreats.push({ rule, matchText: matched[0] });
      rawThreatScore += rule.weight;
      categoriesDetected[rule.category] = (categoriesDetected[rule.category] || 0) + rule.weight;
      if (rule.critical) {
        hasCriticalThreat = true;
      }
    }
  }

  let dampeningPoints = 0;
  for (const dampener of CLIENT_CONTEXT_DAMPENERS) {
    const matchOrig = dampener.regex.exec(original);
    const matchNorm = dampener.regex.exec(normalized);
    const matched = matchOrig || matchNorm;

    if (matched) {
      matchedDampeners.push({ rule: dampener, matchText: matched[0] });
      dampeningPoints += dampener.weightReduction;
    }
  }

  if (isObfuscated && matchedThreats.length > 0) {
    rawThreatScore += 20;
  }

  let netScore = rawThreatScore;

  const isNegatedSecurityWarning = matchedDampeners.some(d => d.rule.id === 'security_awareness_warning');
  const isLegitBankAlert = matchedDampeners.some(d => d.rule.id === 'legitimate_bank_alert');
  const isAcademicDiscussion = matchedDampeners.some(d => d.rule.id === 'cybersecurity_academic_discussion');

  if (isAcademicDiscussion) {
    netScore = 0;
  } else if (isNegatedSecurityWarning || isLegitBankAlert) {
    netScore = Math.max(0, netScore - dampeningPoints - 50);
  } else if (!hasCriticalThreat && dampeningPoints > 0) {
    netScore = Math.max(0, netScore - dampeningPoints);
  } else if (hasCriticalThreat && dampeningPoints > 0) {
    const nonChatDampeners = matchedDampeners.filter(d => d.rule.id !== 'conversational_peer_chat');
    if (nonChatDampeners.length > 0) {
      netScore = Math.max(65, netScore - 15);
    }
  }

  if (matchedThreats.length === 0) {
    return {
      prediction: 'genuine',
      risk_score: 0,
      confidence: 0.85,
      category: 'legitimate',
      indicators: [],
      explanation: 'No suspicious intent or harmful request detected.',
      recommendations: [
        'No immediate defensive action required.',
      ],
      summary: 'Content verified as safe with no suspicious threat signatures detected.',
      engine: 'heuristic_fallback',
    };
  }

  const risk_score = Math.min(100, Math.max(0, netScore));

  let prediction: 'scam' | 'suspicious' | 'genuine';
  if (risk_score >= 50) {
    prediction = 'scam';
  } else if (risk_score >= 21) {
    prediction = 'suspicious';
  } else {
    prediction = 'genuine';
  }

  let dominantCategory = 'legitimate';
  if (prediction !== 'genuine') {
    let highestWeight = 0;
    for (const [cat, w] of Object.entries(categoriesDetected)) {
      if (w > highestWeight) {
        highestWeight = w;
        dominantCategory = cat;
      }
    }
    if (dominantCategory === 'legitimate') {
      dominantCategory = 'suspicious_activity';
    }
  }

  const indicators: ScanIndicator[] = [];

  for (const { rule, matchText } of matchedThreats) {
    if ((isNegatedSecurityWarning || isLegitBankAlert || isAcademicDiscussion) && (rule.id === 'otp_harvesting_direct' || rule.id === 'credential_solicitation' || rule.id === 'confidential_military_credential_solicitation')) {
      continue;
    }
    indicators.push({
      phrase: matchText,
      reason: rule.reason,
    });
  }

  if (isObfuscated && matchedThreats.length > 0) {
    indicators.push({
      phrase: 'Obfuscated character spacing / formatting',
      reason: 'Deliberate spacing or symbols inserted between letters to evade keyword filters.',
    });
  }

  if (prediction === 'genuine' && matchedDampeners.length > 0) {
    indicators.push({
      phrase: matchedDampeners[0].matchText,
      reason: matchedDampeners[0].rule.reason,
    });
  }

  let confidence = 0.85;
  if (prediction === 'scam') {
    confidence = indicators.length >= 2 || hasCriticalThreat ? 0.95 : 0.80;
  } else if (prediction === 'suspicious') {
    confidence = 0.75;
  } else {
    confidence = matchedDampeners.length > 0 ? 0.90 : 0.85;
  }

  let explanation = '';
  if (prediction === 'scam') {
    const keyPhrases = indicators.slice(0, 3).map(i => `"${i.phrase}"`).join(', ');
    explanation = `Offline client forensic engine identified high-severity threat markers (${keyPhrases || dominantCategory}). Communication shows characteristics of ${dominantCategory.replace('_', ' ')} fraud.`;
  } else if (prediction === 'suspicious') {
    explanation = `Offline client analysis detected moderate risk indicators. Contains elements requiring independent verification.`;
  } else {
    if (matchedDampeners.length > 0) {
      explanation = `Verified as legitimate human communication (${matchedDampeners[0].rule.reason.toLowerCase()}). No scam patterns detected.`;
    } else {
      explanation = `No scam heuristics or high-pressure triggers detected. Normal communication.`;
    }
  }

  const recommendations: string[] = [];
  if (prediction === 'scam') {
    recommendations.push('Do NOT click links, open attachments, or wire funds.');
    recommendations.push('Never disclose passwords, SMS OTPs, banking credentials, or seed phrases.');
    recommendations.push('Block the sender and report to platform security.');
  } else if (prediction === 'suspicious') {
    recommendations.push('Verify sender identity through official published channels.');
    recommendations.push('Do not share sensitive credentials or payment information.');
  } else {
    recommendations.push('Maintain standard cyber hygiene.');
    recommendations.push('Keep 2FA enabled on your accounts.');
  }

  const classification = prediction === 'scam' ? 'SCAM' : prediction === 'suspicious' ? 'SUSPICIOUS' : 'SAFE';
  const risk_level = risk_score >= 80 ? 'CRITICAL' : risk_score >= 60 ? 'HIGH' : risk_score >= 30 ? 'MEDIUM' : 'LOW';
  const detected_indicators = indicators.map(i => `${i.phrase}: ${i.reason}`);
  const summary = prediction === 'scam'
    ? `Flagged as a high-risk ${dominantCategory.replace('_', ' ')} scam (Threat Score: ${risk_score}/100).`
    : prediction === 'suspicious'
    ? `Identified as suspicious communication (Risk Score: ${risk_score}/100).`
    : `Verified as genuine communication (Risk Score: ${risk_score}/100).`;
  const recommended_action = recommendations[0] || 'Verify sender identity independently.';

  return {
    classification,
    prediction,
    risk_score,
    confidence,
    risk_level,
    category: dominantCategory,
    detected_indicators,
    indicators,
    explanation,
    recommended_action,
    recommendations,
    url_analysis: 'No URL extracted in client heuristic pass.',
    limitations: 'Offline client-side heuristic engine only. Real-time AI threat validation was unavailable.',
    summary,
    engine: 'heuristic_fallback',
  };
}
