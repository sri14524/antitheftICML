import dns from 'node:dns/promises';
import validator from 'validator';

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com',
  'sharklasers.com', 'yopmail.com', 'trashmail.com', 'throwawaymail.com',
  'getairmail.com', 'dispostable.com', 'fakeinbox.com', 'mohmal.com'
]);

/**
 * Validates and analyzes email address security, MX records, and burner risk.
 */
export async function analyzeEmail(rawEmail) {
  if (!rawEmail || typeof rawEmail !== 'string') {
    throw new Error('Please provide an email address.');
  }

  const cleaned = rawEmail.trim().toLowerCase();

  if (!validator.isEmail(cleaned)) {
    throw new Error(`Invalid email address format: "${cleaned}".`);
  }

  const [username, domain] = cleaned.split('@');
  const isDisposable = DISPOSABLE_DOMAINS.has(domain);

  let hasMx = false;
  let mxRecords = [];
  try {
    mxRecords = await dns.resolveMx(domain);
    hasMx = mxRecords && mxRecords.length > 0;
  } catch (err) {
    hasMx = false;
  }

  let trustScore = 95;
  const deductions = [];

  if (isDisposable) {
    trustScore -= 50;
    deductions.push({
      reason: 'Disposable / Burner Email Service',
      penalty: -50,
      impact: 'Associated with high volume spam, throwaway accounts, and credential abuse',
    });
  }

  if (!hasMx) {
    trustScore -= 40;
    deductions.push({
      reason: 'No valid MX (Mail Exchange) DNS records found',
      penalty: -40,
      impact: 'Domain cannot receive mail, often used for spoofed sender headers in phishing',
    });
  }

  // Check for suspicious username patterns
  if (/^(admin|support|security|billing|account-update|verify)\d*$/i.test(username) && !['google.com', 'microsoft.com'].includes(domain)) {
    trustScore -= 20;
    deductions.push({
      reason: 'Executive/Authority impersonation prefix',
      penalty: -20,
      impact: 'Frequently leveraged in Business Email Compromise (BEC) and phishing lures',
    });
  }

  const verdict = trustScore >= 75 ? 'Safe' : trustScore >= 50 ? 'Suspicious' : 'Malicious';

  return {
    available: true,
    email: cleaned,
    username,
    domain,
    hasValidMx: hasMx,
    mxCount: mxRecords.length,
    isDisposable,
    trustScore: Math.max(0, trustScore),
    verdict,
    deductions,
    source: 'DNS MX Resolver & ThreatLens Email Intelligence',
  };
}
