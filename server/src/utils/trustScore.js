/**
 * Transparent Trust Score Calculation Engine (0 - 100)
 * Evaluates signals from multiple threat intelligence feeds and provides
 * a fully documented audit log of deductions.
 */
export function calculateUrlTrustScore({
  googleSafeBrowsing,
  virusTotal,
  phishTank,
  urlscan,
  whois,
  ssl,
}) {
  let score = 100;
  const deductions = [];
  const threatCategories = new Set();

  // 1. Google Safe Browsing Signal
  if (googleSafeBrowsing?.available) {
    if (googleSafeBrowsing.status === 'malicious') {
      const penalty = -50;
      score += penalty;
      threatCategories.add(
        googleSafeBrowsing.threatType === 'MALWARE' ? 'Malware Distribution' : 'Phishing / Social Engineering'
      );
      deductions.push({
        source: 'Google Safe Browsing',
        reason: `Flagged as malicious threat: ${googleSafeBrowsing.threatType || 'Malicious'}`,
        penalty,
        severity: 'Critical',
        impact: 'Google security telemetry confirmed an active malicious campaign',
      });
    } else if (googleSafeBrowsing.status === 'suspicious') {
      const penalty = -25;
      score += penalty;
      threatCategories.add('Potential Phishing');
      deductions.push({
        source: 'Google Safe Browsing',
        reason: 'Suspicious credential harvesting heuristic pattern',
        penalty,
        severity: 'High',
        impact: 'Deceptive URL structure matching common phishing lures',
      });
    }
  }

  // 2. VirusTotal Multi-Engine Signal
  if (virusTotal?.available) {
    const malicious = virusTotal.maliciousCount || 0;
    const suspicious = virusTotal.suspiciousCount || 0;

    if (malicious > 0) {
      const penalty = Math.max(-60, -(malicious * 10));
      score += penalty;
      threatCategories.add(malicious > 5 ? 'Multi-Vendor Malicious URL' : 'Suspicious Threat Vector');
      deductions.push({
        source: 'VirusTotal Intelligence',
        reason: `${malicious} security vendor${malicious > 1 ? 's' : ''} flagged this target as malicious`,
        penalty,
        severity: malicious >= 3 ? 'Critical' : 'High',
        impact: `Security vendors detected threat signatures (${Object.keys(virusTotal.vendorBreakdown || {}).filter(k => virusTotal.vendorBreakdown[k].category === 'malicious').slice(0, 3).join(', ')})`,
      });
    } else if (suspicious > 0) {
      const penalty = Math.max(-20, -(suspicious * 5));
      score += penalty;
      threatCategories.add('Suspicious Domain');
      deductions.push({
        source: 'VirusTotal Intelligence',
        reason: `${suspicious} security vendor${suspicious > 1 ? 's' : ''} classified this target as suspicious`,
        penalty,
        severity: 'Medium',
        impact: 'Unusual routing or domain registration characteristics',
      });
    }
  }

  // 3. PhishTank Active Database Signal
  if (phishTank?.available && phishTank.status === 'malicious') {
    const penalty = -45;
    score += penalty;
    threatCategories.add('Verified Phishing Attack');
    deductions.push({
      source: 'PhishTank Database',
      reason: 'Verified active phishing site listed in PhishTank repository',
      penalty,
      severity: 'Critical',
      impact: 'Confirmed credential harvesting targeting online users',
    });
  }

  // 4. WHOIS & Domain Age Signal
  if (whois?.available) {
    const ageDays = whois.ageDays;
    if (whois.isCriticalRiskDomain || ageDays < 14) {
      const penalty = -30;
      score += penalty;
      threatCategories.add('Newly Registered Domain (<14 days)');
      deductions.push({
        source: 'WHOIS & Domain Age',
        reason: `Extremely new domain registration (${ageDays} day${ageDays === 1 ? '' : 's'} old)`,
        penalty,
        severity: 'High',
        impact: 'New domains are overwhelmingly used in ephemeral phishing campaigns and quick-burn scams',
      });
    } else if (whois.isNewDomain || ageDays < 60) {
      const penalty = -15;
      score += penalty;
      threatCategories.add('Fresh Domain (<60 days)');
      deductions.push({
        source: 'WHOIS & Domain Age',
        reason: `Recently registered domain (${ageDays} days old)`,
        penalty,
        severity: 'Medium',
        impact: 'Insufficient domain longevity to establish baseline trust',
      });
    }
  }

  // 5. SSL / TLS Certificate Signal
  if (ssl?.available) {
    if (ssl.isExpired) {
      const penalty = -25;
      score += penalty;
      threatCategories.add('Expired SSL Certificate');
      deductions.push({
        source: 'SSL / TLS Inspector',
        reason: 'Expired SSL certificate',
        penalty,
        severity: 'High',
        impact: 'Encrypted communication is untrusted or abandoned',
      });
    } else if (ssl.isSelfSigned) {
      const penalty = -30;
      score += penalty;
      threatCategories.add('Untrusted Self-Signed Certificate');
      deductions.push({
        source: 'SSL / TLS Inspector',
        reason: 'Untrusted self-signed certificate detected',
        penalty,
        severity: 'High',
        impact: 'Certificate not issued by recognized Certificate Authority (CA)',
      });
    } else if (!ssl.valid && ssl.error) {
      const penalty = -20;
      score += penalty;
      threatCategories.add('Insecure Connection / No HTTPS');
      deductions.push({
        source: 'SSL / TLS Inspector',
        reason: 'Invalid or missing TLS certificate',
        penalty,
        severity: 'Medium',
        impact: ssl.error,
      });
    }
  }

  // 6. Redirect Chain Analysis
  if (urlscan?.redirectChain && urlscan.redirectChain.length > 2) {
    const hops = urlscan.redirectChain.length - 1;
    const penalty = -15;
    score += penalty;
    threatCategories.add('Multiple Redirection Hops');
    deductions.push({
      source: 'Redirect Chain Inspector',
      reason: `Chain contains ${hops} intermediate redirects`,
      penalty,
      severity: 'Medium',
      impact: 'Deep redirect chains are often used to evade automated web crawlers',
    });
  }

  // Clamp score between 0 and 100
  const finalScore = Math.max(0, Math.min(100, Math.round(score)));

  // Determine Verdict
  let verdict = 'Safe';
  if (finalScore < 50) {
    verdict = 'Malicious';
  } else if (finalScore < 80) {
    verdict = 'Suspicious';
  }

  // Final primary threat category
  const threatCategoryList = Array.from(threatCategories);
  const primaryThreatCategory = threatCategoryList.length > 0 ? threatCategoryList[0] : (verdict === 'Safe' ? 'Clean Infrastructure' : 'Low Confidence Anomaly');

  return {
    trustScore: finalScore,
    verdict,
    threatCategory: primaryThreatCategory,
    threatCategories: threatCategoryList,
    deductions,
    baseScore: 100,
    scoringMethodology: 'Transparent Weighted Multi-Signal Security Matrix',
  };
}
