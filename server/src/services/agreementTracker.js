import { runQuery, queryAll, queryOne } from '../db/database.js';

/**
 * Normalizes verdicts to standard category: 'safe' | 'suspicious' | 'malicious'
 */
function normalizeVerdict(verdict) {
  if (!verdict) return 'safe';
  const v = verdict.toLowerCase();
  if (v.includes('malic') || v.includes('phish') || v.includes('harmful') || v.includes('threat')) return 'malicious';
  if (v.includes('susp') || v.includes('warn') || v.includes('elevated')) return 'suspicious';
  return 'safe';
}

/**
 * Logs engine comparison and calculates majority agreement.
 */
export async function logEngineAgreement({
  scanId,
  inputType = 'url',
  threatlensVerdict,
  gsbVerdict,
  vtVerdict,
  phishtankVerdict,
}) {
  try {
    const tlNorm = normalizeVerdict(threatlensVerdict);
    const gsbNorm = normalizeVerdict(gsbVerdict);
    const vtNorm = normalizeVerdict(vtVerdict);
    const ptNorm = normalizeVerdict(phishtankVerdict);

    // External engines array
    const externalVotes = [gsbNorm, vtNorm, ptNorm];

    // Determine majority verdict among external engines
    const voteCounts = { safe: 0, suspicious: 0, malicious: 0 };
    for (const vote of externalVotes) {
      if (voteCounts[vote] !== undefined) {
        voteCounts[vote]++;
      }
    }

    let majorityVerdict = 'safe';
    let maxVotes = 0;
    for (const [v, count] of Object.entries(voteCounts)) {
      if (count > maxVotes) {
        maxVotes = count;
        majorityVerdict = v;
      }
    }

    // ThreatLens matches majority if normalizations align
    // Or if both agree it is non-safe (suspicious / malicious)
    const isMajorityAgreement = (tlNorm === majorityVerdict ||
      (tlNorm !== 'safe' && majorityVerdict !== 'safe')) ? 1 : 0;

    await runQuery(
      `INSERT INTO engine_agreements (scan_id, input_type, threatlens_verdict, gsb_verdict, vt_verdict, phishtank_verdict, is_majority_agreement)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [scanId, inputType, threatlensVerdict, gsbVerdict, vtVerdict, phishtankVerdict, isMajorityAgreement]
    );

    return isMajorityAgreement === 1;
  } catch (err) {
    console.error('[Agreement Tracker Error]:', err.message);
    return false;
  }
}

/**
 * Fetches cumulative agreement rate and engine breakdown statistics.
 */
export async function getAgreementStats() {
  try {
    const totals = await queryOne(`
      SELECT 
        COUNT(*) as total_comparisons,
        SUM(is_majority_agreement) as total_agreements
      FROM engine_agreements
    `);

    const total = totals?.total_comparisons || 0;
    const agreements = totals?.total_agreements || 0;
    const agreementRate = total > 0 ? Math.round((agreements / total) * 100) : 100;

    // Recent 10 agreement logs for HUD stream
    const recentLogs = await queryAll(`
      SELECT scan_id, input_type, threatlens_verdict, is_majority_agreement, timestamp
      FROM engine_agreements
      ORDER BY id DESC
      LIMIT 10
    `);

    return {
      totalComparisons: total,
      totalAgreements: agreements,
      agreementRate: agreementRate,
      disclaimer: 'Measures consistency and alignment with external security scanning engines (Google Safe Browsing, VirusTotal, PhishTank), not absolute ground-truth accuracy.',
      recentLogs: recentLogs || [],
    };
  } catch (err) {
    console.error('[Get Agreement Stats Error]:', err.message);
    return {
      totalComparisons: 0,
      totalAgreements: 0,
      agreementRate: 100,
      disclaimer: 'Engine agreement statistics initializing.',
      recentLogs: [],
    };
  }
}
