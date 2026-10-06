import axios from 'axios';

/**
 * Checks a URL against Google Safe Browsing Lookup API v4.
 * Falls back gracefully to heuristic inspection if no key is configured or on network error.
 */
export async function checkGoogleSafeBrowsing(targetUrl) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (apiKey && apiKey.trim() !== '') {
    try {
      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey.trim()}`;
      const payload = {
        client: {
          clientId: 'threatlens-intel',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: targetUrl }],
        },
      };

      const response = await axios.post(endpoint, payload, { timeout: 6000 });
      const matches = response.data?.matches || [];

      if (matches.length > 0) {
        const threatType = matches[0].threatType;
        return {
          available: true,
          status: 'malicious',
          verdict: 'Malicious',
          threatType: threatType,
          description: `Flagged as ${threatType.replace(/_/g, ' ')} by Google Safe Browsing`,
          source: 'Google Safe Browsing v4 (Live API)',
          details: matches,
        };
      }

      return {
        available: true,
        status: 'safe',
        verdict: 'Safe',
        threatType: null,
        description: 'No threat matches found in Google Safe Browsing database',
        source: 'Google Safe Browsing v4 (Live API)',
        details: [],
      };
    } catch (err) {
      console.warn(`[GSB API Warning] ${err.response?.data?.error?.message || err.message}. Falling back to heuristic engine.`);
      // Proceed to fallback
    }
  }

  // Graceful Heuristic Fallback
  return fallbackSafeBrowsingCheck(targetUrl);
}

function fallbackSafeBrowsingCheck(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    const host = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();

    // Known test malware/phishing domains and common attack patterns
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    const hasPhishKeywords = /(login|verify|secure|account|update|banking|paypal|appleid|support|wallet)/.test(host) &&
      !/(google\.com|paypal\.com|apple\.com|microsoft\.com|chase\.com|amazon\.com)$/.test(host);
    const suspiciousTld = /\.(xyz|top|work|click|loan|gq|cf|tk|ml|ga|rest|buzz|cam)$/i.test(host);
    const isTestMalware = /(testsafebrowsing\.appspot\.com|malware|phishing-test|evil-test)/i.test(host + pathname);

    if (isTestMalware || (isIpHost && hasPhishKeywords)) {
      return {
        available: true,
        isFallback: true,
        status: 'malicious',
        verdict: 'Malicious',
        threatType: 'SOCIAL_ENGINEERING',
        description: 'Simulated detection: High-confidence credential harvesting pattern detected',
        source: 'Google Safe Browsing (Heuristic Engine - API Key Missing)',
        details: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM' }],
      };
    }

    if (suspiciousTld && hasPhishKeywords) {
      return {
        available: true,
        isFallback: true,
        status: 'suspicious',
        verdict: 'Suspicious',
        threatType: 'POTENTIAL_PHISHING',
        description: 'Suspicious domain pattern matching deceptive credential harvesting TLD',
        source: 'Google Safe Browsing (Heuristic Engine - API Key Missing)',
        details: [],
      };
    }

    return {
      available: true,
      isFallback: true,
      status: 'safe',
      verdict: 'Safe',
      threatType: null,
      description: 'No deceptive signature detected (Live API key not provided; evaluated via pattern heuristics)',
      source: 'Google Safe Browsing (Heuristic Engine - API Key Missing)',
      details: [],
    };
  } catch (err) {
    return {
      available: false,
      status: 'unknown',
      verdict: 'Data Unavailable',
      threatType: null,
      description: 'Could not evaluate URL syntax',
      source: 'Google Safe Browsing',
    };
  }
}
