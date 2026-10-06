import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import db, { runQuery, queryAll, queryOne } from './db/database.js';
import { sanitizeAndValidateUrl } from './utils/urlValidator.js';
import { checkGoogleSafeBrowsing } from './services/googleSafeBrowsing.js';
import { checkVirusTotal } from './services/virusTotal.js';
import { checkPhishTank } from './services/phishTank.js';
import { checkUrlScan } from './services/urlscan.js';
import { checkWhois } from './services/whoisService.js';
import { checkSslCertificate } from './services/sslService.js';
import { analyzePhoneNumber } from './services/phoneService.js';
import { analyzeEmail } from './services/emailService.js';
import { calculateUrlTrustScore } from './utils/trustScore.js';
import { logEngineAgreement, getAgreementStats } from './services/agreementTracker.js';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Global Rate Limiter: max 120 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  message: {
    success: false,
    error: 'Rate limit exceeded. Please wait a few moments before submitting more scans.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', globalLimiter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    version: '1.0.0',
    platform: 'ThreatLens Intel Engine',
    timestamp: new Date().toISOString(),
  });
});

/**
 * Auto-detect input type: 'url' | 'phone' | 'email'
 */
function detectInputType(input) {
  const str = input.trim();
  // Phone: starts with + or contains digits and dashes/spaces/parentheses
  if (/^(\+?\d{1,4}[-.\s]?)?(\(?\d{1,4}\)?[-.\s]?)?[\d\s-]{6,16}$/.test(str) && /\d{6,}/.test(str.replace(/\D/g, '')) && !str.includes('@') && !str.includes('.')) {
    return 'phone';
  }
  // Email: contains @ and domain dot
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str)) {
    return 'email';
  }
  // Default to URL
  return 'url';
}

/**
 * Unified Scan Pipeline: POST /api/scan
 */
app.post('/api/scan', async (req, res, next) => {
  try {
    const { input, type = 'auto', defaultCountry = 'US' } = req.body;
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ success: false, error: 'Please enter a target to scan.' });
    }

    const detectedType = type === 'auto' ? detectInputType(input) : type;
    const scanId = 'tl_' + crypto.randomBytes(6).toString('hex');
    const timestamp = new Date().toISOString();

    // 1. PHONE NUMBER PIPELINE
    if (detectedType === 'phone') {
      const phoneResult = await analyzePhoneNumber(input, defaultCountry);
      const scanRecord = {
        id: scanId,
        input_value: phoneResult.phoneNumber,
        input_type: 'phone',
        trust_score: phoneResult.trustScore,
        verdict: phoneResult.verdict,
        threat_category: phoneResult.isVoip ? 'VOIP / Burner Risk' : 'Telecom Infrastructure',
        signals_json: JSON.stringify(phoneResult),
        external_verdicts_json: JSON.stringify({
          telecomValidation: phoneResult.verdict,
          carrier: phoneResult.carrier,
          lineType: phoneResult.lineType,
        }),
        metadata_json: JSON.stringify({
          country: phoneResult.country,
          carrier: phoneResult.carrier,
          lineType: phoneResult.lineType,
          paidTierNote: phoneResult.paidTierNote,
        }),
      };

      await runQuery(
        `INSERT INTO scans (id, input_value, input_type, trust_score, verdict, threat_category, signals_json, external_verdicts_json, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [scanRecord.id, scanRecord.input_value, scanRecord.input_type, scanRecord.trust_score, scanRecord.verdict, scanRecord.threat_category, scanRecord.signals_json, scanRecord.external_verdicts_json, scanRecord.metadata_json, timestamp]
      );

      return res.json({
        success: true,
        scanId,
        input: phoneResult.phoneNumber,
        inputType: 'phone',
        trustScore: phoneResult.trustScore,
        verdict: phoneResult.verdict,
        threatCategory: scanRecord.threat_category,
        timestamp,
        report: phoneResult,
      });
    }

    // 2. EMAIL ADDRESS PIPELINE
    if (detectedType === 'email') {
      const emailResult = await analyzeEmail(input);
      const scanRecord = {
        id: scanId,
        input_value: emailResult.email,
        input_type: 'email',
        trust_score: emailResult.trustScore,
        verdict: emailResult.verdict,
        threat_category: emailResult.isDisposable ? 'Disposable Burner Mail' : (emailResult.hasValidMx ? 'Legitimate Mail Domain' : 'Missing MX / Spoofing Risk'),
        signals_json: JSON.stringify(emailResult),
        external_verdicts_json: JSON.stringify({
          mxVerification: emailResult.hasValidMx ? 'Valid' : 'Invalid',
          burnerCheck: emailResult.isDisposable ? 'Flagged' : 'Clean',
        }),
        metadata_json: JSON.stringify({
          domain: emailResult.domain,
          mxCount: emailResult.mxCount,
        }),
      };

      await runQuery(
        `INSERT INTO scans (id, input_value, input_type, trust_score, verdict, threat_category, signals_json, external_verdicts_json, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [scanRecord.id, scanRecord.input_value, scanRecord.input_type, scanRecord.trust_score, scanRecord.verdict, scanRecord.threat_category, scanRecord.signals_json, scanRecord.external_verdicts_json, scanRecord.metadata_json, timestamp]
      );

      return res.json({
        success: true,
        scanId,
        input: emailResult.email,
        inputType: 'email',
        trustScore: emailResult.trustScore,
        verdict: emailResult.verdict,
        threatCategory: scanRecord.threat_category,
        timestamp,
        report: emailResult,
      });
    }

    // 3. URL PIPELINE (Default & QR Decoded URLs)
    const { normalizedUrl, hostname, protocol } = sanitizeAndValidateUrl(input);

    // Run all intelligence feeds concurrently with safe fallback guards
    const [gsbSettled, vtSettled, ptSettled, usSettled, whoisSettled, sslSettled] = await Promise.allSettled([
      checkGoogleSafeBrowsing(normalizedUrl),
      checkVirusTotal(normalizedUrl),
      checkPhishTank(normalizedUrl),
      checkUrlScan(normalizedUrl, hostname),
      checkWhois(hostname),
      checkSslCertificate(hostname, protocol === 'http:' ? 80 : 443),
    ]);

    const googleSafeBrowsing = gsbSettled.status === 'fulfilled' ? gsbSettled.value : { available: false, verdict: 'Unavailable' };
    const virusTotal = vtSettled.status === 'fulfilled' ? vtSettled.value : { available: false, verdict: 'Unavailable' };
    const phishTank = ptSettled.status === 'fulfilled' ? ptSettled.value : { available: false, verdict: 'Unavailable' };
    const urlscan = usSettled.status === 'fulfilled' ? usSettled.value : { available: false, redirectChain: [{ url: normalizedUrl }] };
    const whois = whoisSettled.status === 'fulfilled' ? whoisSettled.value : { available: false, ageDays: 365 };
    const ssl = sslSettled.status === 'fulfilled' ? sslSettled.value : { available: false, valid: false };

    // Calculate Trust Score and transparent deductions
    const trustAnalysis = calculateUrlTrustScore({
      googleSafeBrowsing,
      virusTotal,
      phishTank,
      urlscan,
      whois,
      ssl,
    });

    // Comparative engine breakdown
    const externalVerdicts = {
      threatlens: trustAnalysis.verdict,
      googleSafeBrowsing: googleSafeBrowsing.verdict || 'Unavailable',
      virusTotal: virusTotal.verdict || 'Unavailable',
      phishTank: phishTank.verdict || 'Unavailable',
    };

    // Log agreement in SQLite
    const agreedWithMajority = await logEngineAgreement({
      scanId,
      inputType: 'url',
      threatlensVerdict: trustAnalysis.verdict,
      gsbVerdict: googleSafeBrowsing.verdict,
      vtVerdict: virusTotal.verdict,
      phishtankVerdict: phishTank.verdict,
    });

    const metadata = {
      hostname,
      protocol,
      domainAgeDays: whois.ageDays,
      registrar: whois.registrar,
      country: whois.country || urlscan.country || 'Global',
      screenshotUrl: urlscan.screenshotUrl,
      redirectChain: urlscan.redirectChain || [{ url: normalizedUrl, status: 200 }],
      finalUrl: urlscan.finalUrl || normalizedUrl,
      sslIssuer: ssl.issuer,
      sslDaysRemaining: ssl.daysRemaining,
      sslValid: ssl.valid,
      ip: urlscan.ip,
      asn: urlscan.asn,
    };

    const signals = {
      googleSafeBrowsing,
      virusTotal,
      phishTank,
      urlscan,
      whois,
      ssl,
    };

    // Persist scan in SQLite
    await runQuery(
      `INSERT INTO scans (id, input_value, input_type, trust_score, verdict, threat_category, signals_json, external_verdicts_json, metadata_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        scanId,
        normalizedUrl,
        'url',
        trustAnalysis.trustScore,
        trustAnalysis.verdict,
        trustAnalysis.threatCategory,
        JSON.stringify(signals),
        JSON.stringify(externalVerdicts),
        JSON.stringify(metadata),
        timestamp,
      ]
    );

    return res.json({
      success: true,
      scanId,
      input: normalizedUrl,
      inputType: 'url',
      trustScore: trustAnalysis.trustScore,
      verdict: trustAnalysis.verdict,
      threatCategory: trustAnalysis.threatCategory,
      threatCategories: trustAnalysis.threatCategories,
      deductions: trustAnalysis.deductions,
      signals,
      externalVerdicts,
      agreedWithMajority,
      metadata,
      timestamp,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * Scan History Endpoint: GET /api/scans
 */
app.get('/api/scans', async (req, res, next) => {
  try {
    const { search, verdict, type, limit = 50 } = req.query;
    let query = `SELECT * FROM scans WHERE 1=1`;
    const params = [];

    if (search) {
      query += ` AND input_value LIKE ?`;
      params.push(`%${search}%`);
    }
    if (verdict && verdict !== 'all') {
      query += ` AND LOWER(verdict) = LOWER(?)`;
      params.push(verdict);
    }
    if (type && type !== 'all') {
      query += ` AND input_type = ?`;
      params.push(type);
    }

    query += ` ORDER BY created_at DESC LIMIT ?`;
    params.push(Number(limit));

    const rows = await queryAll(query, params);
    const parsedRows = rows.map((r) => ({
      ...r,
      signals: JSON.parse(r.signals_json || '{}'),
      external_verdicts: JSON.parse(r.external_verdicts_json || '{}'),
      metadata: JSON.parse(r.metadata_json || '{}'),
    }));

    res.json({ success: true, count: parsedRows.length, scans: parsedRows });
  } catch (err) {
    next(err);
  }
});

/**
 * Single Scan by ID: GET /api/scans/:id
 */
app.get('/api/scans/:id', async (req, res, next) => {
  try {
    const row = await queryOne(`SELECT * FROM scans WHERE id = ?`, [req.params.id]);
    if (!row) {
      return res.status(404).json({ success: false, error: 'Scan record not found.' });
    }

    res.json({
      success: true,
      scan: {
        ...row,
        signals: JSON.parse(row.signals_json || '{}'),
        external_verdicts: JSON.parse(row.external_verdicts_json || '{}'),
        metadata: JSON.parse(row.metadata_json || '{}'),
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * Clear History: DELETE /api/scans
 */
app.delete('/api/scans', async (req, res, next) => {
  try {
    await runQuery(`DELETE FROM scans`);
    await runQuery(`DELETE FROM engine_agreements`);
    res.json({ success: true, message: 'Scan history successfully cleared.' });
  } catch (err) {
    next(err);
  }
});

/**
 * Engine Agreement Stats: GET /api/stats/agreement
 */
app.get('/api/stats/agreement', async (req, res, next) => {
  try {
    const stats = await getAgreementStats();
    res.json({ success: true, stats });
  } catch (err) {
    next(err);
  }
});

/**
 * Overall Platform Stats: GET /api/stats/summary
 */
app.get('/api/stats/summary', async (req, res, next) => {
  try {
    const counts = await queryOne(`
      SELECT 
        COUNT(*) as total_scans,
        SUM(CASE WHEN LOWER(verdict) = 'safe' THEN 1 ELSE 0 END) as safe_count,
        SUM(CASE WHEN LOWER(verdict) = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
        SUM(CASE WHEN LOWER(verdict) = 'malicious' THEN 1 ELSE 0 END) as malicious_count,
        AVG(trust_score) as avg_trust_score
      FROM scans
    `);

    const agreement = await getAgreementStats();

    res.json({
      success: true,
      stats: {
        totalScans: counts?.total_scans || 0,
        safeCount: counts?.safe_count || 0,
        suspiciousCount: counts?.suspicious_count || 0,
        maliciousCount: counts?.malicious_count || 0,
        avgTrustScore: Math.round(counts?.avg_trust_score || 88),
        agreementRate: agreement.agreementRate,
        disclaimer: agreement.disclaimer,
      },
    });
  } catch (err) {
    next(err);
  }
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error('[ThreatLens Server Error]:', err.message);
  res.status(400).json({
    success: false,
    error: err.message || 'Scan evaluation error occurred.',
  });
});

app.listen(PORT, () => {
  console.log(`[ThreatLens] Engine listening on http://localhost:${PORT}`);
});
