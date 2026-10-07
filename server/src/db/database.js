import sqlite3 from 'sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.VERCEL ? '/tmp' : path.join(__dirname, '../../data');

if (!process.env.VERCEL && !fs.existsSync(dataDir)) {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
  } catch {}
}

const dbPath = process.env.VERCEL ? ':memory:' : path.join(dataDir, 'threatlens.db');

// In-memory mock store fallback in case SQLite binary fails in serverless environments
const inMemoryStore = {
  scans: [],
  agreements: []
};

let db = null;
let useMemoryFallback = false;

try {
  db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.warn('[Database] SQLite unavailable, using in-memory mock store:', err.message);
      useMemoryFallback = true;
    } else {
      console.log(`[Database] SQLite connected at ${dbPath}`);
    }
  });

  if (db) {
    db.serialize(() => {
      db.run(`
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          input_value TEXT NOT NULL,
          input_type TEXT NOT NULL,
          trust_score INTEGER NOT NULL,
          verdict TEXT NOT NULL,
          threat_category TEXT,
          signals_json TEXT NOT NULL,
          external_verdicts_json TEXT NOT NULL,
          metadata_json TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS engine_agreements (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id TEXT NOT NULL,
          input_type TEXT NOT NULL,
          threatlens_verdict TEXT NOT NULL,
          gsb_verdict TEXT,
          vt_verdict TEXT,
          phishtank_verdict TEXT,
          is_majority_agreement INTEGER NOT NULL,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
      `);
    });
  }
} catch (e) {
  console.warn('[Database] Failed to initialize SQLite, falling back to memory store:', e.message);
  useMemoryFallback = true;
}

export const queryAll = (sql, params = []) => {
  if (useMemoryFallback || !db) {
    if (sql.includes('FROM scans')) {
      return Promise.resolve(inMemoryStore.scans);
    }
    if (sql.includes('FROM engine_agreements')) {
      return Promise.resolve(inMemoryStore.agreements.slice(-10).reverse());
    }
    return Promise.resolve([]);
  }

  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) resolve([]);
      else resolve(rows || []);
    });
  });
};

export const queryOne = (sql, params = []) => {
  if (useMemoryFallback || !db) {
    if (sql.includes('FROM scans')) {
      const scans = inMemoryStore.scans;
      const total = scans.length;
      const safe = scans.filter(s => s.verdict?.toLowerCase() === 'safe').length;
      const susp = scans.filter(s => s.verdict?.toLowerCase() === 'suspicious').length;
      const mal = scans.filter(s => s.verdict?.toLowerCase() === 'malicious').length;
      const avg = total > 0 ? scans.reduce((a, b) => a + (b.trust_score || 0), 0) / total : 88;
      return Promise.resolve({
        total_scans: total,
        safe_count: safe,
        suspicious_count: susp,
        malicious_count: mal,
        avg_trust_score: avg
      });
    }
    if (sql.includes('FROM engine_agreements')) {
      const agreements = inMemoryStore.agreements;
      const total = agreements.length;
      const count = agreements.filter(a => a.is_majority_agreement === 1).length;
      return Promise.resolve({
        total_comparisons: total,
        total_agreements: count
      });
    }
    return Promise.resolve(null);
  }

  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) resolve(null);
      else resolve(row || null);
    });
  });
};

export const runQuery = (sql, params = []) => {
  if (useMemoryFallback || !db) {
    if (sql.includes('INSERT INTO scans')) {
      inMemoryStore.scans.unshift({
        id: params[0],
        input_value: params[1],
        input_type: params[2],
        trust_score: params[3],
        verdict: params[4],
        threat_category: params[5],
        signals_json: params[6],
        external_verdicts_json: params[7],
        metadata_json: params[8],
        created_at: new Date().toISOString()
      });
    } else if (sql.includes('INSERT INTO engine_agreements')) {
      inMemoryStore.agreements.push({
        id: inMemoryStore.agreements.length + 1,
        scan_id: params[0],
        input_type: params[1],
        threatlens_verdict: params[2],
        gsb_verdict: params[3],
        vt_verdict: params[4],
        phishtank_verdict: params[5],
        is_majority_agreement: params[6],
        timestamp: new Date().toISOString()
      });
    } else if (sql.includes('DELETE FROM scans')) {
      inMemoryStore.scans = [];
    } else if (sql.includes('DELETE FROM engine_agreements')) {
      inMemoryStore.agreements = [];
    }
    return Promise.resolve({ lastID: 1, changes: 1 });
  }

  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) resolve({ lastID: 0, changes: 0 });
      else resolve({ lastID: this?.lastID || 0, changes: this?.changes || 0 });
    });
  });
};

export default db;
