import sqlite3 from 'sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, '../../data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'threatlens.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to open SQLite database:', err.message);
  } else {
    console.log(`[Database] SQLite connected at ${dbPath}`);
  }
});

// Initialize Schema
db.serialize(() => {
  // Scans history table
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

  // Engine agreement logs table
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

// Promisified DB helpers
export const queryAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

export const queryOne = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

export const runQuery = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

export default db;
