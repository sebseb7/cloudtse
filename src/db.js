import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { config } from "./config.js";
import { normalizeTseSerial } from "./tse-response.js";

mkdirSync(dirname(config.dbPath), { recursive: true });

const db = new Database(config.dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS clients (
    serial_number TEXT PRIMARY KEY,
    registered_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'REGISTERED',
    type_of_system TEXT,
    meta_json TEXT
  );

  CREATE TABLE IF NOT EXISTS transactions (
    transaction_number INTEGER PRIMARY KEY,
    client_id TEXT NOT NULL,
    external_transaction_id TEXT,
    process_type TEXT NOT NULL DEFAULT '',
    process_data TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    time_start TEXT NOT NULL,
    time_end TEXT,
    signature_counter INTEGER NOT NULL,
    signature_value TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_transactions_state
    ON transactions(state);
  CREATE INDEX IF NOT EXISTS idx_transactions_client
    ON transactions(client_id);

  CREATE TABLE IF NOT EXISTS oauth_tokens (
    token TEXT PRIMARY KEY,
    client_serial TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT
  );
`);

const defaults = {
  signature_counter: "0",
  transaction_counter: "0",
  created_at: new Date().toISOString(),
  tse_serial: normalizeTseSerial(config.tseSerial),
};

const upsertSetting = db.prepare(`
  INSERT INTO settings (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO NOTHING
`);

for (const [key, value] of Object.entries(defaults)) {
  upsertSetting.run(key, value);
}

// Fix legacy non-hex serial stored from earlier simulator versions.
const storedSerial = db.prepare("SELECT value FROM settings WHERE key = 'tse_serial'").get();
if (storedSerial && !/^[0-9A-Fa-f]{32,}$/.test(storedSerial.value)) {
  setSetting("tse_serial", normalizeTseSerial(config.tseSerial));
}

export function getSetting(key, fallback = null) {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  return row?.value ?? fallback;
}

export function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, String(value));
}

export function incrementCounter(key) {
  return db.transaction(() => {
    const current = Number(getSetting(key, "0"));
    const next = current + 1;
    setSetting(key, next);
    return next;
  })();
}

const insertToken = db.prepare(`
  INSERT OR REPLACE INTO oauth_tokens (token, client_serial, issued_at, expires_at)
  VALUES (?, ?, ?, ?)
`);

const getToken = db.prepare(`
  SELECT client_serial, issued_at, expires_at FROM oauth_tokens WHERE token = ?
`);

export function saveOAuthToken(token, clientSerial, expiresInSeconds = 86400) {
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();
  insertToken.run(token, clientSerial ?? "unknown", issuedAt, expiresAt);
}

export function loadOAuthToken(token) {
  const row = getToken.get(token);
  if (!row) return null;
  if (row.expires_at && new Date(row.expires_at) < new Date()) return null;
  return { clientSerial: row.client_serial, issuedAt: row.issued_at };
}

export { db };
