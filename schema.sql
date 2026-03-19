-- Finance OS — Cloudflare D1 Schema
-- Run with: wrangler d1 execute finance-os-db --file=schema.sql --remote

-- Single-user auth (singleton row, id always = 1)
CREATE TABLE IF NOT EXISTS auth (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  salt TEXT NOT NULL,   -- hex-encoded 16-byte random salt
  hash TEXT NOT NULL    -- hex-encoded PBKDF2-SHA256 32-byte hash (310k iterations)
);

-- Individual expense entries (relational so we can query by month_key)
CREATE TABLE IF NOT EXISTS expenses (
  id           TEXT PRIMARY KEY,  -- JS Date.now() cast to TEXT
  month_key    TEXT NOT NULL,     -- "YYYY-MM" e.g. "2026-03"
  cat          TEXT NOT NULL,     -- bills|food|travel|petrol|emi|sip|subs|iphone|shopping|health|entertainment|other
  amt          REAL NOT NULL,
  note         TEXT NOT NULL DEFAULT '',
  ts           TEXT NOT NULL,     -- ISO 8601 creation timestamp
  confirmed_at TEXT               -- ISO 8601, NULL means it arrived directly (not via pending)
);
CREATE INDEX IF NOT EXISTS idx_expenses_month ON expenses(month_key);

-- Settings and pending queue stored as JSON blobs (singleton row, id always = 1)
CREATE TABLE IF NOT EXISTS app_state (
  id       INTEGER PRIMARY KEY CHECK (id = 1),
  settings TEXT NOT NULL DEFAULT '{}',  -- JSON object
  pending  TEXT NOT NULL DEFAULT '[]'   -- JSON array
);
