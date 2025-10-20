-- Idempotent base tables for the SOC project
PRAGMA foreign_keys = ON;

-- Raw Wazuh/Suricata alerts (minimal cols; expand as needed)
CREATE TABLE IF NOT EXISTS alerts (
  id               INTEGER PRIMARY KEY,
  ts               TEXT NOT NULL,          -- ISO8601
  src_ip           TEXT,
  dst_ip           TEXT,
  src_port         INTEGER,
  dst_port         INTEGER,
  proto            TEXT,
  rule_id          INTEGER,
  rule_level       INTEGER,
  category         TEXT,                   -- e.g., "suricata", "wazuh"
  raw              TEXT                    -- raw JSON if you store it
);

-- Enriched alerts (derived features)
CREATE TABLE IF NOT EXISTS alerts_enriched (
  alert_id         INTEGER PRIMARY KEY,
  ts_hour          TEXT,                   -- e.g., hour bucket
  src_hourly_count INTEGER,
  pair_hourly_count INTEGER,
  src_distinct_dstport_hour INTEGER,
  proto_code       INTEGER,
  CONSTRAINT fk_alerts FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

-- Model scores (RF)
CREATE TABLE IF NOT EXISTS wz_scores_rf (
  alert_id         INTEGER PRIMARY KEY,
  score            REAL NOT NULL,          -- calibrated probability
  risk_bucket      TEXT,                   -- Critical/High/Medium/Low
  created_at       TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

-- Model scores (BRF)
CREATE TABLE IF NOT EXISTS wz_scores_brf (
  alert_id         INTEGER PRIMARY KEY,
  score            REAL NOT NULL,
  risk_bucket      TEXT,
  created_at       TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

-- “Interface” table your dashboard/API reads (either RF or BRF published here)
CREATE TABLE IF NOT EXISTS wz_scores_if (
  alert_id         INTEGER PRIMARY KEY,
  score            REAL NOT NULL,
  model            TEXT NOT NULL,          -- 'rf' or 'brf'
  risk_bucket      TEXT,
  published_at     TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

-- Survey responses (if you collect analyst data)
CREATE TABLE IF NOT EXISTS survey_responses (
  id               INTEGER PRIMARY KEY,
  analyst_id       TEXT NOT NULL,
  submitted_at     TEXT DEFAULT (datetime('now')),
  trust_ai         INTEGER,                -- example fields
  cognitive_style  TEXT
);

-- MITRE lookup (id -> name/desc) if you need it
CREATE TABLE IF NOT EXISTS mitre_lookup (
  tactic_id        TEXT PRIMARY KEY,
  tactic_name      TEXT,
  tactic_desc      TEXT
);

-- Field map (for feature engineering metadata)
CREATE TABLE IF NOT EXISTS field_map (
  field_name       TEXT PRIMARY KEY,
  source           TEXT,                   -- wazuh/suricata/derived
  dtype            TEXT,
  description      TEXT
);

-- Trained model registry (metadata only; binaries tracked via LFS/releases)
CREATE TABLE IF NOT EXISTS ml_models (
  id               INTEGER PRIMARY KEY,
  model_name       TEXT NOT NULL,          -- 'rf' or 'brf'
  version          TEXT NOT NULL,          -- 'v1', '2025-10-20', etc.
  trained_at       TEXT DEFAULT (datetime('now')),
  features_json    TEXT,                   -- list of feature names
  params_json      TEXT                    -- model hyperparams
);

-- Indices (speed up common queries)
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts(dst_ip);
CREATE INDEX IF NOT EXISTS idx_scores_if_bucket ON wz_scores_if(risk_bucket);
