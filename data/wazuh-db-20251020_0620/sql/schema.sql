CREATE TABLE suri_events (
  id INTEGER PRIMARY KEY,         -- local autoincrement
  timestamp TEXT,
  severity INTEGER,               -- Suricata: 1=high,2=med,3=low
  signature_id TEXT,
  signature TEXT,
  src_ip TEXT,
  src_port INTEGER,
  dest_ip TEXT,
  dest_port INTEGER,
  proto TEXT,
  event_type TEXT,                -- "alert", "dns", ...
  raw_json TEXT                   -- full EVE line for future features
);
CREATE TABLE alert_scores (
  id INTEGER PRIMARY KEY,         -- matches suri_events.id
  risk_score REAL NOT NULL,       -- 0..1
  risk_bucket TEXT NOT NULL,      -- Critical/High/Medium/Low
  scored_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE triage_labels (
  id INTEGER PRIMARY KEY,         -- matches suri_events.id
  is_important INTEGER            -- 1 or 0
);
CREATE TABLE wazuh_events (
        _index TEXT,
        _id TEXT PRIMARY KEY,
        _version INTEGER,
        timestamp TEXT,
        agent_ip TEXT,
        agent_name TEXT,
        agent_id TEXT,
        manager_name TEXT,
        srcip TEXT,
        dstip TEXT,
        data_id TEXT,
        rule_firedtimes INTEGER,
        rule_mail BOOLEAN,
        rule_level INTEGER,
        rule_description TEXT,
        rule_groups TEXT,
        rule_id TEXT,
        location TEXT,
        decoder_parent TEXT,
        decoder_name TEXT,
        alert_id TEXT,
        full_log TEXT,
        raw_timestamp TEXT,
        sort INTEGER,
        srcport TEXT,
        dstport TEXT,
        proto TEXT
    );
CREATE INDEX idx_wz_ts    ON wazuh_events(timestamp);
CREATE INDEX idx_wz_level ON wazuh_events(rule_level);
CREATE INDEX idx_wz_srcip ON wazuh_events(srcip);
CREATE INDEX idx_wz_dstip ON wazuh_events(dstip);
CREATE TABLE wz_scores (
  id TEXT PRIMARY KEY,
  risk_score  REAL NOT NULL,
  risk_bucket TEXT NOT NULL,
  scored_at   TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE ml_features(
  id TEXT,
  rule_level,
  dst_port INT,
  is_suricata,
  is_ssh,
  is_nmap,
  kw_malware,
  kw_exploit,
  kw_brute,
  kw_ransom,
  kw_shellcode,
  proto_code,
  hour INT,
  src_private,
  dst_private
, src_hourly_count INTEGER DEFAULT 0, src_distinct_dstport_hour INTEGER DEFAULT 0, pair_hourly_count INTEGER DEFAULT 0, len_rule_desc INTEGER, flag_nmap INTEGER, flag_brute INTEGER, flag_ssh INTEGER, flag_http INTEGER, flag_dns INTEGER, src_port INTEGER, proto TEXT, timestamp TEXT, "rule_description" TEXT, "rule_id"          TEXT, "agent_ip"         TEXT, "agent_name"       TEXT, "agent_id"         TEXT, "srcip"            TEXT, "dstip"            TEXT, "srcport"          TEXT, "dstport"          TEXT, "location"         TEXT, "decoder_name"     TEXT, "decoder_parent"   TEXT, "source_ip"        TEXT, "destination_ip"   TEXT, "is_brute" INTEGER DEFAULT 0, "is_scan" INTEGER DEFAULT 0, "is_dns" INTEGER DEFAULT 0, "is_https" INTEGER DEFAULT 0, is_http INTEGER DEFAULT 0);
CREATE INDEX idx_mlf_id ON ml_features(id);
CREATE VIEW alerts_api AS
SELECT
  _id AS id,
  rule_level,
  rule_description,
  srcip AS source_ip,
  COALESCE(NULLIF(dstip,''), NULLIF(agent_ip,''), agent_name) AS destination_ip,
  timestamp
FROM wazuh_events
/* alerts_api(id,rule_level,rule_description,source_ip,destination_ip,timestamp) */;
CREATE INDEX idx_we_ts       ON wazuh_events(timestamp);
CREATE TABLE sqlite_stat1(tbl,idx,stat);
CREATE TABLE wz_scores_if_backup_20250926013617(
  id TEXT,
  risk_score REAL,
  risk_bucket TEXT,
  scored_at TEXT
);
CREATE INDEX idx_ml_features_id ON ml_features(id);
CREATE TABLE model_metrics (
            model        TEXT PRIMARY KEY,
            trained_at   TEXT,
            auc          REAL,
            ap           REAL,
            best_f1      REAL,
            best_thr     REAL,
            n_train      INTEGER,
            n_test       INTEGER,
            pos_rate_test REAL,
            features_json TEXT
        );
CREATE TABLE model_feature_importance (
            model      TEXT,
            feature    TEXT,
            importance REAL,
            trained_at TEXT,
            PRIMARY KEY(model, feature)
        );
CREATE TABLE alerts_staging (
  id TEXT PRIMARY KEY,
  rule_level INTEGER,
  rule_description TEXT,
  source_ip TEXT,
  destination_ip TEXT,
  timestamp TEXT,
  risk_score REAL,
  risk_bucket TEXT
);
CREATE TABLE alerts_inbox (
  id TEXT PRIMARY KEY,
  rule_level INTEGER,
  rule_description TEXT,
  source_ip TEXT,
  destination_ip TEXT,
  timestamp TEXT
);
CREATE INDEX idx_alerts_inbox_ts ON alerts_inbox(timestamp);
CREATE VIEW alerts_api_plus AS
SELECT id, rule_level, rule_description, source_ip, destination_ip, timestamp FROM alerts_api
UNION ALL
SELECT id, rule_level, rule_description, source_ip, destination_ip, timestamp FROM alerts_inbox
/* alerts_api_plus(id,rule_level,rule_description,source_ip,destination_ip,timestamp) */;
CREATE UNIQUE INDEX wazuh_events_id_unique ON wazuh_events(_id);
CREATE TABLE wz_scores_rf (
  id TEXT PRIMARY KEY,
  pred_proba REAL,
  pred_class INTEGER,
  actual INTEGER,
  scored_at TEXT
, score  REAL, bucket TEXT, risk_score  REAL, risk_bucket TEXT);
CREATE TABLE wz_scores_brf (
  id TEXT PRIMARY KEY,
  pred_proba REAL,
  pred_class INTEGER,
  actual INTEGER,
  scored_at TEXT
, score  REAL, bucket TEXT, risk_score  REAL, risk_bucket TEXT);
CREATE TABLE wz_scores_if (
  id TEXT PRIMARY KEY,
  pred_proba REAL,
  pred_class INTEGER,
  actual INTEGER,
  scored_at TEXT
, score  REAL, bucket TEXT, risk_score  REAL, risk_bucket TEXT);
CREATE INDEX idx_wz_scores_brf_id    ON wz_scores_brf(id);
CREATE INDEX idx_wz_scores_rf_id     ON wz_scores_rf(id);
CREATE TABLE ml_labels_v2(id TEXT,is_important);
CREATE VIEW triage_labels_text AS
SELECT CAST(id AS TEXT) AS id, is_important FROM triage_labels
/* triage_labels_text(id,is_important) */;
CREATE TABLE ml_labels_backup(id TEXT,is_important INT);
CREATE INDEX idx_ml_labels_v2_id     ON ml_labels_v2(id);
CREATE TRIGGER trg_rf_ins AFTER INSERT ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_rf_upd AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_brf_ins AFTER INSERT ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_brf_upd AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_if_ins AFTER INSERT ON wz_scores_if
BEGIN
  UPDATE wz_scores_if SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_if_upd AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_if
BEGIN
  UPDATE wz_scores_if SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE INDEX idx_wz_rf_id     ON wz_scores_rf(id);
CREATE INDEX idx_wz_brf_id    ON wz_scores_brf(id);
CREATE INDEX idx_wz_if_id     ON wz_scores_if(id);
CREATE INDEX idx_wz_rf_scored ON wz_scores_rf(scored_at);
CREATE INDEX idx_wz_brf_scored ON wz_scores_brf(scored_at);
CREATE VIEW v_scores_rf_mapped AS
SELECT id,
       COALESCE(risk_score, score, pred_proba) AS score,
       COALESCE(risk_bucket, bucket)           AS bucket,
       scored_at,
       COALESCE(actual,0)                      AS actual
FROM wz_scores_rf
/* v_scores_rf_mapped(id,score,bucket,scored_at,actual) */;
CREATE VIEW v_scores_brf_mapped AS
SELECT id,
       COALESCE(risk_score, score, pred_proba) AS score,
       COALESCE(risk_bucket, bucket)           AS bucket,
       scored_at,
       COALESCE(actual,0)                      AS actual
FROM wz_scores_brf
/* v_scores_brf_mapped(id,score,bucket,scored_at,actual) */;
CREATE VIEW v_scores_if_mapped AS
SELECT id,
       COALESCE(risk_score, score, pred_proba) AS score,
       COALESCE(risk_bucket, bucket)           AS bucket,
       scored_at
FROM wz_scores_if
/* v_scores_if_mapped(id,score,bucket,scored_at) */;
CREATE VIEW v_alerts_scored_rf AS
SELECT s.id, s.score, s.bucket, s.scored_at, s.actual,
       e.rule_id, e.rule_level, e.rule_description, e.srcip, e.dstip, e.agent_name, e.timestamp
FROM v_scores_rf_mapped s
LEFT JOIN wazuh_events e ON e._id = s.id
/* v_alerts_scored_rf(id,score,bucket,scored_at,actual,rule_id,rule_level,rule_description,srcip,dstip,agent_name,timestamp) */;
CREATE VIEW v_alerts_scored_brf AS
SELECT s.id, s.score, s.bucket, s.scored_at, s.actual,
       e.rule_id, e.rule_level, e.rule_description, e.srcip, e.dstip, e.agent_name, e.timestamp
FROM v_scores_brf_mapped s
LEFT JOIN wazuh_events e ON e._id = s.id
/* v_alerts_scored_brf(id,score,bucket,scored_at,actual,rule_id,rule_level,rule_description,srcip,dstip,agent_name,timestamp) */;
CREATE VIEW v_alerts_scored AS
SELECT 'rf'  AS model, id, score, bucket, scored_at, actual, rule_id, rule_level, rule_description, srcip, dstip, agent_name, timestamp FROM v_alerts_scored_rf
UNION ALL
SELECT 'brf' AS model, id, score, bucket, scored_at, actual, rule_id, rule_level, rule_description, srcip, dstip, agent_name, timestamp FROM v_alerts_scored_brf
/* v_alerts_scored(model,id,score,bucket,scored_at,actual,rule_id,rule_level,rule_description,srcip,dstip,agent_name,timestamp) */;
CREATE VIEW v_bucket_counts AS
SELECT bucket, COUNT(*) AS n
FROM v_scores_if_mapped
GROUP BY bucket
/* v_bucket_counts(bucket,n) */;
CREATE TRIGGER trg_rf_risk_to_score_ins
AFTER INSERT ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_rf_risk_to_score_upd
AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_brf_risk_to_score_ins
AFTER INSERT ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_brf_risk_to_score_upd
AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_if_risk_to_score_ins
AFTER INSERT ON wz_scores_if
BEGIN
  UPDATE wz_scores_if
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_if_risk_to_score_upd
AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_if
BEGIN
  UPDATE wz_scores_if
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE VIEW v_alerts_scored_if AS
SELECT
  s.id,
  s.risk_score   AS score,
  s.risk_bucket  AS bucket,
  s.risk_score   AS risk_score,
  s.risk_bucket  AS risk_bucket
FROM wz_scores_if s
/* v_alerts_scored_if(id,score,bucket,risk_score,risk_bucket) */;
CREATE INDEX idx_scores_if_id      ON wz_scores_if(id);
CREATE INDEX idx_scores_if_bucket  ON wz_scores_if(risk_bucket);
CREATE INDEX idx_scores_if_score   ON wz_scores_if(risk_score);
CREATE VIEW v_alerts_scored_if_enriched AS
SELECT
  a.id,
  COALESCE(datetime(replace(substr(a.timestamp,1,19),'T',' ')), a.timestamp) AS ts,
  a.rule_level,
  a.rule_description,
  a.agent_name,
  a.wazuh_score,
  a.wazuh_bucket,
  s.risk_score  AS ml_score,
  s.risk_bucket AS ml_bucket
FROM alerts_enriched_mat a
LEFT JOIN wz_scores_if s ON s.id = a.id;
CREATE TABLE alerts_enriched_mat(
  id TEXT,
  timestamp TEXT,
  rule_level INT,
  rule_description TEXT,
  source_ip TEXT,
  destination_ip
);
CREATE INDEX idx_aemat_id       ON alerts_enriched_mat(id);
CREATE INDEX idx_aemat_ts       ON alerts_enriched_mat(timestamp);
CREATE INDEX idx_aemat_rule_ts  ON alerts_enriched_mat(rule_description, timestamp);
CREATE INDEX idx_aemat_src_ts   ON alerts_enriched_mat(source_ip, timestamp);
CREATE INDEX idx_aemat_dst_ts   ON alerts_enriched_mat(destination_ip, timestamp);
CREATE TRIGGER protect_alerts_mat_delete
BEFORE DELETE ON alerts_enriched_mat
BEGIN
  SELECT RAISE(ABORT, 'Deletion not allowed on alerts_enriched_mat');
END;
CREATE INDEX idx_aemat_src_rule
 ON alerts_enriched_mat(source_ip, rule_description);
CREATE VIEW v_model_scores_union AS
SELECT 'rf'  AS model, id, risk_score, risk_bucket, scored_at FROM wz_scores_rf
UNION ALL
SELECT 'brf' AS model, id, risk_score, risk_bucket, scored_at FROM wz_scores_brf
UNION ALL
SELECT 'if'  AS model, id, risk_score, risk_bucket, scored_at FROM wz_scores_if
/* v_model_scores_union(model,id,risk_score,risk_bucket,scored_at) */;
CREATE VIEW alerts AS
SELECT
  id,
  rule_level,
  rule_description,
  source_ip,
  destination_ip,
  timestamp,
  -- legacy aliases some queries still use:
  source_ip      AS srcip,
  destination_ip AS dstip
FROM alerts_enriched
/* alerts(id,rule_level,rule_description,source_ip,destination_ip,timestamp,srcip,dstip) */;
CREATE VIEW alerts_enriched AS
SELECT
  id,
  rule_level,
  rule_description,
  source_ip,
  destination_ip,
  timestamp,
  -- legacy aliases required by some API queries:
  source_ip      AS srcip,
  destination_ip AS dstip
FROM alerts_enriched_mat
/* alerts_enriched(id,rule_level,rule_description,source_ip,destination_ip,timestamp,srcip,dstip) */;
CREATE TABLE ml_labels (
  id TEXT PRIMARY KEY,
  is_important INTEGER NOT NULL CHECK(is_important IN (0,1))
);
CREATE VIEW v_cases_if AS
SELECT 
  a.id,
  a.rule_description,
  l.is_important
FROM alerts_enriched a
JOIN ml_labels l ON a.id = l.id
/* v_cases_if(id,rule_description,is_important) */;
CREATE TABLE wz_scores_if_bak_20251007002815(
  id TEXT,
  pred_proba REAL,
  pred_class INT,
  actual INT,
  scored_at TEXT,
  score REAL,
  bucket TEXT,
  risk_score REAL,
  risk_bucket TEXT
);
CREATE TABLE wz_scores_if_bak_20251007024316(
  id TEXT,
  pred_proba REAL,
  pred_class INT,
  actual INT,
  scored_at TEXT,
  score REAL,
  bucket TEXT,
  risk_score REAL,
  risk_bucket TEXT
);
CREATE TABLE wz_scores_if_bak_20251011015600(
  id TEXT,
  pred_proba REAL,
  pred_class INT,
  actual INT,
  scored_at TEXT,
  score REAL,
  bucket TEXT,
  risk_score REAL,
  risk_bucket TEXT
);
CREATE TABLE wz_scores_if_bak_20251011025202(
  id TEXT,
  pred_proba REAL,
  pred_class INT,
  actual INT,
  scored_at TEXT,
  score REAL,
  bucket TEXT,
  risk_score REAL,
  risk_bucket TEXT
);
CREATE TABLE wz_scores_if_bak_static(
                    id TEXT PRIMARY KEY,
                    risk_score REAL,
                    risk_bucket TEXT,
                    scored_at TEXT
                  );
