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
FROM alerts_enriched;
CREATE VIEW alerts_api AS
SELECT
  _id AS id,
  rule_level,
  rule_description,
  srcip AS source_ip,
  COALESCE(NULLIF(dstip,''), NULLIF(agent_ip,''), agent_name) AS destination_ip,
  timestamp
FROM wazuh_events;
CREATE VIEW alerts_api_plus AS
SELECT id, rule_level, rule_description, source_ip, destination_ip, timestamp FROM alerts_api
UNION ALL
SELECT id, rule_level, rule_description, source_ip, destination_ip, timestamp FROM alerts_inbox;
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
FROM alerts_enriched_mat;
CREATE VIEW triage_labels_text AS
SELECT CAST(id AS TEXT) AS id, is_important FROM triage_labels;
CREATE VIEW v_alerts_scored AS
SELECT 'rf'  AS model, id, score, bucket, scored_at, actual, rule_id, rule_level, rule_description, srcip, dstip, agent_name, timestamp FROM v_alerts_scored_rf
UNION ALL
SELECT 'brf' AS model, id, score, bucket, scored_at, actual, rule_id, rule_level, rule_description, srcip, dstip, agent_name, timestamp FROM v_alerts_scored_brf;
CREATE VIEW v_alerts_scored_brf AS
SELECT s.id, s.score, s.bucket, s.scored_at, s.actual,
       e.rule_id, e.rule_level, e.rule_description, e.srcip, e.dstip, e.agent_name, e.timestamp
FROM v_scores_brf_mapped s
LEFT JOIN wazuh_events e ON e._id = s.id;
CREATE VIEW v_alerts_scored_if AS
SELECT
  s.id,
  s.risk_score   AS score,
  s.risk_bucket  AS bucket,
  s.risk_score   AS risk_score,
  s.risk_bucket  AS risk_bucket
FROM wz_scores_if s;
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
CREATE VIEW v_alerts_scored_rf AS
SELECT s.id, s.score, s.bucket, s.scored_at, s.actual,
       e.rule_id, e.rule_level, e.rule_description, e.srcip, e.dstip, e.agent_name, e.timestamp
FROM v_scores_rf_mapped s
LEFT JOIN wazuh_events e ON e._id = s.id;
CREATE VIEW v_bucket_counts AS
SELECT bucket, COUNT(*) AS n
FROM v_scores_if_mapped
GROUP BY bucket;
CREATE VIEW v_cases_if AS
SELECT 
  a.id,
  a.rule_description,
  l.is_important
FROM alerts_enriched a
JOIN ml_labels l ON a.id = l.id;
CREATE VIEW v_model_scores_union AS
SELECT 'rf'  AS model, id, risk_score, risk_bucket, scored_at FROM wz_scores_rf
UNION ALL
SELECT 'brf' AS model, id, risk_score, risk_bucket, scored_at FROM wz_scores_brf
UNION ALL
SELECT 'if'  AS model, id, risk_score, risk_bucket, scored_at FROM wz_scores_if;
CREATE VIEW v_paired_eval AS
WITH params AS (
  SELECT 0.50 AS rf_thr, 7 AS wazuh_sev_thr
)
SELECT
  tl.id,
  tl.true_label,
  -- Use provided rf_pred; if it is NULL but we have a score, threshold it.
  CASE
    WHEN re.rf_pred IS NOT NULL THEN CAST(re.rf_pred AS INTEGER)
    WHEN re.rf_score IS NOT NULL THEN CAST(re.rf_score >= (SELECT rf_thr FROM params) AS INTEGER)
    ELSE NULL
  END AS rf_prediction,
  CAST(re.rule_level >= (SELECT wazuh_sev_thr FROM params) AS INTEGER) AS wazuh_prediction,
  re.timestamp
FROM v_true_labels tl
JOIN v_rf_enriched re ON re.id = tl.id
WHERE tl.true_label IN (0,1);
CREATE VIEW v_rf_enriched AS
SELECT
  CAST(r.id AS TEXT)                     AS id,
  r.pred_class                           AS rf_pred,
  COALESCE(r.risk_score, r.score, r.pred_proba) AS rf_score,
  s.scored_at,
  e.rule_level,
  e.timestamp
FROM wz_scores_rf r
LEFT JOIN v_scores_rf_mapped s ON s.id = r.id
LEFT JOIN wazuh_events        e ON e._id = r.id;
CREATE VIEW v_scores_brf_mapped AS
SELECT id,
       COALESCE(risk_score, score, pred_proba) AS score,
       COALESCE(risk_bucket, bucket)           AS bucket,
       scored_at,
       COALESCE(actual,0)                      AS actual
FROM wz_scores_brf;
CREATE VIEW v_scores_if_mapped AS
SELECT id,
       COALESCE(risk_score, score, pred_proba) AS score,
       COALESCE(risk_bucket, bucket)           AS bucket,
       scored_at
FROM wz_scores_if;
CREATE VIEW v_scores_rf_mapped AS
SELECT id,
       COALESCE(risk_score, score, pred_proba) AS score,
       COALESCE(risk_bucket, bucket)           AS bucket,
       scored_at,
       COALESCE(actual,0)                      AS actual
FROM wz_scores_rf;
CREATE VIEW v_true_labels AS
WITH
triage AS (
  SELECT CAST(id AS TEXT) AS id, CAST(is_important AS INTEGER) AS y
  FROM triage_labels
  WHERE is_important IN (0,1)
),
ml2 AS (
  SELECT CAST(id AS TEXT) AS id, CAST(is_important AS INTEGER) AS y
  FROM ml_labels_v2
  WHERE is_important IN (0,1)
),
ml1 AS (
  SELECT CAST(id AS TEXT) AS id, CAST(is_important AS INTEGER) AS y
  FROM ml_labels
  WHERE is_important IN (0,1)
),
rf_actual AS (
  SELECT CAST(id AS TEXT) AS id, CAST(actual AS INTEGER) AS y
  FROM wz_scores_rf
  WHERE actual IN (0,1)
)
SELECT id, y AS true_label FROM triage
UNION ALL
SELECT m.id, m.y FROM ml2 m
LEFT JOIN triage t ON t.id = m.id
WHERE t.id IS NULL
UNION ALL
SELECT m.id, m.y FROM ml1 m
LEFT JOIN triage t ON t.id = m.id
LEFT JOIN ml2    m2 ON m2.id = m.id
WHERE t.id IS NULL AND m2.id IS NULL
UNION ALL
SELECT r.id, r.y FROM rf_actual r
LEFT JOIN triage t ON t.id = r.id
LEFT JOIN ml2    m2 ON m2.id = r.id
LEFT JOIN ml1    m1 ON m1.id = r.id
WHERE t.id IS NULL AND m2.id IS NULL AND m1.id IS NULL;
