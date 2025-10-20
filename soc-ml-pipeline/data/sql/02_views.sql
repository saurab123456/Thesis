-- Helpful views for dashboards & API

CREATE VIEW IF NOT EXISTS v_alerts_scored AS
SELECT a.id,
       a.ts,
       a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.proto, a.rule_level, a.category,
       s.score, s.model, s.risk_bucket, s.published_at
FROM alerts a
LEFT JOIN wz_scores_if s ON s.alert_id = a.id;

CREATE VIEW IF NOT EXISTS v_top_noisy_rules AS
SELECT rule_id, COUNT(*) AS cnt
FROM alerts
GROUP BY rule_id
ORDER BY cnt DESC;

CREATE VIEW IF NOT EXISTS v_recent_high_risk AS
SELECT *
FROM v_alerts_scored
WHERE risk_bucket IN ('Critical','High')
ORDER BY ts DESC;
