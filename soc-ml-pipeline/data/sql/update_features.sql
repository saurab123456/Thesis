PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

-- Table holds features; add columns once and reuse
CREATE TABLE IF NOT EXISTS ml_features (
  id TEXT PRIMARY KEY,
  rule_level INTEGER,
  dst_port   INTEGER,
  is_suricata INTEGER,
  is_ssh     INTEGER,
  is_nmap    INTEGER,
  kw_malware INTEGER,
  kw_exploit INTEGER,
  kw_brute   INTEGER,
  kw_ransom  INTEGER,
  kw_shellcode INTEGER,
  proto_code INTEGER,
  hour       INTEGER,
  src_private INTEGER,
  dst_private INTEGER
);

-- Insert ONLY new alerts (by id) into ml_features
INSERT OR IGNORE INTO ml_features (
  id, rule_level, dst_port, is_suricata, is_ssh, is_nmap,
  kw_malware, kw_exploit, kw_brute, kw_ransom, kw_shellcode,
  proto_code, hour, src_private, dst_private
)
SELECT
  we._id                                                       AS id,
  COALESCE(we.rule_level, 0)                                   AS rule_level,
  CAST(NULLIF(we.dstport,'') AS INTEGER)                       AS dst_port,
  CASE WHEN we.rule_groups LIKE '%suricata%' OR we.location LIKE '%/suricata/%' THEN 1 ELSE 0 END AS is_suricata,
  CASE
    WHEN LOWER(we.rule_description) LIKE '%ssh%' OR LOWER(we.rule_description) LIKE 'pam:%' OR we.dstport='22'
    THEN 1 ELSE 0 END                                          AS is_ssh,
  CASE WHEN LOWER(we.rule_description) LIKE '%nmap%' THEN 1 ELSE 0 END AS is_nmap,
  CASE WHEN LOWER(we.rule_description) LIKE '%malware%'   THEN 1 ELSE 0 END AS kw_malware,
  CASE WHEN LOWER(we.rule_description) LIKE '%exploit%'   THEN 1 ELSE 0 END AS kw_exploit,
  CASE WHEN LOWER(we.rule_description) LIKE '%brute%'     THEN 1 ELSE 0 END AS kw_brute,
  CASE WHEN LOWER(we.rule_description) LIKE '%ransom%'    THEN 1 ELSE 0 END AS kw_ransom,
  CASE WHEN LOWER(we.rule_description) LIKE '%shellcode%' THEN 1 ELSE 0 END AS kw_shellcode,
  CASE LOWER(we.proto)
    WHEN 'tcp'  THEN 1
    WHEN 'udp'  THEN 2
    WHEN 'icmp' THEN 3
    WHEN 'http' THEN 4
    ELSE 0
  END                                                          AS proto_code,
  CAST(substr(we.timestamp,12,2) AS INTEGER)                   AS hour,
  CASE WHEN we.srcip GLOB '10.*'
        OR we.srcip GLOB '192.168.*'
        OR we.srcip GLOB '172.1[6-9].*'
        OR we.srcip GLOB '172.2[0-9].*'
        OR we.srcip GLOB '172.3[0-1].*'
       THEN 1 ELSE 0 END                                       AS src_private,
  CASE WHEN we.dstip GLOB '10.*'
        OR we.dstip GLOB '192.168.*'
        OR we.dstip GLOB '172.1[6-9].*'
        OR we.dstip GLOB '172.2[0-9].*'
        OR we.dstip GLOB '172.3[0-1].*'
       THEN 1 ELSE 0 END                                       AS dst_private
FROM wazuh_events we
LEFT JOIN ml_features mf ON mf.id = we._id
WHERE mf.id IS NULL;

-- (Optional) keep SQLite stats fresh
ANALYZE;
