#!/usr/bin/env python3
# make_features_delta.py — build/refresh ml_features only for NEW wazuh_events rows
import json, os, sqlite3, sys, ipaddress, argparse
from datetime import datetime, timezone

DB_DEFAULT = "/home/ubuntu/wazuh-logs/wazuh.db"
FEATURES_JSON = "/home/ubuntu/wazuh-logs/models/rf_feature_columns.json"

def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def is_private_ip(s):
    try:
        return int(ipaddress.ip_address(s).is_private)
    except Exception:
        return None

def ensure_table(con):
    con.execute("""
    CREATE TABLE IF NOT EXISTS ml_features (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        rule_level INTEGER,
        rule_description TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        proto TEXT,
        agent_id TEXT,
        agent_name TEXT,
        decoder_name TEXT,
        is_nmap INTEGER,
        is_ssh INTEGER,
        is_brute INTEGER,
        is_dns  INTEGER,
        is_http INTEGER,
        is_https INTEGER,
        src_private INTEGER,
        dst_private INTEGER
    )
    """)

def load_expected_cols():
    try:
        with open(FEATURES_JSON, "r") as f:
            cols = json.load(f)
        return [c for c in cols if c != "id"]
    except Exception:
        return []

def select_new_rows(con, limit):
    sql = f"""
    SELECT
      we._id           AS id,
      we.timestamp     AS timestamp,
      we.rule_level    AS rule_level,
      we.rule_description,
      we.srcip         AS source_ip,
      we.dstip         AS destination_ip,
      CAST(NULLIF(we.srcport,'') AS INTEGER) AS src_port,
      CAST(NULLIF(we.dstport,'') AS INTEGER) AS dst_port,
      we.proto         AS proto,
      we.agent_id      AS agent_id,
      we.agent_name    AS agent_name,
      we.decoder_name  AS decoder_name
    FROM wazuh_events we
    LEFT JOIN ml_features mf ON mf.id = we._id
    WHERE mf.id IS NULL
    ORDER BY we.timestamp DESC
    LIMIT {int(limit)}
    """
    cur = con.execute(sql)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

def derive_flags(rec):
    desc = (rec.get("rule_description") or "").lower()
    rec["is_nmap"]  = 1 if "nmap" in desc else 0
    rec["is_ssh"]   = 1 if "ssh" in desc or "sshd" in desc else 0
    rec["is_brute"] = 1 if "brute" in desc else 0
    rec["is_dns"]   = 1 if "dns"  in desc else 0
    rec["is_http"]  = 1 if "http " in desc or "http-" in desc or "http:" in desc else 0
    rec["is_https"] = 1 if "https" in desc else 0
    rec["src_private"] = is_private_ip(rec.get("source_ip") or "")
    rec["dst_private"] = is_private_ip(rec.get("destination_ip") or "")
    return rec

def upsert(con, records, expected_cols):
    if not records: return 0
    base_cols = [
        "id","timestamp","rule_level","rule_description","source_ip","destination_ip",
        "src_port","dst_port","proto","agent_id","agent_name","decoder_name",
        "is_nmap","is_ssh","is_brute","is_dns","is_http","is_https","src_private","dst_private"
    ]
    for c in expected_cols:
        if c not in base_cols and c != "is_important":
            base_cols.append(c)

    fixed = []
    for r in records:
        r = derive_flags(r)
        fixed.append({k: r.get(k) for k in base_cols})

    placeholders = ",".join(["?"]*len(base_cols))
    sql = f"INSERT OR REPLACE INTO ml_features({','.join(base_cols)}) VALUES({placeholders})"
    vals = [tuple(rec.get(c) for c in base_cols) for rec in fixed]
    con.executemany(sql, vals)
    con.commit()
    return len(fixed)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_DEFAULT)
    ap.add_argument("--limit", type=int, default=200000)
    args = ap.parse_args()
    with sqlite3.connect(args.db) as con:
        ensure_table(con)
        expected = load_expected_cols()
        rows = select_new_rows(con, args.limit)
        n = upsert(con, rows, expected)
        print(f"[{utcnow()}] features-delta: inserted_or_replaced={n}")

if __name__ == "__main__":
    main()
