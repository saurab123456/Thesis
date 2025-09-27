#!/usr/bin/env python3
"""
inject_wazuh_like_alerts.py

Generate additional Wazuh-style alerts (no 'synthetic' label) and insert them into:
 - wazuh_events (full alert row)
 - ml_labels (id, is_important)
 - ml_features (match existing ml_features columns)

The script samples existing real events as templates so format matches your DB.
Run on a backup copy first. Use --dry-run to preview without writing.
"""

import sqlite3
import argparse
import random
import time
import datetime
import re
from copy import deepcopy

DEFAULT_DB = "/home/ubuntu/wazuh-logs/wazuh.db"

# --- Helpers ---
def now_iso():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

def make_unique_id():
    base = f"{time.time():.8f}"
    suffix = random.randint(1, 99999)
    return f"{base}{suffix}"

def random_ipv4(public=False):
    if public:
        while True:
            ip = random.randint(1, 0xFFFFFFFF)
            a = (ip >> 24) & 0xFF
            b = (ip >> 16) & 0xFF
            c = (ip >> 8) & 0xFF
            d = ip & 0xFF
            if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
                continue
            if a == 127 or a == 0 or a >= 224:
                continue
            return f"{a}.{b}.{c}.{d}"
    else:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return random.randint(1025, 65535)

def replace_ip_port_in_full_log(full_log, new_src, new_src_port, new_dst, new_dst_port):
    s = full_log
    # Suricata pattern
    sur_pat = re.compile(r'(\{[A-Z]+\}\s*)(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)')
    if sur_pat.search(s):
        return sur_pat.sub(f"\\1{new_src}:{new_src_port} -> {new_dst}:{new_dst_port}", s, count=1)
    # SSH/syslog
    ssh_pat = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(\d+))?', flags=re.I)
    def ssh_repl(m):
        return f"from {new_src} port {new_src_port}"
    s2, n2 = ssh_pat.subn(ssh_repl, s, count=1)
    if n2:
        return s2
    return s

def normalize_ip_port_fields(event):
    """Ensure srcip/dstip contain only IPs and ports are separate fields."""
    for key in ["srcip", "dstip"]:
        if event.get(key) and ":" in str(event[key]):
            ip, port = event[key].split(":", 1)
            event[key] = ip
            if key == "srcip" and not event.get("srcport"):
                event["srcport"] = port
            elif key == "dstip" and not event.get("dstport"):
                event["dstport"] = port
    return event

def choose_templates(conn, where_clause, limit=10):
    q = f"SELECT * FROM wazuh_events WHERE {where_clause} ORDER BY RANDOM() LIMIT {limit};"
    cur = conn.execute(q)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

def get_ml_features_columns(conn):
    cur = conn.execute("PRAGMA table_info(ml_features);")
    return [r[1] for r in cur.fetchall()]

def create_ml_features_row_from_template(template, ml_cols):
    rd = (template.get("rule_description") or "").lower()
    row = {c:0 for c in ml_cols}
    row["id"] = template["_id"]
    try:
        row["dst_port"] = int(template.get("dstport")) if template.get("dstport") else 0
    except:
        row["dst_port"] = 0
    row["is_suricata"] = 1 if "suricata" in rd else 0
    row["is_ssh"] = 1 if "ssh" in rd or "brute" in rd else 0
    row["is_nmap"] = 1 if "nmap" in rd else 0
    row["kw_malware"] = 1 if "malware" in rd or "coinminer" in rd else 0
    row["kw_exploit"] = 1 if "exploit" in rd else 0
    row["kw_brute"] = 1 if "brute" in rd or "failed password" in rd else 0
    row["kw_ransom"] = 1 if "ransom" in rd else 0
    row["kw_shellcode"] = 1 if "shellcode" in rd else 0
    proto = (template.get("proto") or "").upper()
    row["proto_code"] = 1 if "TCP" in proto else (2 if "UDP" in proto else 0)
    try:
        hour = int(datetime.datetime.fromisoformat(template["timestamp"].replace("+0000", "+00:00")).hour)
    except:
        hour = random.randint(0,23)
    row["hour"] = hour
    row["rule_level"] = int(template.get("rule_level") or 0)
    return row

def insert_wazuh_event(conn, row):
    cur = conn.execute("PRAGMA table_info(wazuh_events);")
    cols = [r[1] for r in cur.fetchall()]
    values = [row.get(c) for c in cols]
    placeholders = ",".join(["?"]*len(cols))
    conn.execute(f"INSERT INTO wazuh_events ({','.join(cols)}) VALUES ({placeholders});", values)

def insert_ml_label(conn, id_val, label):
    conn.execute("INSERT OR REPLACE INTO ml_labels (id, is_important) VALUES (?,?);", (id_val, label))

def insert_ml_features(conn, features_row):
    ml_cols = list(features_row.keys())
    placeholders = ",".join(["?"]*len(ml_cols))
    conn.execute(f"INSERT OR REPLACE INTO ml_features ({','.join(ml_cols)}) VALUES ({placeholders});", [features_row[c] for c in ml_cols])

# --- Core ---
def prepare_event_from_template(tpl, make_public_src=False):
    new = deepcopy(tpl)
    new_id = make_unique_id()
    new["_id"] = new_id
    new["alert_id"] = new_id
    dt = datetime.datetime.utcnow() - datetime.timedelta(seconds=random.randint(0,7*24*3600))
    new_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    new["timestamp"] = new_ts
    new["raw_timestamp"] = new_ts

    new_src = random_ipv4(public=make_public_src)
    new_dst = tpl.get("dstip") or random_ipv4(public=False)
    new_src_port = random_port()
    new_dst_port = tpl.get("dstport") or random_port()

    new["srcip"] = new_src
    new["dstip"] = new_dst
    new["srcport"] = str(new_src_port)
    new["dstport"] = str(new_dst_port)
    new["proto"] = tpl.get("proto") or "TCP"

    full = tpl.get("full_log") or ""
    if full:
        new["full_log"] = replace_ip_port_in_full_log(full, new_src, new_src_port, new_dst, new_dst_port)
    else:
        new["full_log"] = full

    if not new.get("agent_name"):
        new["agent_name"] = "injected-agent"
    if not new.get("manager_name"):
        new["manager_name"] = "wazuh.manager"

    # 🔹 Normalize fields before returning
    return normalize_ip_port_fields(new)

# --- Main ---
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--tp", type=int, default=50)
    ap.add_argument("--fp", type=int, default=50)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    tp_templates = choose_templates(conn, "(rule_description LIKE '%brute%' OR rule_description LIKE '%NMAP%' OR rule_description LIKE '%Failed password%')", limit=20)
    fp_templates = choose_templates(conn, "(rule_description LIKE '%Wazuh server started%' OR full_log LIKE '%HTTPS Traffic Detected%' OR full_log LIKE '%DNS Response Detected%')", limit=20)

    ml_cols = get_ml_features_columns(conn)
    print(f"Found {len(tp_templates)} TP templates, {len(fp_templates)} FP templates. ml_features columns: {len(ml_cols)}")

    tp_to_insert = [prepare_event_from_template(random.choice(tp_templates), make_public_src=True) for _ in range(args.tp)]
    fp_to_insert = [prepare_event_from_template(random.choice(fp_templates), make_public_src=False) for _ in range(args.fp)]

    if args.dry_run:
        import json
        print("\n=== Example TP row ===")
        print(json.dumps(tp_to_insert[0], indent=2, default=str))
        print("\n=== Example FP row ===")
        print(json.dumps(fp_to_insert[0], indent=2, default=str))
        return

    try:
        inserted = 0
        for new in tp_to_insert:
            insert_wazuh_event(conn, new)
            insert_ml_label(conn, new["_id"], 1)
            insert_ml_features(conn, create_ml_features_row_from_template(new, ml_cols))
            inserted += 1
        for new in fp_to_insert:
            insert_wazuh_event(conn, new)
            insert_ml_label(conn, new["_id"], 0)
            insert_ml_features(conn, create_ml_features_row_from_template(new, ml_cols))
            inserted += 1
        conn.commit()
        print(f"✅ Inserted {len(tp_to_insert)} TP, {len(fp_to_insert)} FP, total {inserted} alerts into {args.db}")
    except Exception as e:
        conn.rollback()
        print("Error during insert:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
