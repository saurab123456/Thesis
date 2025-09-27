#!/usr/bin/env python3
"""
inject_public_attack_alerts.py

Inject Wazuh/Suricata-style alerts into wazuh_events + ml_labels + ml_features.
- True-positive (TP) rows are given attacker/source IPs chosen from "public" IPv4
  (excludes RFC1918, loopback, multicast, link-local, reserved/documentation/bogon ranges).
- False-positive (FP) rows default to private/internal-looking sources, but follow DB format.

Usage:
  python3 inject_public_attack_alerts.py --db /path/to/wazuh.db --tp 1000 --fp 400 --dry-run
  (then remove --dry-run to commit)

Run on a DB backup first.
"""
import sqlite3
import argparse
import random
import time
import datetime
import re
from copy import deepcopy
import ipaddress

DEFAULT_DB = "/home/ubuntu/wazuh-logs/wazuh.db"

# --------------- Public IP generator (excludes many reserved ranges) ---------------
EXCLUDED_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
]
EXCLUDED_NETS = [ipaddress.ip_network(c) for c in EXCLUDED_CIDRS]

def is_excluded(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return any(ip in net for net in EXCLUDED_NETS)

def random_public_ipv4():
    while True:
        i = random.randint(1, 0xFFFFFFFF - 1)
        ip = ipaddress.ip_address(i)
        if not is_excluded(ip):
            return str(ip)

def random_private_ipv4():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return random.randint(1025, 65535)

def replace_ip_port_in_full_log(full_log, new_src, new_src_port, new_dst, new_dst_port):
    s = full_log or ""
    # Suricata pattern
    sur_pat = re.compile(
        r'(\{[A-Z]+\}\s*)(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)'
    )
    m = sur_pat.search(s)
    if m:
        proto = m.group(1)  # e.g. "{TCP} "
        return sur_pat.sub(f"{proto}{new_src}:{new_src_port} -> {new_dst}:{new_dst_port}", s, count=1)
    # SSH/syslog pattern
    ssh_pat = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(\d+))?', flags=re.I)
    s2, n2 = ssh_pat.subn(lambda m: f"from {new_src} port {new_src_port}", s, count=1)
    return s2 if n2 else s

def choose_templates(conn, where_clause, limit=20):
    q = f"SELECT * FROM wazuh_events WHERE {where_clause} ORDER BY RANDOM() LIMIT {limit};"
    cur = conn.execute(q)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

def get_ml_features_columns(conn):
    cur = conn.execute("PRAGMA table_info(ml_features);")
    return [r[1] for r in cur.fetchall()]

def make_unique_id():
    base = f"{time.time():.8f}"
    suffix = random.randint(1, 999999)
    return f"{base}{suffix}"

def normalize_ip_port_fields(event):
    for key in ("srcip","dstip"):
        val = event.get(key) or ""
        if ":" in str(val):
            ip, port = str(val).split(":",1)
            event[key] = ip
            if key == "srcip" and not event.get("srcport"):
                event["srcport"] = port
            if key == "dstip" and not event.get("dstport"):
                event["dstport"] = port
    return event

def create_ml_features_row_from_template(template, ml_cols):
    rd = (template.get("rule_description") or "").lower()
    row = {c: 0 for c in ml_cols}
    row["id"] = template.get("_id")
    try:
        row["dst_port"] = int(template.get("dstport")) if template.get("dstport") else 0
    except:
        row["dst_port"] = 0
    row["is_suricata"] = 1 if "suricata" in rd or "ids" in (template.get("rule_groups") or "").lower() else 0
    row["is_ssh"] = 1 if "ssh" in rd or "brute" in rd else 0
    row["is_nmap"] = 1 if "nmap" in rd else 0
    row["kw_malware"] = 1 if "malware" in rd or "miner" in rd else 0
    row["kw_exploit"] = 1 if "exploit" in rd else 0
    row["kw_brute"] = 1 if "brute" in rd or "failed password" in rd or "invalid user" in rd else 0
    row["kw_ransom"] = 1 if "ransom" in rd else 0
    row["kw_shellcode"] = 1 if "shellcode" in rd else 0
    proto = (template.get("proto") or "").upper()
    row["proto_code"] = 1 if "TCP" in proto else (2 if "UDP" in proto else 0)
    try:
        hour = int(datetime.datetime.fromisoformat(template["timestamp"].replace("+0000", "+00:00")).hour)
    except:
        hour = random.randint(0,23)
    row["hour"] = hour
    def is_private(ip):
        if not ip: return 0
        try:
            a = int(str(ip).split(".")[0])
            return 1 if (a == 10 or a == 172 or a == 192) else 0
        except: return 0
    row["src_privat"] = is_private(template.get("srcip"))
    row["dst_privat"] = is_private(template.get("dstip"))
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

def insert_ml_features(conn, features_row, ml_cols):
    available_cols = get_ml_features_columns(conn)
    row = {c: features_row.get(c, 0) for c in available_cols}
    placeholders = ",".join(["?"]*len(available_cols))
    conn.execute(f"INSERT OR REPLACE INTO ml_features ({','.join(available_cols)}) VALUES ({placeholders});", [row[c] for c in available_cols])

def prepare_event_from_template(tpl, public_src=False):
    new = deepcopy(tpl)
    new_id = make_unique_id()
    new["_id"] = new_id
    new["alert_id"] = new_id
    dt = datetime.datetime.utcnow() - datetime.timedelta(seconds=random.randint(0,7*24*3600))
    new_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    new["timestamp"] = new_ts
    new["raw_timestamp"] = new_ts

    srcip = random_public_ipv4() if public_src else random_private_ipv4()
    dstip = tpl.get("dstip") or random_private_ipv4()
    srcport = random_port()
    dstport = tpl.get("dstport") or random_port()

    new["srcip"] = srcip
    new["dstip"] = dstip
    new["srcport"] = str(srcport)
    new["dstport"] = str(dstport)
    new["proto"] = tpl.get("proto") or "TCP"

    new_full = tpl.get("full_log") or ""
    if new_full:
        new["full_log"] = replace_ip_port_in_full_log(new_full, srcip, srcport, dstip, dstport)
    else:
        if "suricata" in (tpl.get("rule_groups") or "").lower() or "suricata" in (tpl.get("rule_description") or "").lower():
            new["full_log"] = f"{new_ts}  [**] [1:86601:1] {tpl.get('rule_description','Suricata alert')}  [**] {{TCP}} {srcip}:{srcport} -> {dstip}:{dstport}"

    if not new.get("agent_name"):
        new["agent_name"] = "injected-agent"
    if not new.get("manager_name"):
        new["manager_name"] = "wazuh.manager"

    return normalize_ip_port_fields(new)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--tp", type=int, default=50)
    ap.add_argument("--fp", type=int, default=50)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    tp_where = "(rule_description LIKE '%brute%' OR rule_description LIKE '%NMAP%' OR rule_description LIKE '%Failed password%' OR rule_description LIKE '%Invalid user%')"
    fp_where = "(rule_description LIKE '%Wazuh server started%' OR full_log LIKE '%HTTPS Traffic Detected%' OR full_log LIKE '%DNS Response Detected%')"

    tp_templates = choose_templates(conn, tp_where, limit=50) or choose_templates(conn, "(rule_description LIKE '%sshd%' OR rule_description LIKE '%brute%')", limit=50)
    fp_templates = choose_templates(conn, fp_where, limit=50) or choose_templates(conn, "rule_description LIKE '%Wazuh server started%'", limit=50)

    if not tp_templates or not fp_templates:
        print("Error: could not find suitable templates in the DB. Aborting.")
        return

    ml_cols = get_ml_features_columns(conn)
    print(f"Found {len(tp_templates)} TP templates, {len(fp_templates)} FP templates. ml_features columns: {len(ml_cols)}")

    tp_rows = [prepare_event_from_template(random.choice(tp_templates), public_src=True) for _ in range(args.tp)]
    fp_rows = [prepare_event_from_template(random.choice(fp_templates), public_src=False) for _ in range(args.fp)]

    if args.dry_run:
        import json
        print("\n=== Example TP row ===")
        print(json.dumps(tp_rows[0], indent=2, default=str))
        print("\n=== Example FP row ===")
        print(json.dumps(fp_rows[0], indent=2, default=str))
        return

    try:
        inserted = 0
        for r in tp_rows:
            insert_wazuh_event(conn, r)
            insert_ml_label(conn, r["_id"], 1)
            insert_ml_features(conn, create_ml_features_row_from_template(r, ml_cols), ml_cols)
            inserted += 1
        for r in fp_rows:
            insert_wazuh_event(conn, r)
            insert_ml_label(conn, r["_id"], 0)
            insert_ml_features(conn, create_ml_features_row_from_template(r, ml_cols), ml_cols)
            inserted += 1
        conn.commit()
        print(f"✅ Inserted {len(tp_rows)} TP, {len(fp_rows)} FP (total {inserted}) into {args.db}")
    except Exception as e:
        conn.rollback()
        print("Error during insert:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
