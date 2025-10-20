#!/usr/bin/env python3
import os
import json
import hashlib
import subprocess
import sqlite3

CONTAINER_NAME = "single-node-wazuh.manager-1"
CONTAINER_ALERTS_JSON_PATH = "/var/ossec/logs/alerts/alerts.json"
LOCAL_OUTPUT_DIR = "./alerts_data"
LOCAL_RAW_FILE = os.path.join(LOCAL_OUTPUT_DIR, "raw_alerts.json")
LOCAL_DEDUP_FILE = os.path.join(LOCAL_OUTPUT_DIR, "deduplicated_alerts.json")
DB_FILE = "wazuh.db"
CONFIG_FILE = "field_map.json"

# Create output directory if missing
os.makedirs(LOCAL_OUTPUT_DIR, exist_ok=True)

print("[*] Fetching alerts.json from Wazuh Manager container...")
subprocess.run([
    "docker", "cp",
    f"{CONTAINER_NAME}:{CONTAINER_ALERTS_JSON_PATH}",
    LOCAL_RAW_FILE
], check=True)

print("[*] Deduplicating alerts...")
unique_hashes = set()
deduped_alerts = []

with open(LOCAL_RAW_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        h = hashlib.sha256(line.encode()).hexdigest()
        if h not in unique_hashes:
            unique_hashes.add(h)
            try:
                alert = json.loads(line)
                alert['_hash'] = h
                deduped_alerts.append(alert)
            except json.JSONDecodeError:
                print("[!] Skipping malformed JSON line.")

with open(LOCAL_DEDUP_FILE, "w") as out_f:
    for alert in deduped_alerts:
        json.dump(alert, out_f)
        out_f.write("\n")

print(f"[+] Deduplicated alerts saved to {LOCAL_DEDUP_FILE}")

# Load JSON config for field mapping
with open(CONFIG_FILE) as f:
    config = json.load(f)

db_columns = config["db_columns"]
json_paths = config["json_paths"]

def get_from_path(obj, path):
    parts = path.split('.')
    val = obj
    for p in parts:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            return None
        if val is None:
            return None
    return val

def extract_value(alert, expr):
    for part in expr.split("||"):
        part = part.strip()
        if part.startswith("'") and part.endswith("'"):
            return part.strip("'")
        elif part.lower() == 'null':
            return None
        elif part.isdigit():
            return int(part)
        else:
            val = get_from_path(alert, part)
            if val is not None:
                return val
    return None

def create_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
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
    )
    """)

def insert_alert(cursor, alert):
    try:
        values = []
        for col in db_columns:
            expr = json_paths.get(col)
            if expr is None:
                values.append(None)
            else:
                val = extract_value(alert, expr)
                if col == "rule_mail":
                    val = int(bool(val))
                if col == "rule_groups" and val is not None:
                    val = json.dumps(val)
                values.append(val)

        placeholders = ", ".join("?" for _ in db_columns)
        cols = ", ".join(db_columns)

        cursor.execute(f"""
            INSERT OR IGNORE INTO alerts ({cols}) VALUES ({placeholders})
        """, values)
        return True
    except Exception as e:
        print(f"[!] Failed to insert alert {alert.get('id','')}: {e}")
        return False

print("[*] Uploading alerts to SQLite database...")
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
create_table(conn)

inserted = 0
for alert in deduped_alerts:
    if insert_alert(cursor, alert):
        inserted += 1

conn.commit()
conn.close()

print(f"[✔] Successfully inserted {inserted} unique alerts into {DB_FILE}.")
