#!/usr/bin/env python3
import sys, json, argparse, sqlite3

DEFAULT_DB = "/home/ubuntu/wazuh-logs/wazuh.db"
TARGET_TABLE = "wazuh_events"

def get(d, *path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def first(*vals):
    for v in vals:
        if v not in (None, ""):
            return v
    return None

def map_alert_to_row(a):
    rule = a.get("rule", {}) or {}
    agent = a.get("agent", {}) or {}
    mgr = a.get("manager", {}) or {}
    dec = a.get("decoder", {}) or {}
    dat = a.get("data", {}) or {}

    srcip = first(dat.get("srcip"), a.get("srcip"), get(a, "source", "ip"), agent.get("ip"))
    dstip = first(dat.get("dstip"), a.get("dstip"), get(a, "destination", "ip"))
    srcport = first(dat.get("srcport"), a.get("srcport"), get(a, "source", "port"))
    dstport = first(dat.get("dstport"), a.get("dstport"), get(a, "destination", "port"))
    proto = first(dat.get("proto"), dat.get("protocol"), a.get("proto"))

    row = {
        "_index": "",
        "_id": a.get("id"),
        "_version": 1,
        "timestamp": a.get("timestamp"),
        "agent_ip": agent.get("ip"),
        "agent_name": agent.get("name"),
        "agent_id": agent.get("id"),
        "manager_name": mgr.get("name"),
        "srcip": srcip,
        "dstip": dstip,
        "data_id": None,
        "rule_firedtimes": rule.get("firedtimes"),
        "rule_mail": int(bool(rule.get("mail"))) if rule.get("mail") is not None else 0,
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": json.dumps(rule.get("groups")) if isinstance(rule.get("groups"), list) else rule.get("groups"),
        "rule_id": rule.get("id"),
        "location": a.get("location"),
        "decoder_parent": dec.get("parent"),
        "decoder_name": dec.get("name"),
        "alert_id": a.get("id"),
        "full_log": a.get("full_log", ""),
        "raw_timestamp": a.get("timestamp"),
        "sort": None,
        "srcport": str(srcport) if srcport is not None else None,
        "dstport": str(dstport) if dstport is not None else None,
        "proto": proto,
    }
    return row

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--stdin", action="store_true", help="Read alerts.json lines from stdin")
    ap.add_argument("--file", help="Read alerts.json from file instead of stdin")
    args = ap.parse_args()

    if not (args.stdin or args.file):
        print("Provide --stdin or --file", file=sys.stderr); sys.exit(2)

    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute(f"PRAGMA table_info({TARGET_TABLE});")
    cols = [r[1] for r in cur.fetchall()]
    if not cols:
        print(f"ERROR: table '{TARGET_TABLE}' not found in {args.db}", file=sys.stderr)
        sys.exit(1)

    insert_cols = cols[:]
    placeholders = ",".join(["?"] * len(insert_cols))
    sql = f"INSERT OR IGNORE INTO {TARGET_TABLE} ({','.join(insert_cols)}) VALUES ({placeholders})"

    def iter_lines():
        if args.stdin:
            for line in sys.stdin:
                yield line
        else:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    yield line

    inserted = skipped = bad = 0

    try:
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("BEGIN;")
        for line in iter_lines():
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except Exception:
                bad += 1
                continue
            row = map_alert_to_row(a)
            values = [row.get(c) for c in insert_cols]
            try:
                cur.execute(sql, values)
                if cur.rowcount == 1:
                    inserted += 1
                else:
                    skipped += 1
            except Exception:
                bad += 1
        con.commit()
    except Exception as e:
        con.rollback()
        print("ERROR during ingest:", e, file=sys.stderr)
        sys.exit(1)
    finally:
        con.close()

    print(f"Done. inserted={inserted}, skipped(dupes)={skipped}, bad={bad}")

if __name__ == "__main__":
    main()

