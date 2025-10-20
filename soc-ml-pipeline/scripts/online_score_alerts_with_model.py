#!/usr/bin/env python3
import time, json, os, sqlite3, ipaddress
import numpy as np
import pandas as pd
import joblib

DB = "/home/ubuntu/wazuh-logs/wazuh.db"
ART_DIR = "/home/ubuntu/wazuh-logs/models"
MODEL = os.path.join(ART_DIR, "brf_model.pkl")             # or rf_model.pkl
FEATS = os.path.join(ART_DIR, "rf_feature_columns.json")    # saved by your trainer

T_CRIT, T_HIGH, T_MED = 0.95, 0.85, 0.50
def bucket(p):
    if p >= T_CRIT: return "Critical"
    if p >= T_HIGH: return "High"
    if p >= T_MED:  return "Medium"
    return "Low"

def is_private(ip):
    try: return ipaddress.ip_address(ip).is_private
    except: return None

def ip_to_int(x):
    try: return int(ipaddress.ip_address(x))
    except: return np.nan

def hour_or_nan(t):
    try:
        t2 = t.replace("Z","+0000") if t and t.endswith("Z") else t
        t2 = t2.replace("T"," ").split("+")[0]
        return pd.to_datetime(t2).hour
    except: return np.nan

def load_expected_features():
    with open(FEATS,"r") as f:
        cols = json.load(f)
    return list(cols) if isinstance(cols,list) else list(cols)

def build_feature_frame(rows, feature_cols):
    # rows: (id, rule_level, rule_description, source_ip, destination_ip, timestamp)
    df = pd.DataFrame([{c: np.nan for c in feature_cols} for _ in rows])
    def set_if(col, series):
        if col in df.columns: df[col] = series

    ids, lvl, desc, src, dst, ts = zip(*rows)

    set_if("rule_level", pd.to_numeric(lvl, errors="coerce"))
    set_if("is_nmap", pd.Series([1 if (d and "nmap" in d.lower()) else 0 for d in desc], dtype="float"))
    set_if("src_private", pd.Series([1 if is_private(s) else 0 if is_private(s) is not None else np.nan for s in src], dtype="float"))
    set_if("dst_private", pd.Series([1 if is_private(d) else 0 if is_private(d) is not None else np.nan for d in dst], dtype="float"))
    set_if("hour", pd.Series([hour_or_nan(t) for t in ts], dtype="float"))
    set_if("srcip_int", pd.Series([ip_to_int(s) for s in src], dtype="float"))
    set_if("dstip_int", pd.Series([ip_to_int(d) for d in dst], dtype="float"))
    return df

def fetch_unscored(cur, limit=500):
    return cur.execute("""
        SELECT id, rule_level, rule_description, source_ip, destination_ip, timestamp
        FROM alerts
        WHERE risk_score IS NULL
        ORDER BY ROWID ASC
        LIMIT ?
    """,(limit,)).fetchall()

def write_scores(cur, rows, probs):
    ids = [r[0] for r in rows]
    cur.executemany("""
        UPDATE alerts SET risk_score=?, risk_bucket=? WHERE id=?
    """, [(float(p), bucket(float(p)), rid) for p, rid in zip(probs, ids)])

def main():
    model = joblib.load(MODEL)              # full calibrated pipeline
    feature_cols = load_expected_features()

    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    cur = conn.cursor()

    print("[online] model:", MODEL)
    while True:
        rows = fetch_unscored(cur)
        if not rows:
            time.sleep(1.5)
            continue
        X = build_feature_frame(rows, feature_cols)
        probs = model.predict_proba(X)[:,1]
        write_scores(cur, rows, probs)
        conn.commit()
        print(f"[online] scored {len(rows)} rows; last={probs[-1]:.3f}")
        time.sleep(0.2)

if __name__ == "__main__":
    main()
