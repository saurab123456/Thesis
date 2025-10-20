#!/usr/bin/env python3
import time, json, os, sqlite3, ipaddress, argparse
import numpy as np, pandas as pd, joblib

DB = "/home/ubuntu/wazuh-logs/wazuh.db"
ART_DIR = "/home/ubuntu/wazuh-logs/models"
MODEL = os.path.join(ART_DIR, "brf_model.pkl")               # or rf_model.pkl
FEATS = os.path.join(ART_DIR, "rf_feature_columns.json")      # feature names used in training

T_CRIT, T_HIGH, T_MED = 0.95, 0.85, 0.50
def bucket(p): return "Critical" if p>=T_CRIT else "High" if p>=T_HIGH else "Medium" if p>=T_MED else "Low"

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
    return list(cols) if isinstance(cols, list) else list(cols)

def build_feature_frame(rows, feature_cols):
    # rows: (id, rule_level, rule_description, source_ip, destination_ip, timestamp)
    df = pd.DataFrame([{c: np.nan for c in feature_cols} for _ in rows])
    def set_if(c, s):
        if c in df.columns: df[c]=s
    ids,lvl,desc,src,dst,ts = zip(*rows)
    set_if("rule_level", pd.to_numeric(lvl, errors="coerce"))
    set_if("is_nmap", pd.Series([1 if (d and "nmap" in str(d).lower()) else 0 for d in desc], dtype="float"))
    set_if("src_private", pd.Series([1 if is_private(s) else 0 if is_private(s) is not None else np.nan for s in src], dtype="float"))
    set_if("dst_private", pd.Series([1 if is_private(d) else 0 if is_private(d) is not None else np.nan for d in dst], dtype="float"))
    set_if("hour", pd.Series([hour_or_nan(t) for t in ts], dtype="float"))
    set_if("srcip_int", pd.Series([ip_to_int(s) for s in src], dtype="float"))
    set_if("dstip_int", pd.Series([ip_to_int(d) for d in dst], dtype="float"))
    return df

ap = argparse.ArgumentParser()
ap.add_argument("--table", default="alerts_staging", help="Table to score")
args = ap.parse_args()

model = joblib.load(MODEL)
is_pipeline = hasattr(model, "named_steps")
feature_cols = load_expected_features()

conn = sqlite3.connect(DB); conn.execute("PRAGMA journal_mode=WAL;"); conn.execute("PRAGMA synchronous=NORMAL;")
cur = conn.cursor()
print(f"[online] model: {MODEL}  pipeline={is_pipeline}  table: {args.table}")

def fetch_unscored(limit=500):
    return cur.execute(f"""
        SELECT id, rule_level, rule_description, source_ip, destination_ip, timestamp
        FROM {args.table}
        WHERE risk_score IS NULL
        ORDER BY ROWID ASC
        LIMIT ?
    """,(limit,)).fetchall()

def write_scores(rows, probs):
    ids = [r[0] for r in rows]
    cur.executemany(f"UPDATE {args.table} SET risk_score=?, risk_bucket=? WHERE id=?",
                    [(float(p), bucket(float(p)), rid) for p, rid in zip(probs, ids)])

while True:
    rows = fetch_unscored()
    if not rows:
        time.sleep(1.5); continue

    X = build_feature_frame(rows, feature_cols)

    if is_pipeline:
        # Let the saved Pipeline handle imputation/encoding
        probs = model.predict_proba(X)[:,1]
    else:
        # Bare estimator: coerce to numeric and replace NaNs/Infs
        X_num = X.copy()
        for c in X_num.columns:
            X_num[c] = pd.to_numeric(X_num[c], errors="coerce")
        X_mat = X_num.to_numpy(dtype=float)
        X_mat = np.nan_to_num(X_mat, nan=-1.0, posinf=1e9, neginf=-1e9)
        probs = model.predict_proba(X_mat)[:,1]

    write_scores(rows, probs); conn.commit()
    print(f"[online] scored {len(rows)} rows; last={probs[-1]:.3f}")
    time.sleep(0.2)
