#!/usr/bin/env python3
# Unsupervised prioritizer: trains IsolationForest on features from SQLite
import sqlite3, pandas as pd, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import time

DB = "wazuh.db"
SCORES_TABLE = "wz_scores_if"   # keep separate from rule-based scores

# Columns we expect in ml_features
FEATURE_COLS = [
    "rule_level","dst_port","is_suricata","is_ssh","is_nmap",
    "kw_malware","kw_exploit","kw_brute","kw_ransom","kw_shellcode",
    "proto_code","hour","src_private","dst_private"
]

def bucket(p):
    # map 0..1 anomaly score to buckets (tune if needed)
    if p >= 0.95: return "Critical"
    if p >= 0.80: return "High"
    if p >= 0.50: return "Medium"
    return "Low"

t0 = time.time()
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

# Load all features directly from DB
df = pd.read_sql_query(
    "SELECT id, " + ",".join(FEATURE_COLS) + " FROM ml_features",
    con
)

# Basic cleaning
X = df[FEATURE_COLS].copy()
X = X.fillna({"dst_port": -1}).fillna(0)  # fill NaNs

# Fit IsolationForest (unsupervised)
# contamination ~ fraction you want flagged as unusual
clf = IsolationForest(
    n_estimators=200,
    contamination=0.02,   # <<< changed from 0.02 to 0.01
    n_jobs=-1,
    random_state=42
)
clf.fit(X)

# Score: higher should mean "more anomalous"
raw = -clf.score_samples(X).reshape(-1, 1)       # invert (higher = more anomalous)
norm = MinMaxScaler().fit_transform(raw).ravel()  # normalize to 0..1

# Prepare rows for DB
rows = [(i, float(p), bucket(float(p))) for i, p in zip(df["id"], norm)]

# Create table and write scores back
con.execute(f"""
CREATE TABLE IF NOT EXISTS {SCORES_TABLE} (
  id TEXT PRIMARY KEY,
  risk_score  REAL NOT NULL,
  risk_bucket TEXT NOT NULL,
  scored_at   TEXT DEFAULT CURRENT_TIMESTAMP
)""")
with con:
    con.executemany(
        f"""INSERT OR REPLACE INTO {SCORES_TABLE}(id, risk_score, risk_bucket, scored_at)
            VALUES(?,?,?,CURRENT_TIMESTAMP)""",
        rows
    )
con.close()
print(f"[+] Trained & scored {len(rows)} alerts into {SCORES_TABLE} in {time.time()-t0:.1f}s")
