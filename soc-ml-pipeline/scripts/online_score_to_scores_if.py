#!/usr/bin/env python3
import time, json, os, sqlite3, ipaddress, argparse, random
import numpy as np, pandas as pd, joblib
from datetime import datetime

DB="/home/ubuntu/wazuh-logs/wazuh.db"
ART="/home/ubuntu/wazuh-logs/models"
MODEL=os.path.join(ART,"brf_model.pkl")         # or rf_model.pkl
FEATS=os.path.join(ART,"rf_feature_columns.json")

# Buckets (tweak for demo to surface more High/Critical in 'alerts')
DEF_T_CRIT,DEF_T_HIGH,DEF_T_MED = 0.95,0.85,0.50
T_CRIT, T_HIGH, T_MED = DEF_T_CRIT, DEF_T_HIGH, DEF_T_MED
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

ap=argparse.ArgumentParser()
ap.add_argument("--base", default="alerts_api", help="Table/view to read new ids from")
ap.add_argument("--batch", type=int, default=200, help="Batch size")
ap.add_argument("--tcrit", type=float, default=DEF_T_CRIT, help="Critical threshold")
ap.add_argument("--thigh", type=float, default=DEF_T_HIGH, help="High threshold")
ap.add_argument("--tmed",  type=float, default=DEF_T_MED,  help="Medium threshold")
args=ap.parse_args()
T_CRIT, T_HIGH, T_MED = args.tcrit, args.thigh, args.tmed

with open(FEATS) as f: feature_cols = json.load(f)
model = joblib.load(MODEL)
is_pipeline = hasattr(model, "named_steps")

# SQLite: autocommit + timeouts + busy retry
conn=sqlite3.connect(DB, timeout=30.0, isolation_level=None)
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA synchronous=NORMAL;")
conn.execute("PRAGMA busy_timeout=30000;")
cur=conn.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS wz_scores_if (
  id TEXT PRIMARY KEY, risk_score REAL, risk_bucket TEXT, scored_at TEXT
)""")

# Only try to index if --base is a real table (not a view)
row = cur.execute("SELECT type FROM sqlite_master WHERE name=?", (args.base,)).fetchone()
if row and row[0].lower() == "table":
    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{args.base}_id ON {args.base}(id)")
    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{args.base}_ts ON {args.base}(timestamp)")

print(f"[online] model: {MODEL}  pipeline={is_pipeline}  base: {args.base}  batch={args.batch}")

# --- recent-first + backlog fetch using timestamp order ---
def fetch_unscored(limit):
    # half newest, half oldest (keeps UI fresh while draining backlog)
    recent_n = max(1, limit // 2)

    recent = cur.execute(f"""
      SELECT a.id, a.rule_level, a.rule_description, a.source_ip, a.destination_ip, a.timestamp
      FROM {args.base} a
      LEFT JOIN wz_scores_if s ON s.id = a.id
      WHERE s.id IS NULL
      ORDER BY a.timestamp DESC
      LIMIT ?
    """,(recent_n,)).fetchall()

    rest = limit - len(recent)
    if rest <= 0:
        return recent

    old = cur.execute(f"""
      SELECT a.id, a.rule_level, a.rule_description, a.source_ip, a.destination_ip, a.timestamp
      FROM {args.base} a
      LEFT JOIN wz_scores_if s ON s.id = a.id
      WHERE s.id IS NULL
      ORDER BY a.timestamp ASC
      LIMIT ?
    """,(rest,)).fetchall()

    return recent + old

def write_scores_with_retry(rows, probs, max_tries=8):
    now=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    payload=[(rid, float(p), bucket(float(p)), now) for (rid, *_), p in zip(rows, probs)]
    tries=0
    while True:
        try:
            cur.executemany(
              "INSERT OR REPLACE INTO wz_scores_if (id,risk_score,risk_bucket,scored_at) VALUES (?,?,?,?)",
              payload
            )
            return
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and tries < max_tries:
                sleep = min(5.0, 0.25 * (2 ** tries) * (1 + 0.25*random.random()))
                time.sleep(sleep); tries += 1; continue
            raise

def build_feature_frame(rows):
    df = pd.DataFrame([{c: np.nan for c in feature_cols} for _ in rows])
    def set_if(c, s):
        if c in df.columns: df[c]=s
    ids,lvl,desc,src,dst,ts = zip(*rows)
    set_if("rule_level", pd.to_numeric(lvl, errors="coerce"))
    set_if("is_nmap", [1 if ("nmap" in str(d).lower()) else 0 for d in desc])
    set_if("src_private", [1 if is_private(s) else 0 if is_private(s) is not None else np.nan for s in src])
    set_if("dst_private", [1 if is_private(d) else 0 if is_private(d) is not None else np.nan for d in dst])
    set_if("hour", [hour_or_nan(t) for t in ts])
    set_if("srcip_int", [ip_to_int(s) for s in src])
    set_if("dstip_int", [ip_to_int(d) for d in dst])

    # Keep feature names, ensure numeric & no NaNs/Infs
    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.replace([np.inf, -np.inf], [1e9, -1e9]).fillna(-1.0)
    return df

while True:
    rows = fetch_unscored(args.batch)
    if not rows:
        time.sleep(1.5); continue

    X = build_feature_frame(rows)
    probs = model.predict_proba(X)[:,1]  # pipeline or bare, we pass a DataFrame with correct names

    write_scores_with_retry(rows, probs)
    print(f"[online] scored {len(rows)} rows; last={probs[-1]:.3f}")
    time.sleep(0.2)
