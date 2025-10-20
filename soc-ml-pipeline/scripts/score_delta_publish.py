#!/usr/bin/env python3
"""
score_delta_publish.py
Score only NEW ml_features rows for BOTH RF and BRF with the latest saved models,
write to wz_scores_rf / wz_scores_brf, and (optionally) publish one model to wz_scores_if.
"""

import argparse, sqlite3, json, os, sys
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from joblib import load

DEFAULT_DB = "/home/ubuntu/wazuh-logs/wazuh.db"
MODELS_DIR = "/home/ubuntu/wazuh-logs/models"
FEATURES_JSON = os.path.join(MODELS_DIR, "rf_feature_columns.json")

TABLE_RF  = "wz_scores_rf"
TABLE_BRF = "wz_scores_brf"
TABLE_IF  = "wz_scores_if"

def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def load_features_list():
    with open(FEATURES_JSON, "r", encoding="utf-8") as f:
        cols = json.load(f)
    # models were trained with named columns; do NOT include id
    return [c for c in cols if c != "id"]

def ensure_scores_table(con, table):
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id          TEXT PRIMARY KEY,
            risk_score  REAL,
            risk_bucket TEXT,
            scored_at   TEXT
        )
    """)

def fetch_best_thr(con, model_tag):
    try:
        r = con.execute(
            "SELECT best_thr FROM model_metrics WHERE model=? ORDER BY trained_at DESC LIMIT 1",
            (model_tag,)
        ).fetchone()
        if r and r[0] is not None:
            return float(r[0])
    except Exception:
        pass
    return None

def get_new_ids(con, score_table, limit):
    q = f"""
      SELECT f.id
      FROM ml_features f
      LEFT JOIN {score_table} s ON s.id = f.id
      WHERE s.id IS NULL
      LIMIT ?;
    """
    return [r[0] for r in con.execute(q, (limit,)).fetchall()]

def fetch_df(con, ids, feat_cols) -> pd.DataFrame:
    """Return a DataFrame with columns exactly feat_cols (filled via COALESCE(...,0))."""
    if not ids:
        return pd.DataFrame(columns=["id"] + feat_cols)
    ph = ",".join(["?"] * len(ids))
    cols_expr = ",".join([f"COALESCE({c},0) AS \"{c}\"" for c in feat_cols])
    q = f"SELECT id, {cols_expr} FROM ml_features WHERE id IN ({ph})"
    df = pd.read_sql_query(q, con, params=ids)
    # enforce column order
    return df[["id"] + feat_cols]

def bucketize(p, tcrit, thigh, tmed):
    if p >= tcrit: return "Critical"
    if p >= thigh: return "High"
    if p >= tmed:  return "Medium"
    return "Low"

def score_one_model(con, model_tag, model_path, score_table, feat_cols, batch, crit, high, med):
    if not os.path.isfile(model_path):
        print(f"[{utcnow()}] SKIP {model_tag}: missing model {model_path}", file=sys.stderr)
        return 0

    ensure_scores_table(con, score_table)

    ids_needed = get_new_ids(con, score_table, batch)
    if not ids_needed:
        print(f"[{utcnow()}] {model_tag.upper()}: 0 new rows.")
        return 0

    df = fetch_df(con, ids_needed, feat_cols)
    if df.empty:
        print(f"[{utcnow()}] {model_tag.upper()}: no features for {len(ids_needed)} ids.")
        return 0

    model = load(model_path)

    # Predict using DataFrame (required by ColumnTransformer with named columns)
    proba = model.predict_proba(df[feat_cols])[:, 1]

    # Thresholds: enforce Medium >= best_thr (from training)
    best_thr = fetch_best_thr(con, model_tag)
    tcrit = crit
    thigh = high
    tmed  = max(med, best_thr if best_thr is not None else med)

    now = utcnow()
    rows = []
    for i, s in zip(df["id"].tolist(), proba.tolist()):
        s = float(s)
        rows.append((i, s, bucketize(s, tcrit, thigh, tmed), now))

    with con:
        con.executemany(
            f"INSERT OR REPLACE INTO {score_table}(id,risk_score,risk_bucket,scored_at) VALUES (?,?,?,?)",
            rows
        )

    print(f"[{now}] {model_tag.upper()}: Scored {len(rows)} new rows (crit≥{tcrit:.2f}, high≥{thigh:.2f}, med≥{tmed:.2f}).")
    return len(rows)

def publish_to_if(con, src_table):
    ensure_scores_table(con, TABLE_IF)
    with con:
        con.execute("DELETE FROM wz_scores_if")
        con.execute(f"""
            INSERT INTO wz_scores_if(id, risk_score, risk_bucket, scored_at)
            SELECT id, risk_score, risk_bucket, scored_at FROM {src_table}
        """)
    print(f"[{utcnow()}] Published {src_table} → wz_scores_if.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--batch", type=int, default=50000, help="Max rows per model per run")
    ap.add_argument("--crit", type=float, default=0.99, help="Critical bucket cutoff")
    ap.add_argument("--high", type=float, default=0.90, help="High bucket cutoff")
    ap.add_argument("--med",  type=float, default=0.50, help="Medium bucket base cutoff (raised to best_thr if higher)")
    ap.add_argument("--publish", choices=["rf","brf","none"], default="brf",
                    help="Copy chosen model's table into wz_scores_if (default: brf)")
    args = ap.parse_args()

    feat_cols = load_features_list()
    con = sqlite3.connect(args.db)
    con.execute("PRAGMA journal_mode=WAL;")

    n_brf = score_one_model(
        con, "brf",
        os.path.join(MODELS_DIR, "brf_model.pkl"),
        TABLE_BRF, feat_cols, args.batch, args.crit, args.high, args.med
    )
    n_rf = score_one_model(
        con, "rf",
        os.path.join(MODELS_DIR, "rf_model.pkl"),
        TABLE_RF, feat_cols, args.batch, args.crit, args.high, args.med
    )

    if args.publish != "none":
        src = TABLE_BRF if args.publish == "brf" else TABLE_RF
        publish_to_if(con, src)

    con.close()

if __name__ == "__main__":
    main()
