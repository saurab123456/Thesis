#!/usr/bin/env python3
"""
train_rf_brf_poc.py

Master's-thesis PoC:
- Train RandomForest (RF) and BalancedRandomForest (BRF) with preprocessing in Pipelines (no leakage).
- Optional time-based split (if a timestamp column exists or is provided).
- Calibrate probabilities (RF: isotonic; BRF: isotonic) using a small validation split.
- Evaluate (AUC, AP, best-F1), store metrics & importances in SQLite.
- Optionally score all rows into wz_scores_rf / wz_scores_brf and publish one to wz_scores_if.

Usage (example):
python3 train_rf_brf_poc.py \
  --db /home/ubuntu/wazuh-logs/wazuh.db \
  --drop-cols is_nmap,src_private,dst_private \
  --score-all \
  --write-to-if \
  --publish brf

If you have a timestamp column in ml_features (e.g., 'timestamp' or 'ts'):
  --ts-col timestamp
"""

import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from imblearn.ensemble import BalancedRandomForestClassifier

# ----------------------------- defaults & paths -------------------------------
DEFAULT_DB = "/home/ubuntu/wazuh-logs/wazuh.db"
ART_DIR = "/home/ubuntu/wazuh-logs/models"

RF_MODEL_PATH  = os.path.join(ART_DIR, "rf_model.pkl")
BRF_MODEL_PATH = os.path.join(ART_DIR, "brf_model.pkl")
FEATURES_PATH  = os.path.join(ART_DIR, "rf_feature_columns.json")

LEAKY_DEFAULT_DROP = ["is_nmap", "src_private", "dst_private"]  # extend via --drop-cols

# ----------------------------- helpers ---------------------------------------
def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def ensure_tables_for_metrics(con: sqlite3.Connection):
    con.execute("""
        CREATE TABLE IF NOT EXISTS model_metrics (
            model         TEXT PRIMARY KEY,  -- 'rf' or 'brf'
            trained_at    TEXT,
            auc           REAL,
            ap            REAL,
            best_f1       REAL,
            best_thr      REAL,
            n_train       INTEGER,
            n_test        INTEGER,
            pos_rate_test REAL,
            features_json TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS model_feature_importance (
            model      TEXT,                 -- 'rf' or 'brf'
            feature    TEXT,
            importance REAL,
            trained_at TEXT,
            PRIMARY KEY(model, feature)
        )
    """)

def ensure_scores_table(con: sqlite3.Connection, table: str):
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id          TEXT PRIMARY KEY,
            risk_score  REAL,
            risk_bucket TEXT,
            scored_at   TEXT
        )
    """)

def choose_bucket_thresholds_from_quantiles(scores: np.ndarray,
                                            qcrit=0.995, qhigh=0.99, qmed=0.97) -> Tuple[float,float,float]:
    if len(scores) == 0:
        return 0.9, 0.7, 0.4
    crit = float(np.quantile(scores, qcrit))
    high = float(np.quantile(scores, qhigh))
    med  = float(np.quantile(scores, qmed))
    # monotonic
    crit = max(crit, high, med)
    high = min(crit, max(high, med))
    return crit, high, med

def bucketize(p: float, tcrit: float, thigh: float, tmed: float) -> str:
    if p >= tcrit: return "Critical"
    if p >= thigh: return "High"
    if p >= tmed:  return "Medium"
    return "Low"

def load_features_labels(db_path: str) -> pd.DataFrame:
    with sqlite3.connect(db_path) as con:
        X = pd.read_sql_query("SELECT * FROM ml_features", con)
        y = pd.read_sql_query("SELECT id, is_important FROM ml_labels", con)
    df = X.merge(y, on="id", how="inner")
    return df

def evaluate_and_log(name: str,
                     proba_test: np.ndarray,
                     y_test: pd.Series,
                     model_pipeline: Pipeline,
                     feature_cols: List[str],
                     n_train: int,
                     n_test: int,
                     con: sqlite3.Connection):
    """Compute AUC/AP/F1*, print report & confusion; store metrics & importances."""
    auc = roc_auc_score(y_test, proba_test)
    ap  = average_precision_score(y_test, proba_test)

    prec, rec, thrs = precision_recall_curve(y_test, proba_test)
    f1s = (2 * prec * rec) / np.clip(prec + rec, 1e-12, None)
    best_idx = int(np.nanargmax(f1s))
    best_f1  = float(f1s[best_idx])
    best_thr = float(thrs[best_idx-1]) if best_idx > 0 and best_idx-1 < len(thrs) else 0.5

    y_pred = (proba_test >= best_thr).astype(int)
    print(f"\n[{name.upper()}]  AUC={auc:.3f}  AP={ap:.3f}  F1*={best_f1:.3f}  thr*={best_thr:.3f}")
    print(classification_report(y_test, y_pred, digits=3))
    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    # Feature importances from the classifier step if available
    fi_df = None
    clf = None
    try:
        # If calibrated, the pipeline looks like: ('cal', CalibratedClassifierCV)
        # The base estimator we fitted with 'prefit' is itself a Pipeline([... ('clf', RF/BRF) ])
        cal = model_pipeline.named_steps.get("cal", None)
        if cal is not None and hasattr(cal, "base_estimator"):
            base = cal.base_estimator  # this is the fitted Pipeline(pre -> clf)
            clf = base.named_steps.get("clf", None)
        else:
            clf = model_pipeline.named_steps.get("clf", None)
    except Exception:
        clf = None

    if clf is not None and hasattr(clf, "feature_importances_"):
        fi_df = pd.DataFrame({
            "feature": feature_cols,
            "importance": np.asarray(clf.feature_importances_).tolist()
        }).sort_values("importance", ascending=False)
        print(f"\nTop 10 feature importances ({name}):")
        print(fi_df.head(10).to_string(index=False))

    ensure_tables_for_metrics(con)
    trained_at = utc_now_iso()

    # Store importances
    if fi_df is not None:
        con.execute("DELETE FROM model_feature_importance WHERE model=?", (name,))
        con.executemany(
            "INSERT OR REPLACE INTO model_feature_importance(model,feature,importance,trained_at) VALUES(?,?,?,?)",
            [(name, r.feature, float(r.importance), trained_at) for r in fi_df.itertuples(index=False)]
        )

    # Store metrics
    con.execute("""
        INSERT OR REPLACE INTO model_metrics
            (model, trained_at, auc, ap, best_f1, best_thr, n_train, n_test, pos_rate_test, features_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        name, trained_at, float(auc), float(ap), float(best_f1), float(best_thr),
        int(n_train), int(n_test), float((y_test==1).mean()),
        json.dumps(feature_cols)
    ))
    con.commit()

    return best_thr

def score_and_write(con: sqlite3.Connection,
                    table: str,
                    ids: pd.Series,
                    proba_all: np.ndarray,
                    qcrit: float, qhigh: float, qmed: float):
    ensure_scores_table(con, table)
    tcrit, thigh, tmed = choose_bucket_thresholds_from_quantiles(
        proba_all, qcrit=qcrit, qhigh=qhigh, qmed=qmed
    )
    print(f"[{table}] Bucket thresholds: Critical≥{tcrit:.3f}, High≥{thigh:.3f}, Medium≥{tmed:.3f}")

    scored = pd.DataFrame({
        "id": ids.values,
        "risk_score": proba_all,
    })
    scored["risk_bucket"] = [
        bucketize(p, tcrit, thigh, tmed) for p in scored["risk_score"].tolist()
    ]
    scored["scored_at"] = utc_now_iso()

    con.execute(f"DELETE FROM {table}")
    con.executemany(
        f"INSERT OR REPLACE INTO {table}(id,risk_score,risk_bucket,scored_at) VALUES(?,?,?,?)",
        list(scored.itertuples(index=False, name=None))
    )
    con.commit()
    print(f"Wrote {len(scored):,} rows to {table}")

# ----------------------------- main ------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--drop-cols", default=",".join(LEAKY_DEFAULT_DROP),
                    help="Comma-separated extra columns to drop (in addition to defaults).")
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--score-all", action="store_true",
                    help="Score all rows and write to wz_scores_rf & wz_scores_brf")
    ap.add_argument("--write-to-if", action="store_true",
                    help="Also replace wz_scores_if with the chosen model via --publish")
    ap.add_argument("--publish", choices=["rf","brf"], default="brf",
                    help="Which model's scores to publish to wz_scores_if when --write-to-if is set")
    ap.add_argument("--qcrit", type=float, default=0.995, help="Quantile for Critical threshold")
    ap.add_argument("--qhigh", type=float, default=0.990, help="Quantile for High threshold")
    ap.add_argument("--qmed",  type=float, default=0.970, help="Quantile for Medium threshold")
    ap.add_argument("--ts-col", default="", help="Optional timestamp column in ml_features for time-based split")
    args = ap.parse_args()

    os.makedirs(ART_DIR, exist_ok=True)

    # Load & prepare
    df = load_features_labels(args.db)

    # Decide time column (if any)
    ts_col = None
    auto_ts_candidates = [c for c in ["timestamp", "ts", "event_time", "time"] if c in df.columns]
    if args.ts_col and args.ts_col in df.columns:
        ts_col = args.ts_col
    elif auto_ts_candidates:
        ts_col = auto_ts_candidates[0]

    # Drop leaky/forbidden columns
    extra_drop = [c.strip() for c in args.drop_cols.split(",") if c.strip()]
    to_drop = set(extra_drop)
    base_exclude = {"id", "is_important"}
    if ts_col:
        base_exclude.add(ts_col)

    feature_cols = [c for c in df.columns if c not in base_exclude and c not in to_drop]

    # Split
    if ts_col:
        # time-based: train on older, test on newer
        df = df.sort_values(ts_col)
        split_idx = int(len(df)*0.80)
        train_df, test_df = df.iloc[:split_idx], df.iloc[split_idx:]
        print(f"Time-based split on '{ts_col}': train={len(train_df)}, test={len(test_df)}")
    else:
        train_df, test_df = train_test_split(df, test_size=0.20, random_state=42, stratify=df["is_important"])
        print(f"Stratified random split: train={len(train_df)}, test={len(test_df)} (no timestamp column found)")

    X_train = train_df[feature_cols].copy()
    y_train = train_df["is_important"].copy()
    X_test  = test_df[feature_cols].copy()
    y_test  = test_df["is_important"].copy()

    # Preprocessing: numeric + ordinal-encode any object columns (robust + minimal)
    num_cols = X_train.select_dtypes(include=[np.number]).columns.tolist()
    obj_cols = [c for c in feature_cols if c not in num_cols]

    num_tf = Pipeline([("imp", SimpleImputer(strategy="median"))])
    obj_tf = Pipeline([
        ("imp", SimpleImputer(strategy="most_frequent")),
        ("enc", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1))
    ]) if obj_cols else "drop"

    pre = ColumnTransformer(
        transformers=[
            ("num", num_tf, num_cols),
            ("obj", obj_tf, obj_cols)
        ],
        remainder="drop"
    )

    # ---------------- RF (with calibration) ----------------
    rf_base = Pipeline([
        ("pre", pre),
        ("clf", RandomForestClassifier(
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            n_jobs=-1,
            random_state=42,
            bootstrap=True,
            class_weight="balanced"
        ))
    ])

    # hold-out validation for calibration (no leakage)
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.20, random_state=42, stratify=y_train
    )
    rf_base.fit(X_tr, y_tr)
    rf = Pipeline([
        ("base", rf_base),
        ("cal", CalibratedClassifierCV(rf_base, method="isotonic", cv="prefit"))
    ])
    rf.named_steps["cal"].fit(X_val, y_val)
    proba_test_rf = rf.predict_proba(X_test)[:, 1]

    # ---------------- BRF (with calibration) ----------------
    brf_base = Pipeline([
        ("pre", pre),
        ("clf", BalancedRandomForestClassifier(
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            n_jobs=-1,
            random_state=42,
            sampling_strategy="auto",
            replacement=False
        ))
    ])
    X_tr2, X_val2, y_tr2, y_val2 = train_test_split(
        X_train, y_train, test_size=0.20, random_state=123, stratify=y_train
    )
    brf_base.fit(X_tr2, y_tr2)
    brf = Pipeline([
        ("base", brf_base),
        ("cal", CalibratedClassifierCV(brf_base, method="isotonic", cv="prefit"))
    ])
    brf.named_steps["cal"].fit(X_val2, y_val2)
    proba_test_brf = brf.predict_proba(X_test)[:, 1]

    # Persist artifacts (save the full calibrated pipelines)
    joblib.dump(rf,  RF_MODEL_PATH)
    joblib.dump(brf, BRF_MODEL_PATH)
    with open(FEATURES_PATH, "w") as f:
        json.dump(feature_cols, f, indent=2)
    print(f"\nArtifacts saved to {ART_DIR} (rf_model.pkl, brf_model.pkl, rf_feature_columns.json)")

    # Evaluate & log both
    with sqlite3.connect(args.db) as con:
        thr_rf  = evaluate_and_log("rf",  proba_test_rf,  y_test, rf,  feature_cols, len(X_train), len(X_test), con)
        thr_brf = evaluate_and_log("brf", proba_test_brf, y_test, brf, feature_cols, len(X_train), len(X_test), con)

        # Score all rows (optional)
        if args.score_all:
            print("\nScoring all rows for both models…")
            # Important: use the same feature_cols!
            X_all = df[feature_cols].copy()
            proba_all_rf  = rf.predict_proba(X_all)[:, 1]
            proba_all_brf = brf.predict_proba(X_all)[:, 1]

            score_and_write(con, "wz_scores_rf",  df["id"], proba_all_rf,
                            qcrit=args.qcrit, qhigh=args.qhigh, qmed=args.qmed)
            score_and_write(con, "wz_scores_brf", df["id"], proba_all_brf,
                            qcrit=args.qcrit, qhigh=args.qhigh, qmed=args.qmed)

            if args.write_to_if:
                src_table = "wz_scores_brf" if args.publish == "brf" else "wz_scores_rf"
                # safety: ensure target exists
                ensure_scores_table(con, "wz_scores_if")
                bak = f"wz_scores_if_bak_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                con.execute(f"CREATE TABLE IF NOT EXISTS {bak} AS SELECT * FROM wz_scores_if")
                con.execute("DELETE FROM wz_scores_if")
                con.execute(f"""
                    INSERT INTO wz_scores_if(id, risk_score, risk_bucket, scored_at)
                    SELECT id, risk_score, risk_bucket, scored_at FROM {src_table}
                """)
                con.commit()
                print(f"Published {args.publish.upper()} to wz_scores_if (dashboard now reflects {args.publish.upper()}).")

if __name__ == "__main__":
    main()
