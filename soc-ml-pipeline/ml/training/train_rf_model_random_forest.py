#!/usr/bin/env python3
"""
train_rf_model_random_forest.py  (CV calibration + BRF regularisation + lock-safe publish)

Master's-thesis PoC:
- Train RandomForest (RF) and BalancedRandomForest (BRF) with preprocessing in Pipelines (no leakage).
- Optional time-based split (if a timestamp column exists or is provided).
- Calibrate probabilities via cross-validation (cv=N) for stability (RF: isotonic by default; BRF: sigmoid by default).
- Evaluate (AUC, AP, best-F1), store metrics & importances in SQLite.
- Score ALL rows into wz_scores_rf / wz_scores_brf and publish one to wz_scores_if.
- Lock-safe publish: uses a static backup table and WAL + busy_timeout to avoid "database is locked".

Run:
    python3 /home/ubuntu/wazuh-logs/train_rf_model_random_forest.py
    # examples:
    #   ... --publish rf
    #   ... --cv-calibration 5 --brf-calibration sigmoid --rf-calibration isotonic
    #   ... --brf-max-depth 20 --brf-min-samples-leaf 10

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
    """Pick monotonic Critical/High/Medium cutoffs from score quantiles; fall back if empty."""
    if len(scores) == 0:
        return 0.9, 0.7, 0.4
    crit = float(np.quantile(scores, qcrit))
    high = float(np.quantile(scores, qhigh))
    med  = float(np.quantile(scores, qmed))
    # Enforce monotonicity (may collapse if distribution is extremely peaked)
    crit = max(crit, high, med)
    high = min(crit, max(high, med))
    eps = 1e-6
    if high >= crit:
        high = max(med, min(crit - eps, high))
    if med >= high:
        med = max(0.0, min(high - eps, med))
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
    return X.merge(y, on="id", how="inner")

def evaluate_and_log(name: str,
                     proba_test: np.ndarray,
                     y_test: pd.Series,
                     model_obj,
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

    # -------- Feature importances (if available) ----------
    fi_df = None
    clf = None
    try:
        # CalibratedClassifierCV wraps a Pipeline; estimator is accessible via base_estimator
        if isinstance(model_obj, CalibratedClassifierCV):
            base = model_obj.base_estimator
            if hasattr(base, "named_steps"):
                clf = base.named_steps.get("clf", None)
        else:
            named = getattr(model_obj, "named_steps", {})
            cal = named.get("cal", None)
            if cal is not None and hasattr(cal, "base_estimator"):
                base = cal.base_estimator
                if hasattr(base, "named_steps"):
                    clf = base.named_steps.get("clf", None)
            else:
                clf = named.get("clf", None)
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

    if fi_df is not None:
        con.execute("DELETE FROM model_feature_importance WHERE model=?", (name,))
        con.executemany(
            "INSERT OR REPLACE INTO model_feature_importance(model,feature,importance,trained_at) VALUES(?,?,?,?)",
            [(name, r.feature, float(r.importance), trained_at) for r in fi_df.itertuples(index=False)]
        )

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

    scored = pd.DataFrame({"id": ids.values, "risk_score": proba_all})
    scored["risk_bucket"] = [bucketize(p, tcrit, thigh, tmed) for p in scored["risk_score"].tolist()]
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
    ap.add_argument("--max-depth", type=int, default=None)  # RF max_depth; BRF has its own flag below

    # calibration/regularisation controls
    ap.add_argument("--cv-calibration", type=int, default=5, help="CV folds for CalibratedClassifierCV (>=3).")
    ap.add_argument("--rf-calibration", choices=["isotonic","sigmoid"], default="isotonic",
                    help="Calibration for RF (default: isotonic).")
    ap.add_argument("--brf-calibration", choices=["isotonic","sigmoid"], default="sigmoid",
                    help="Calibration for BRF (default: sigmoid to avoid stepiness).")
    ap.add_argument("--brf-max-depth", type=int, default=20,
                    help="BRF max_depth (default: 20). Use <= 0 to disable cap (None).")
    ap.add_argument("--brf-min-samples-leaf", type=int, default=10,
                    help="BRF min_samples_leaf (default: 10).")

    # end-to-end defaults
    ap.add_argument("--score-all", action="store_true", default=True,
                    help="Score all rows and write to wz_scores_rf & wz_scores_brf (default: True).")
    ap.add_argument("--write-to-if", action="store_true", default=True,
                    help="Also replace wz_scores_if with --publish model (default: True).")
    ap.add_argument("--publish", choices=["rf","brf"], default="brf",
                    help="Which model's scores to publish to wz_scores_if (default: brf).")
    ap.add_argument("--qcrit", type=float, default=0.995, help="Quantile for Critical threshold")
    ap.add_argument("--qhigh", type=float, default=0.990, help="Quantile for High threshold")
    ap.add_argument("--qmed",  type=float, default=0.970, help="Quantile for Medium threshold")
    ap.add_argument("--ts-col", default="", help="Optional timestamp column in ml_features for time-based split")
    args = ap.parse_args()

    os.makedirs(ART_DIR, exist_ok=True)

    # Load & prepare
    df_all = load_features_labels(args.db)

    # Decide time column (if any)
    ts_col = None
    auto_ts_candidates = [c for c in ["timestamp", "ts", "event_time", "time"] if c in df_all.columns]
    if args.ts_col and args.ts_col in df_all.columns:
        ts_col = args.ts_col
    elif auto_ts_candidates:
        ts_col = auto_ts_candidates[0]

    # Drop leaky/forbidden columns
    extra_drop = [c.strip() for c in args.drop_cols.split(",") if c.strip()]
    to_drop = set(extra_drop)
    base_exclude = {"id", "is_important"}
    if ts_col:
        base_exclude.add(ts_col)

    feature_cols = [c for c in df_all.columns if c not in base_exclude and c not in to_drop]

    # Split
    if ts_col:
        df_sorted = df_all.sort_values(ts_col)
        split_idx = int(len(df_sorted)*0.80)
        train_df, test_df = df_sorted.iloc[:split_idx], df_sorted.iloc[split_idx:]
        print(f"Time-based split on '{ts_col}': train={len(train_df):,}, test={len(test_df):,}")
    else:
        train_df, test_df = train_test_split(
            df_all, test_size=0.20, random_state=42, stratify=df_all["is_important"]
        )
        print(f"Stratified random split: train={len(train_df):,}, test={len(test_df):,} (no timestamp column found)")

    X_train = train_df[feature_cols].copy()
    y_train = train_df["is_important"].copy()
    X_test  = test_df[feature_cols].copy()
    y_test  = test_df["is_important"].copy()

    # Preprocessing: numeric + ordinal-encode any object columns
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

    # ---------------- RF (CV calibration) ----------------
    rf_base = Pipeline([
        ("pre", pre),
        ("clf", RandomForestClassifier(
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,  # optional RF cap from CLI
            n_jobs=-1,
            random_state=42,
            bootstrap=True,
            class_weight="balanced"
        ))
    ])
    rf = CalibratedClassifierCV(rf_base, method=args.rf_calibration, cv=max(3, args.cv_calibration))
    rf.fit(X_train, y_train)
    proba_test_rf = rf.predict_proba(X_test)[:, 1]

    # ---------------- BRF (regularised + CV calibration) ----------------
    brf_max_depth = None if (args.brf_max_depth is None or args.brf_max_depth <= 0) else args.brf_max_depth
    brf_base = Pipeline([
        ("pre", pre),
        ("clf", BalancedRandomForestClassifier(
            n_estimators=args.n_estimators,
            max_depth=brf_max_depth,
            min_samples_leaf=max(1, args.brf_min_samples_leaf),
            max_features="sqrt",
            n_jobs=-1,
            random_state=42,
            sampling_strategy="auto",
            replacement=False,
            bootstrap=True  # explicit to silence FutureWarning (set False to adopt future default)
        ))
    ])
    brf = CalibratedClassifierCV(brf_base, method=args.brf_calibration, cv=max(3, args.cv_calibration))
    brf.fit(X_train, y_train)
    proba_test_brf = brf.predict_proba(X_test)[:, 1]

    # Persist artifacts (save the full calibrated models)
    joblib.dump(rf,  RF_MODEL_PATH)
    joblib.dump(brf, BRF_MODEL_PATH)
    with open(FEATURES_PATH, "w") as f:
        json.dump(feature_cols, f, indent=2)
    print(f"\nArtifacts saved to {ART_DIR} (rf_model.pkl, brf_model.pkl, rf_feature_columns.json)")

    # Evaluate & log both; then (optionally) score all & publish
    with sqlite3.connect(args.db, timeout=30) as con:
        # Friendlier concurrency (avoid "database is locked" with readers around)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA busy_timeout=10000;")

        thr_rf  = evaluate_and_log("rf",  proba_test_rf,  y_test, rf,  feature_cols, len(X_train), len(X_test), con)
        thr_brf = evaluate_and_log("brf", proba_test_brf, y_test, brf, feature_cols, len(X_train), len(X_test), con)

        if args.score_all:
            print("\nScoring all rows for both models…")
            X_all = df_all[feature_cols].copy()
            proba_all_rf  = rf.predict_proba(X_all)[:, 1]
            proba_all_brf = brf.predict_proba(X_all)[:, 1]

            score_and_write(con, "wz_scores_rf",  df_all["id"], proba_all_rf,
                            qcrit=args.qcrit, qhigh=args.qhigh, qmed=args.qmed)
            score_and_write(con, "wz_scores_brf", df_all["id"], proba_all_brf,
                            qcrit=args.qcrit, qhigh=args.qhigh, qmed=args.qmed)

            if args.write_to_if:
                src_table = "wz_scores_brf" if args.publish == "brf" else "wz_scores_rf"
                ensure_scores_table(con, "wz_scores_if")

                # Static backup table: no schema change during publish (lock-safe)
                con.execute("""
                  CREATE TABLE IF NOT EXISTS wz_scores_if_bak_static(
                    id TEXT PRIMARY KEY,
                    risk_score REAL,
                    risk_bucket TEXT,
                    scored_at TEXT
                  )
                """)
                con.execute("DELETE FROM wz_scores_if_bak_static")
                con.execute("INSERT INTO wz_scores_if_bak_static SELECT * FROM wz_scores_if")
                con.execute("DELETE FROM wz_scores_if")
                con.execute(f"""
                    INSERT INTO wz_scores_if(id, risk_score, risk_bucket, scored_at)
                    SELECT id, risk_score, risk_bucket, scored_at FROM {src_table}
                """)
                con.commit()
                print(f"Published {args.publish.upper()} to wz_scores_if (dashboard now reflects {args.publish.upper()}).")

if __name__ == "__main__":
    main()
