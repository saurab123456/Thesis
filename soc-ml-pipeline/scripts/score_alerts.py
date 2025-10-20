#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
score_alerts.py — Score Wazuh alerts with a trained RF model.

This script:
  - Loads rf_model.pkl, feature_columns.pkl, and encoders/*.pkl
  - Pulls rows from SQLite (default alerts.db:alerts_enriched)
  - Rebuilds engineered features (srcip_int/dstip_int, mitre_missing if possible)
  - Applies the SAME LabelEncoder mappings (safe for unseen categories)
  - Selects columns in the EXACT order from feature_columns.pkl
  - Writes scored_alerts.csv with risk_score in [0,1]

Usage:
  python3 score_alerts.py \
    --db alerts.db \
    --table alerts_enriched \
    --out scored_alerts.csv \
    --limit 50000 \
    --where "rule_level IS NOT NULL"

Assumptions:
  - Model is a scikit-learn classifier with predict_proba (e.g., BalancedRandomForestClassifier)
  - feature_columns.pkl contains the final training column order (list[str])
  - encoders/*.pkl holds sklearn.preprocessing.LabelEncoder objects named by column
"""

import os
import sys
import argparse
import sqlite3
import logging
from contextlib import closing
import warnings
import ipaddress
import json

import numpy as np
import pandas as pd
import joblib

# ------------------------- Defaults & Constants -------------------------

ENCODERS_DIR_DEFAULT = "encoders"
MODEL_PATH_DEFAULT = "rf_model.pkl"
FEATURE_COLS_PATH_DEFAULT = "feature_columns.pkl"
DEFAULT_DB = "alerts.db"
DEFAULT_TABLE = "alerts_enriched"
DEFAULT_OUT = "scored_alerts.csv"

# Columns we may engineer if raw columns exist
RAW_SRCIP_COLS = ["srcip", "source_ip", "src_ip"]
RAW_DSTIP_COLS = ["dstip", "destination_ip", "dst_ip"]

# ------------------------- Logging -------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s"
)
log = logging.getLogger("score_alerts")

# ------------------------- Helpers -------------------------

def ip_to_int_safe(x):
    """Convert IPv4/IPv6 to integer; return NaN if missing/invalid."""
    try:
        if x is None or x == "" or str(x).lower() == "missing":
            return np.nan
        return int(ipaddress.ip_address(str(x)))
    except Exception:
        return np.nan

def first_present(df, candidates):
    """Return the first column name from candidates that exists in df, else None."""
    for c in candidates:
        if c in df.columns:
            return c
    return None

def load_encoders(enc_dir):
    """Load per-column LabelEncoders from a directory. Returns dict[col] = encoder."""
    if not os.path.isdir(enc_dir):
        log.warning("Encoders directory %s not found; proceeding without encoders.", enc_dir)
        return {}

    encoders = {}
    for name in os.listdir(enc_dir):
        if not name.endswith(".pkl"):
            continue
        col = name[:-4]  # drop .pkl
        path = os.path.join(enc_dir, name)
        try:
            enc = joblib.load(path)
            encoders[col] = enc
        except Exception as e:
            log.warning("Failed to load encoder %s: %s", path, e)
    if encoders:
        log.info("Loaded %d encoders from %s", len(encoders), enc_dir)
    else:
        log.info("No encoders loaded from %s", enc_dir)
    return encoders

def transform_with_encoder(series, enc):
    """
    Transform a pandas Series via a LabelEncoder while SAFELY handling unseen values.
    Strategy:
      - Build mapping dict from enc.classes_ -> codes via LabelEncoder.transform
      - Map unknowns to -1 (a value the model never saw; trees handle this fine)
    """
    # Build mapping dict using the encoder's classes_
    try:
        classes = list(enc.classes_)
    except Exception:
        # Fallback: try to use encoder as-is (might already be a mapping dict)
        mapper = enc
        return series.map(lambda v: mapper.get(v, -1)).astype("int64")

    # Create a fast mapping: class -> code
    try:
        codes = enc.transform(classes)
    except Exception:
        # Some custom encoders may not expose transform(classes) cleanly
        # Fall back to enumerating classes
        codes = np.arange(len(classes))

    mapping = {cls: int(code) for cls, code in zip(classes, codes)}

    def map_one(v):
        # Normalize NaN/missing to a sentinel
        if pd.isna(v) or v is None:
            return -1
        return mapping.get(v, -1)

    return series.map(map_one).astype("int64")

def ensure_feature_order(X, feature_order):
    """Reindex columns to feature_order. Missing columns filled with 0; extra columns dropped."""
    missing = [c for c in feature_order if c not in X.columns]
    extra = [c for c in X.columns if c not in feature_order]
    if missing:
        log.warning("Adding %d missing feature(s) with 0: %s", len(missing), missing)
        for c in missing:
            X[c] = 0
    if extra:
        log.warning("Dropping %d extra column(s) not used by the model: %s", len(extra), extra)
        X = X.drop(columns=extra, errors="ignore")
    return X.reindex(columns=feature_order)

def infer_positive_class_index(model, class_names=None):
    """
    Determine the index of the 'positive' class (label 1).
    If model.classes_ exists and includes 1, return its index; else default to the max-proba column.
    """
    try:
        classes_ = getattr(model, "classes_", None)
        if classes_ is not None and 1 in classes_:
            return list(classes_).index(1)
        # If binary labels are 0/1 but shuffled:
        if classes_ is not None and len(classes_) == 2:
            # If 1 is not present, pick the 'greater' label as positive (best-effort)
            return int(np.argmax(classes_))
    except Exception:
        pass
    # Fallback: assume last column of predict_proba is "positive-ish"
    return -1

# ------------------------- Core -------------------------

def fetch_dataframe(db_path, table, where=None, limit=None):
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"SQLite DB not found: {db_path}")

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        base = f"SELECT * FROM {table}"
        clauses = []
        if where:
            clauses.append(f"WHERE {where}")
        if limit is not None and int(limit) > 0:
            clauses.append(f"LIMIT {int(limit)}")
        sql = " ".join([base] + clauses)
        log.info("SQL: %s", sql)
        df = pd.read_sql_query(sql, conn)
    log.info("Loaded %d records with %d columns from %s:%s", len(df), len(df.columns), db_path, table)
    return df

def engineer_features(df):
    """Add engineered features (srcip_int, dstip_int, mitre_missing) when possible."""
    df = df.copy()

    # srcip_int
    src_col = first_present(df, RAW_SRCIP_COLS)
    if src_col and "srcip_int" not in df.columns:
        df["srcip_int"] = df[src_col].apply(ip_to_int_safe)

    # dstip_int
    dst_col = first_present(df, RAW_DSTIP_COLS)
    if dst_col and "dstip_int" not in df.columns:
        df["dstip_int"] = df[dst_col].apply(ip_to_int_safe)

    # mitre_missing: 1 if technique_id missing/empty, else 0 (only if technique_id exists)
    if "technique_id" in df.columns and "mitre_missing" not in df.columns:
        df["mitre_missing"] = df["technique_id"].apply(
            lambda v: 1 if (pd.isna(v) or str(v).strip() == "" or str(v).lower() == "null") else 0
        ).astype("int64")

    return df

def apply_encoders(df, encoders):
    """Apply saved per-column LabelEncoders to matching object/categorical columns."""
    if not encoders:
        return df

    df = df.copy()
    for col, enc in encoders.items():
        if col not in df.columns:
            # Some encoded columns might be synthetic; add as missing
            log.debug("Encoded column %s not in dataframe; filling with -1.", col)
            df[col] = -1
            continue

        # Apply only if dtype looks categorical/object; numeric are left untouched
        if pd.api.types.is_object_dtype(df[col]) or pd.api.types.is_categorical_dtype(df[col]):
            try:
                df[col] = transform_with_encoder(df[col], enc)
            except Exception as e:
                log.warning("Failed to encode column %s with saved encoder: %s. Filling with -1.", col, e)
                df[col] = -1
        else:
            # Column exists but is numeric; leave as-is
            pass

    return df

def main():
    parser = argparse.ArgumentParser(description="Score alerts with a trained RF model.")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to SQLite DB (default: alerts.db)")
    parser.add_argument("--table", default=DEFAULT_TABLE, help="Table name (default: alerts_enriched)")
    parser.add_argument("--where", default=None, help="Optional SQL WHERE clause (no 'WHERE')")
    parser.add_argument("--limit", type=int, default=None, help="Optional LIMIT for rows")
    parser.add_argument("--model", default=MODEL_PATH_DEFAULT, help="Path to trained model pickle (default: rf_model.pkl)")
    parser.add_argument("--features", default=FEATURE_COLS_PATH_DEFAULT, help="Path to feature_columns.pkl")
    parser.add_argument("--encoders", default=ENCODERS_DIR_DEFAULT, help="Directory containing per-column encoders/*.pkl")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Output CSV path (default: scored_alerts.csv)")
    parser.add_argument("--prob_column", default="risk_score", help="Name for probability column (default: risk_score)")
    parser.add_argument("--keep_cols", nargs="*", default=None, help="Explicit list of original columns to keep in output (default: keep all)")
    args = parser.parse_args()

    # Load data
    df_raw = fetch_dataframe(args.db, args.table, where=args.where, limit=args.limit)
    mem_mb = df_raw.memory_usage(deep=True).sum() / (1024**2)
    log.info("Memory after load: %.2f MB", mem_mb)

    # Engineer features
    df = engineer_features(df_raw)
    log.info("Engineered feature columns now available: %s",
             [c for c in ["srcip_int", "dstip_int", "mitre_missing"] if c in df.columns])

    # Load encoders & apply
    encoders = load_encoders(args.encoders)
    df_enc = apply_encoders(df, encoders)

    # Load feature order
    if not os.path.exists(args.features):
        raise FileNotFoundError(f"feature_columns.pkl not found at {args.features}")
    feature_order = joblib.load(args.features)
    if not isinstance(feature_order, (list, tuple)):
        raise ValueError("feature_columns.pkl must contain a list/tuple of column names.")
    log.info("Feature order length: %d", len(feature_order))

    # Build X in exact order
    X = df_enc.copy()
    # Coerce any remaining object columns to numeric (safe fill)
    for col in X.columns:
        if pd.api.types.is_object_dtype(X[col]) or pd.api.types.is_categorical_dtype(X[col]):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = ensure_feature_order(X, feature_order)

    # Load model
    if not os.path.exists(args.model):
        raise FileNotFoundError(f"Model pickle not found: {args.model}")
    model = joblib.load(args.model)

    # Predict probabilities
    if not hasattr(model, "predict_proba"):
        raise AttributeError("Loaded model does not support predict_proba().")

    probs = model.predict_proba(X.values)
    pos_idx = infer_positive_class_index(model)
    if pos_idx < 0 or pos_idx >= probs.shape[1]:
        log.warning("Could not confidently determine positive class index; using last column.")
        pos_idx = probs.shape[1] - 1

    risk = probs[:, pos_idx].astype(float)
    # Clamp to [0,1] just in case
    risk = np.clip(risk, 0.0, 1.0)

    # Build output
    out_df = df_raw.copy() if args.keep_cols is None else df_raw[args.keep_cols].copy()
    out_df[args.prob_column] = risk

    # Helpful metadata columns (optional)
    out_df["_model_path"] = os.path.abspath(args.model)
    out_df["_feature_count"] = len(feature_order)

    # Save
    out_path = args.out
    out_df.to_csv(out_path, index=False)
    log.info("✅ Wrote %d scored rows to %s", len(out_df), out_path)

    # Also print a tiny summary to stdout
    summary = {
        "rows_scored": int(len(out_df)),
        "output": os.path.abspath(out_path),
        "prob_column": args.prob_column,
        "model": os.path.abspath(args.model),
        "features": os.path.abspath(args.features),
        "encoders_dir": os.path.abspath(args.encoders) if os.path.isdir(args.encoders) else None,
    }
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.exception("Fatal error: %s", e)
        sys.exit(1)
