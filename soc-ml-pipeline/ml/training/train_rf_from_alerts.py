#!/usr/bin/env python3
"""
Score alerts with the RF model trained in train_rf_from_alerts.py.

This script:
  - Loads rf_model.pkl, feature_columns.pkl, and encoders/*.pkl
  - Pulls rows from SQLite (default alerts.db:alerts_enriched)
  - Rebuilds engineered features (srcip_int/dstip_int, mitre_missing if needed)
  - Applies the SAME LabelEncoder mappings (safe for unseen categories)
  - Selects columns in the EXACT order from feature_columns.pkl
  - Writes scored_alerts.csv with risk_score in [0,1]
"""

import os
import argparse
import sqlite3
import pandas as pd
import numpy as np
import joblib
import ipaddress

ENCODERS_DIR = "encoders"
MODEL_PATH = "rf_model.pkl"
FEATURE_COLS_PATH = "feature_columns.pkl"

def ip_to_int(x):
    try:
        if pd.isna(x) or x == "" or x == "missing":
            return np.nan
        return int(ipaddress.ip_address(str(x)))
    except Exception:
        return np.nan

def load_artifacts():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Missing {MODEL_PATH}")
    if not os.path.exists(FEATURE_COLS_PATH):
        raise FileNotFoundError(f"Missing {FEATURE_COLS_PATH}")
    model = joblib.load(MODEL_PATH)
    feature_cols = joblib.load(FEATURE_COLS_PATH)
    # Load per-column LabelEncoders if present
    encoders = {}
    if os.path.isdir(ENCODERS_DIR):
        for fname in os.listdir(ENCODERS_DIR):
            if fname.endswith(".pkl"):
                col = fname[:-4]
                encoders[col] = joblib.load(os.path.join(ENCODERS_DIR, fname))
    return model, feature_cols, encoders

def fetch_df(db_path, table_name, limit=None):
    with sqlite3.connect(db_path) as con:
        base_query = f'SELECT * FROM "{table_name}"'
        if limit:
            base_query += f" LIMIT {int(limit)}"
        df = pd.read_sql_query(base_query, con)
    return df

def ensure_mitre_missing(df: pd.DataFrame) -> pd.DataFrame:
    if "mitre_missing" not in df.columns:
        # mirror training logic
        for c in ["mitre_tactic", "mitre_technique", "mitre_id"]:
            if c not in df.columns:
                df[c] = np.nan
        df["mitre_missing"] = (
            df["mitre_tactic"].isna() | (df["mitre_tactic"] == "") |
            df["mitre_technique"].isna() | (df["mitre_technique"] == "") |
            df["mitre_id"].isna() | (df["mitre_id"] == "")
        ).astype(int)
    return df

def engineer_ip_ints(df: pd.DataFrame) -> pd.DataFrame:
    # Create numeric versions if not already present
    if "srcip_int" not in df.columns and "srcip" in df.columns:
        df["srcip_int"] = df["srcip"].apply(ip_to_int)
    if "dstip_int" not in df.columns and "dstip" in df.columns:
        df["dstip_int"] = df["dstip"].apply(ip_to_int)
    for ip_col in ["srcip_int", "dstip_int"]:
        if ip_col in df.columns:
            df[ip_col] = df[ip_col].fillna(-1).astype("int64")
    # Drop original string IPs (training dropped these)
    for c in ["srcip", "dstip"]:
        if c in df.columns:
            df = df.drop(columns=c)
    return df

def safe_label_transform(series: pd.Series, le) -> pd.Series:
    """Map using a saved LabelEncoder; unseen labels -> -1."""
    # Build mapping from classes_ to ints
    mapping = {cls: i for i, cls in enumerate(le.classes_)}
    # If NaNs exist, fill with a known token first (training used 'missing')
    filled = series.fillna("missing").astype(str)
    mapped = filled.map(mapping)
    # Unseen -> -1
    return mapped.fillna(-1).astype("int64")

def apply_saved_encoders(df: pd.DataFrame, encoders: dict) -> pd.DataFrame:
    # Apply encoders only to columns we have an encoder for
    for col, le in encoders.items():
        if col in df.columns:
            df[col] = safe_label_transform(df[col], le)
    return df

def coerce_dtypes_and_fill(df: pd.DataFrame) -> pd.DataFrame:
    # Object/bool -> leave as-is (some may be encoded next). Others to numeric.
    # After encoders, convert remaining object cols (that slipped through) to numeric if possible; else set -1.
    for col in df.columns:
        if df[col].dtype == "O":
            # try numeric coercion
            df[col] = pd.to_numeric(df[col], errors="coerce")
    # Numeric NaNs -> median (or 0 if all NaN)
    for col in df.select_dtypes(include=["int64", "float64"]).columns:
        if df[col].isna().any():
            median = df[col].median()
            if pd.isna(median):
                median = 0
            df[col] = df[col].fillna(median)
    # Any lingering non-numeric -> LabelEncoder wasn't provided; fallback to -1 after factorization
    for col in df.columns:
        if not np.issubdtype(df[col].dtype, np.number):
            codes, uniques = pd.factorize(df[col].astype(str))
            df[col] = pd.Series(codes).replace(-1, -1).astype("int64")
    return df

def build_feature_matrix(raw_df: pd.DataFrame, feature_cols, encoders: dict) -> pd.DataFrame:
    df = raw_df.copy()

    # Remove obvious identifiers (mirrors training)
    drop_cols = ["_id", "_index", "alert_id", "timestamp", "raw_timestamp", "full_log", "rule_description", "is_important"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    # Ensure mitre_missing and IP ints are present like training
    df = ensure_mitre_missing(df)
    df = engineer_ip_ints(df)

    # Fill NaNs for object/bool with 'missing' BEFORE applying encoders (as in training)
    for col in df.select_dtypes(include=["object", "bool"]).columns:
        df[col] = df[col].fillna("missing")

    # Apply saved encoders where available
    df = apply_saved_encoders(df, encoders)

    # Coerce everything to numeric and handle NaNs
    df = coerce_dtypes_and_fill(df)

    # Finally, select the exact columns & order the model expects
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"The following expected feature columns are missing after preprocessing: {missing}")
    X = df[feature_cols].copy()

    # Final safety: ensure all numeric
    if X.select_dtypes(include=["object"]).shape[1] > 0:
        raise ValueError("Feature matrix still contains object dtype columns. Encoding step failed.")
    return X

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="alerts.db")
    ap.add_argument("--table", default="alerts_enriched")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default="scored_alerts.csv")
    args = ap.parse_args()

    model, feature_cols, encoders = load_artifacts()
    raw = fetch_df(args.db, args.table, args.limit)

    # Build X exactly as in training
    X = build_feature_matrix(raw, feature_cols, encoders)

    # Score
    probs = model.predict_proba(X)[:, 1]
    out = raw.copy()
    out["risk_score"] = probs

    # Helpful minimal export; adjust columns to taste
    cols = [c for c in ["id", "timestamp", "rule_description", "mitre_tactic", "mitre_technique", "mitre_id"] if c in out.columns]
    cols += ["risk_score"]
    out[cols].to_csv(args.out, index=False)
    print(f"✅ Scored {len(out)} alerts -> {args.out}")

if __name__ == "__main__":
    main()
