#!/usr/bin/env python3
# fig_eval_calibration.py
# Loads saved RF/BRF, reproduces time-based split, and exports:
# - reliability diagrams (RF/BRF)
# - confusion matrices at best-F1 threshold from model_metrics
# - a small CSV with per-bin calibration stats

import json, os, sqlite3, math
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from datetime import datetime

DB = "/home/ubuntu/wazuh-logs/wazuh.db"
ART = "/home/ubuntu/wazuh-logs/models"
OUT = "/home/ubuntu/wazuh-logs/thesis_exports"
os.makedirs(OUT, exist_ok=True)

RF_PKL  = os.path.join(ART, "rf_model.pkl")
BRF_PKL = os.path.join(ART, "brf_model.pkl")
FEAT_JSON = os.path.join(ART, "rf_feature_columns.json")

def load_xy(db, feature_cols):
    with sqlite3.connect(db) as con:
        X = pd.read_sql_query("SELECT * FROM ml_features", con)
        y = pd.read_sql_query("SELECT id, is_important FROM ml_labels", con)
    df = X.merge(y, on="id", how="inner")
    # pick a timestamp column if present
    ts_col = None
    for c in ["timestamp","ts","event_time","time"]:
        if c in df.columns:
            ts_col = c; break
    return df, ts_col, feature_cols

def time_split(df, ts_col, frac=0.80):
    if ts_col:
        df_sorted = df.sort_values(ts_col)
        cut = int(len(df_sorted)*frac)
        return df_sorted.iloc[:cut], df_sorted.iloc[cut:]
    else:
        # fallback – should not happen for your data
        from sklearn.model_selection import train_test_split
        return train_test_split(df, test_size=0.20, random_state=42, stratify=df["is_important"])

def best_thr_from_db(db, model):
    with sqlite3.connect(db) as con:
        row = pd.read_sql_query(
            "SELECT best_thr FROM model_metrics WHERE model=? ORDER BY trained_at DESC LIMIT 1",
            con, params=(model,)
        )
    return float(row.iloc[0,0]) if len(row) else 0.5

def reliability_bins(y_true, p, n_bins=10):
    df = pd.DataFrame({"y": y_true.astype(int), "p": p})
    df["bin"] = np.minimum((df["p"] * n_bins).astype(int), n_bins-1)
    g = df.groupby("bin").agg(
        n=("y","size"),
        mean_p=("p","mean"),
        hit_rate=("y","mean")
    ).reset_index()
    # bin centers
    g["center"] = (g["bin"] + 0.5) / n_bins
    return g

def save_reliability_plot(stats, title, png_path):
    plt.figure()
    # never set custom colors/styles per your tooling policy
    plt.plot([0,1],[0,1])
    plt.scatter(stats["center"], stats["hit_rate"], s=np.maximum(10, stats["n"]/5))
    plt.xlabel("Predicted probability")
    plt.ylabel("Empirical positive rate")
    plt.title(title)
    plt.grid(True, linestyle=":")
    plt.savefig(png_path, bbox_inches="tight", dpi=150)
    plt.close()

def save_confusion_plot(y_true, p, thr, title, png_path):
    y_pred = (p >= thr).astype(int)
    from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)

    plt.figure()
    plt.imshow(cm, interpolation="nearest")
    plt.title(f"{title}\nthr={thr:.3f}  P={prec:.3f} R={rec:.3f} F1={f1:.3f}")
    plt.xticks([0,1], ["Pred 0","Pred 1"])
    plt.yticks([0,1], ["Actual 0","Actual 1"])
    for (i,j), v in np.ndenumerate(cm):
        plt.text(j, i, f"{int(v):,}", ha="center", va="center")
    plt.colorbar()
    plt.tight_layout()
    plt.savefig(png_path, bbox_inches="tight", dpi=150)
    plt.close()

def main():
    feature_cols = json.load(open(FEAT_JSON))
    df, ts_col, feature_cols = load_xy(DB, feature_cols)
    train_df, test_df = time_split(df, ts_col)

    X_test = test_df[feature_cols].copy()
    y_test = test_df["is_important"].astype(int).values

    rf  = joblib.load(RF_PKL)
    brf = joblib.load(BRF_PKL)

    p_rf  = rf.predict_proba(X_test)[:,1]
    p_brf = brf.predict_proba(X_test)[:,1]

    # reliability
    stats_rf  = reliability_bins(y_test, p_rf,  n_bins=10)
    stats_brf = reliability_bins(y_test, p_brf, n_bins=10)
    stats_rf.to_csv(os.path.join(OUT, "reliability_rf_bins.csv"), index=False)
    stats_brf.to_csv(os.path.join(OUT, "reliability_brf_bins.csv"), index=False)
    save_reliability_plot(stats_rf,  "Reliability (RF)",  os.path.join(OUT, "reliability_rf.png"))
    save_reliability_plot(stats_brf, "Reliability (BRF)", os.path.join(OUT, "reliability_brf.png"))

    # confusion mats @ best-F1 thresholds recorded in DB
    thr_rf  = best_thr_from_db(DB, "rf")
    thr_brf = best_thr_from_db(DB, "brf")
    save_confusion_plot(y_test, p_rf,  thr_rf,  "RF confusion @ best-F1",  os.path.join(OUT,"cm_rf_bestF1.png"))
    save_confusion_plot(y_test, p_brf, thr_brf, "BRF confusion @ best-F1", os.path.join(OUT,"cm_brf_bestF1.png"))

    print("Wrote:",
          os.path.join(OUT,"reliability_rf.png"),
          os.path.join(OUT,"reliability_brf.png"),
          os.path.join(OUT,"cm_rf_bestF1.png"),
          os.path.join(OUT,"cm_brf_bestF1.png"),
          os.path.join(OUT,"reliability_rf_bins.csv"),
          os.path.join(OUT,"reliability_brf_bins.csv"),
          sep="\n")

if __name__ == "__main__":
    main()
