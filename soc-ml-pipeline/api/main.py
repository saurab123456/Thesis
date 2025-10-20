#!/usr/bin/env python3
import os
import sqlite3
from typing import Optional, List, Dict, Any, Tuple
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

# === DB Config ===============================================================
DB_FILE = os.environ.get("DB_FILE", "/home/ubuntu/wazuh-logs/wazuh.db")

try:
    with sqlite3.connect(DB_FILE) as _c:
        _c.execute("PRAGMA journal_mode=WAL;")
        _c.execute("PRAGMA synchronous=NORMAL;")
except Exception:
    pass

# === App =====================================================================
app = FastAPI(title="Wazuh Scored Alerts API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# === Helpers =================================================================
def rows(q: str, params: Tuple = ()) -> List[Dict[str, Any]]:
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(q, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.close()

def single(q: str, params: Tuple = ()) -> Dict[str, Any]:
    r = rows(q, params)
    return r[0] if r else {}

def _ts_clause(ts_col: str, since: Optional[str], until: Optional[str]) -> Tuple[str, Tuple]:
    conds, params = [], []
    if since:
        conds.append(f"substr({ts_col},1,19) >= ?")
        params.append(since[:19])
    if until:
        conds.append(f"substr({ts_col},1,19) <= ?")
        params.append(until[:19])
    where = " AND ".join(conds)
    return where, tuple(params)

def _score_table(model: str) -> str:
    if model == "rf": return "wz_scores_rf"
    if model == "brf": return "wz_scores_brf"
    return "wz_scores_if"

def _from_join(model: str) -> str:
    score_tbl = _score_table(model)
    return f" FROM alerts_enriched a JOIN {score_tbl} s ON s.id = a.id "

def frange(start: float, stop: float, step: float):
    x = start
    while x <= stop + 1e-9:
        yield x
        x += step

# === Root & Health ===========================================================
@app.get("/")
def root():
    return {"ok": True, "message": "Wazuh Scored Alerts API", "db_file": DB_FILE, "docs": "/docs"}

@app.get("/health")
def health():
    return {"ok": True}

# === Meta ====================================================================
@app.get("/meta/last-score")
def last_score(model: str = Query("if", pattern="^(rf|brf|if)$")):
    score_tbl = _score_table(model)
    return single(f"SELECT COUNT(*) AS total_scored, MAX(scored_at) AS last_scored_at FROM {score_tbl}")

@app.get("/meta/unscored")
def meta_unscored(model: str = Query("if", pattern="^(rf|brf|if)$"),
                  since: Optional[str] = None, until: Optional[str] = None):
    score_tbl = _score_table(model)
    sql = f"SELECT COUNT(*) AS n FROM alerts_enriched a LEFT JOIN {score_tbl} s ON s.id = a.id WHERE s.id IS NULL"
    params: List[Any] = []
    ts_where, ts_params = _ts_clause("a.timestamp", since, until)
    if ts_where:
        sql += f" AND {ts_where}"; params += list(ts_params)
    return single(sql, tuple(params))

# === Alerts ==================================================================
@app.get("/alerts/buckets")
def buckets(model: str = Query("if", pattern="^(rf|brf|if)$")):
    return rows(f"SELECT s.risk_bucket, COUNT(*) AS n {_from_join(model)} GROUP BY s.risk_bucket ORDER BY n DESC")

@app.get("/alerts/score-stats")
def score_stats(model: str = Query("if", pattern="^(rf|brf|if)$")):
    return single(
        f"SELECT COUNT(*) AS total, ROUND(AVG(s.risk_score),4) AS avg_score, "
        f"ROUND(MIN(s.risk_score),4) AS min_score, ROUND(MAX(s.risk_score),4) AS max_score "
        f"{_from_join(model)}"
    )

@app.get("/alerts")
def get_alerts(model: str = Query("if", pattern="^(rf|brf|if)$"),
               limit: int = 50, offset: int = 0, min_level: int = 1,
               bucket: Optional[str] = None, q: Optional[str] = None,
               since: Optional[str] = None, until: Optional[str] = None,
               min_score: Optional[float] = None):
    sql = f"""
      SELECT a.id, a.rule_level, a.rule_description, a.srcip, a.dstip,
             a.timestamp, s.risk_score, s.risk_bucket, s.scored_at
      {_from_join(model)} WHERE a.rule_level >= ?
    """
    params: List[Any] = [min_level]
    if bucket: sql += " AND s.risk_bucket = ?"; params.append(bucket)
    if min_score is not None: sql += " AND s.risk_score >= ?"; params.append(min_score)
    ts_where, ts_params = _ts_clause("a.timestamp", since, until)
    if ts_where: sql += f" AND {ts_where}"; params += list(ts_params)
    if q:
        like = f"%{q.lower()}%"
        sql += " AND (LOWER(a.rule_description) LIKE ? OR LOWER(a.srcip) LIKE ? OR LOWER(a.dstip) LIKE ?)"
        params += [like, like, like]
    sql += " ORDER BY s.risk_score DESC, a.timestamp DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    return rows(sql, tuple(params))

# ---- endpoints expected by the dashboard ------------------------------------

# same as /alerts, name used by UI
@app.get("/alerts/scored")
def alerts_scored(model: str = Query("if", pattern="^(rf|brf|if)$"),
                  limit: int = 50, offset: int = 0, min_level: int = 1,
                  bucket: Optional[str] = None, q: Optional[str] = None,
                  since: Optional[str] = None, until: Optional[str] = None,
                  min_score: Optional[float] = None):
    return get_alerts(model=model, limit=limit, offset=offset, min_level=min_level,
                      bucket=bucket, q=q, since=since, until=until, min_score=min_score)

@app.get("/alerts/top-sources")
def alerts_top_sources(model: str = Query("if", pattern="^(rf|brf|if)$"),
                       limit: int = 10, q: Optional[str] = None,
                       bucket: Optional[str] = None,
                       since: Optional[str] = None, until: Optional[str] = None,
                       min_score: Optional[float] = None):
    sql = f"SELECT COALESCE(a.srcip,'(null)') AS source_ip, COUNT(*) AS n {_from_join(model)} WHERE 1=1"
    params: List[Any] = []
    if bucket: sql += " AND s.risk_bucket = ?"; params.append(bucket)
    if min_score is not None: sql += " AND s.risk_score >= ?"; params.append(min_score)
    ts_where, ts_params = _ts_clause("a.timestamp", since, until)
    if ts_where: sql += f" AND {ts_where}"; params += list(ts_params)
    if q:
        like = f"%{q.lower()}%"
        sql += " AND (LOWER(a.rule_description) LIKE ? OR LOWER(a.srcip) LIKE ? OR LOWER(a.dstip) LIKE ?)"
        params += [like, like, like]
    sql += " GROUP BY source_ip ORDER BY n DESC LIMIT ?"
    params.append(limit)
    return rows(sql, tuple(params))

@app.get("/alerts/score-trend")
def alerts_score_trend(model: str = Query("if", pattern="^(rf|brf|if)$"),
                       interval: str = Query("hour", pattern="^(minute|hour|day)$"),
                       limit: int = 200,
                       since: Optional[str] = None, until: Optional[str] = None):
    fmt = "%Y-%m-%d %H" if interval=="hour" else "%Y-%m-%d %H:%M" if interval=="minute" else "%Y-%m-%d"
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql = (f"SELECT strftime('{fmt}', replace(substr(a.timestamp,1,19),'T',' ')) AS time_bucket, "
           f"ROUND(AVG(s.risk_score),4) AS avg_score, ROUND(MAX(s.risk_score),4) AS max_score, COUNT(*) AS count "
           f"{_from_join(model)} WHERE 1=1")
    params: List[Any] = []
    if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
    sql += " GROUP BY time_bucket ORDER BY time_bucket DESC LIMIT ?"
    params.append(limit)
    return rows(sql, tuple(params))

@app.get("/alerts/count")
def alerts_count(model: str = Query("if", pattern="^(rf|brf|if)$"),
                 scored_only: bool = False, min_score: Optional[float] = None,
                 bucket: Optional[str] = None,
                 since: Optional[str] = None, until: Optional[str] = None,
                 q: Optional[str] = None):
    if scored_only or min_score is not None or bucket:
        base = _from_join(model)
        sql = f"SELECT COUNT(*) AS n {base} WHERE 1=1"
        params: List[Any] = []
        if bucket: sql += " AND s.risk_bucket = ?"; params.append(bucket)
        if min_score is not None: sql += " AND s.risk_score >= ?"; params.append(min_score)
    else:
        sql = "SELECT COUNT(*) AS n FROM alerts_enriched a WHERE 1=1"
        params = []
    ts_where, ts_params = _ts_clause("a.timestamp", since, until)
    if ts_where: sql += f" AND {ts_where}"; params += list(ts_params)
    if q:
        like = f"%{q.lower()}%"
        sql += " AND (LOWER(a.rule_description) LIKE ? OR LOWER(a.srcip) LIKE ? OR LOWER(a.dstip) LIKE ?)"
        params += [like, like, like]
    return single(sql, tuple(params))

@app.get("/cases")
def cases(model: str = Query("if", pattern="^(rf|brf|if)$"),
          min_score: float = 0.0, limit: int = 100,
          since: Optional[str] = None, until: Optional[str] = None):
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql = (f"SELECT strftime('%Y-%m-%d %H:%M', replace(substr(a.timestamp,1,19),'T',' ')) AS minute, "
           f"a.rule_description, a.srcip, a.dstip, "
           f"COUNT(*) AS n, ROUND(MAX(s.risk_score),4) AS max_score, "
           f"CASE WHEN MAX(s.risk_score)>=0.90 THEN 'Critical' "
           f"     WHEN MAX(s.risk_score)>=0.70 THEN 'High' "
           f"     WHEN MAX(s.risk_score)>=0.40 THEN 'Medium' ELSE 'Low' END AS bucket, "
           f"MAX(a.timestamp) AS last_seen "
           f"{_from_join(model)} WHERE s.risk_score>=? ")
    params: List[Any] = [min_score]
    if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
    sql += (" GROUP BY minute, a.rule_description, a.srcip, a.dstip "
            " ORDER BY n DESC, max_score DESC LIMIT ?")
    params.append(limit)
    return rows(sql, tuple(params))

# === Thesis Endpoints (compare view) =========================================
@app.get("/metrics/imbalance")
def metrics_imbalance(since: Optional[str] = None, until: Optional[str] = None):
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql = "SELECT l.is_important AS label, COUNT(*) AS n FROM alerts_enriched a JOIN ml_labels l ON l.id = a.id WHERE l.is_important IN (0,1)"
    params: List[Any] = []
    if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
    sql += " GROUP BY l.is_important ORDER BY l.is_important"
    dist = rows(sql, tuple(params))
    tot = sum(r["n"] for r in dist) or 1
    imp = next((r["n"] for r in dist if r["label"] == 1), 0)
    return {"total": tot, "important": imp, "not_important": tot - imp,
            "pct_important": round(100.0 * imp / tot, 2), "since": since, "until": until}

@app.get("/metrics/comparison")
def metrics_comparison(since: Optional[str] = None, until: Optional[str] = None):
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql_wazuh = "SELECT a.rule_level, SUM(CASE WHEN l.is_important=1 THEN 1 ELSE 0 END) AS important, SUM(CASE WHEN l.is_important=0 THEN 1 ELSE 0 END) AS not_important FROM alerts_enriched a JOIN ml_labels l ON l.id = a.id WHERE l.is_important IN (0,1)"
    params: List[Any] = []
    if tf_where: sql_wazuh += f" AND {tf_where}"; params += list(tf_params)
    sql_wazuh += " GROUP BY a.rule_level ORDER BY a.rule_level"
    wazuh = rows(sql_wazuh, tuple(params))
    def avg_by_class(score_tbl: str):
        sql = f"SELECT l.is_important, AVG(s.risk_score) AS avg_score, COUNT(*) AS n FROM {score_tbl} s JOIN ml_labels l ON l.id = s.id JOIN alerts_enriched a ON a.id = s.id WHERE l.is_important IN (0,1)"
        p: List[Any] = []
        if tf_where: sql += f" AND {tf_where}"; p += list(tf_params)
        sql += " GROUP BY l.is_important ORDER BY l.is_important"
        return rows(sql, tuple(p))
    return {"wazuh": wazuh, "ml_scores": {"rf": avg_by_class("wz_scores_rf"), "brf": avg_by_class("wz_scores_brf")}}

def _ranked_for(method: str, since: Optional[str], until: Optional[str]):
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    params: List[Any] = []
    if method == "wazuh":
        sql = "SELECT a.id, a.rule_level AS key, l.is_important AS y FROM alerts_enriched a JOIN ml_labels l ON l.id = a.id WHERE l.is_important IN (0,1)"
        if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
        sql += " ORDER BY a.rule_level DESC, a.id DESC"
    else:
        table = "wz_scores_rf" if method == "rf" else "wz_scores_brf"
        sql = f"SELECT s.id, s.risk_score AS key, l.is_important AS y FROM {table} s JOIN ml_labels l ON l.id = s.id JOIN alerts_enriched a ON a.id = s.id WHERE l.is_important IN (0,1)"
        if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
        sql += " ORDER BY s.risk_score DESC, s.id DESC"
    return rows(sql, tuple(params))

def _curve(rows_ranked: List[Dict[str, Any]], max_k: float, step: float):
    n = len(rows_ranked)
    if n == 0: return []
    pos = sum(r["y"] or 0 for r in rows_ranked)
    if pos == 0: return [{"k": round(k,4), "recall": 0.0} for k in frange(step, max_k, step)]
    cum, out = 0, []
    recall_at_idx = [0.0]*n
    for i, r in enumerate(rows_ranked, start=1):
        cum += r["y"] or 0; recall_at_idx[i-1] = cum/pos
    for k in frange(step, max_k, step):
        cut = min(max(1, int(round(n*k))), n)
        out.append({"k": round(k,4), "recall": round(recall_at_idx[cut-1],4)})
    return out

@app.get("/metrics/cumulative_recall")
def metrics_cumulative_recall(since: Optional[str] = None, until: Optional[str] = None,
                              max_k: float = 0.20, step: float = 0.01):
    wz = _ranked_for("wazuh", since, until)
    rf = _ranked_for("rf", since, until)
    brf = _ranked_for("brf", since, until)
    return {"curves": {"wazuh": _curve(wz,max_k,step),
                       "rf": _curve(rf,max_k,step),
                       "brf": _curve(brf,max_k,step)}}

@app.get("/metrics/topk")
def metrics_topk(since: Optional[str] = None, until: Optional[str] = None, k: float = 0.10):
    def compute(method: str):
        ranked = _ranked_for(method, since, until)
        n = len(ranked)
        if n == 0: return {"total":0,"important":0,"topk_count":0,"topk_important":0,"recall":0,"precision":0,"lift":0}
        pos_total = sum(r["y"] or 0 for r in ranked)
        k_count = max(1,int(round(n*k))); top = ranked[:k_count]
        top_pos = sum(r["y"] or 0 for r in top)
        recall = (top_pos/pos_total) if pos_total else 0
        precision = top_pos/k_count; base_rate = (pos_total/n) if n else 0
        lift = (precision/base_rate) if base_rate>0 else 0
        return {"total":n,"important":pos_total,"topk_count":k_count,"topk_important":top_pos,"recall":round(recall,4),"precision":round(precision,4),"lift":round(lift,2)}
    return {"k":k,"wazuh":compute("wazuh"),"rf":compute("rf"),"brf":compute("brf")}

@app.get("/metrics/volume")
def metrics_volume(since: Optional[str] = None, until: Optional[str] = None, granularity: str = "hour"):
    fmt = "%Y-%m-%d %H" if granularity=="hour" else "%Y-%m-%d %H:%M" if granularity=="minute" else "%Y-%m-%d"
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql = f"SELECT strftime('{fmt}', replace(substr(a.timestamp,1,19),'T',' ')) AS t, COUNT(*) AS n FROM alerts_enriched a WHERE 1=1"
    params: List[Any] = []
    if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
    sql += " GROUP BY t ORDER BY t"
    return {"granularity": granularity, "series": rows(sql, tuple(params))}

@app.get("/metrics/top_alert_types")
def metrics_top_alert_types(since: Optional[str] = None, until: Optional[str] = None):
    tf_where, tf_params = _ts_clause("a.timestamp", since, until); params: List[Any] = []
    base_sql = "SELECT a.rule_description AS rule_id, a.rule_description AS name, COUNT(*) AS n FROM alerts_enriched a WHERE 1=1"
    if tf_where: base_sql += f" AND {tf_where}"; params += list(tf_params)
    base_sql += " GROUP BY a.rule_description ORDER BY n DESC LIMIT 10"
    baseline = rows(base_sql, tuple(params))
    ml_sql = "SELECT a.rule_description AS rule_id, a.rule_description AS name, MAX(s.risk_score) AS max_score, COUNT(*) AS n FROM wz_scores_brf s JOIN alerts_enriched a ON a.id = s.id WHERE 1=1"
    if tf_where: ml_sql += f" AND {tf_where}"
    ml_sql += " GROUP BY a.rule_description ORDER BY max_score DESC LIMIT 10"
    ml = rows(ml_sql, tuple(tf_params))
    return {"baseline_top10": baseline, "ml_top10": ml}

@app.get("/metrics/duplicates")
def metrics_duplicates(since: Optional[str] = None, until: Optional[str] = None):
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql1 = "SELECT COALESCE(a.srcip,'(missing)') AS src, COUNT(*) AS n FROM alerts_enriched a WHERE 1=1"
    params1: List[Any] = []
    if tf_where: sql1 += f" AND {tf_where}"; params1 += list(tf_params)
    sql1 += " GROUP BY src HAVING n>1 ORDER BY n DESC LIMIT 10"
    sql2 = "SELECT COALESCE(a.srcip,'(missing)') AS src, a.rule_description AS rule_id, COUNT(*) AS n FROM alerts_enriched a WHERE 1=1"
    params2: List[Any] = []
    if tf_where: sql2 += f" AND {tf_where}"; params2 += list(tf_params)
    sql2 += " GROUP BY src, a.rule_description HAVING n>1 ORDER BY n DESC LIMIT 10"
    return {"by_src": rows(sql1, tuple(params1)), "by_src_rule": rows(sql2, tuple(params2))}

@app.get("/metrics/score_distribution")
def metrics_score_distribution(model: str = "brf", since: Optional[str] = None, until: Optional[str] = None):
    table = "wz_scores_brf" if model == "brf" else "wz_scores_rf"
    tf_where, tf_params = _ts_clause("a.timestamp", since, until)
    sql = f"SELECT CASE WHEN s.risk_score>=0.90 THEN 'Critical' WHEN s.risk_score>=0.70 THEN 'High' WHEN s.risk_score>=0.40 THEN 'Medium' ELSE 'Low' END AS bucket, COUNT(*) AS n FROM {table} s JOIN alerts_enriched a ON a.id=s.id WHERE 1=1"
    params: List[Any] = []
    if tf_where: sql += f" AND {tf_where}"; params += list(tf_params)
    sql += " GROUP BY bucket ORDER BY bucket"
    return {"model": model, "hist": rows(sql, tuple(params))}

@app.get("/metrics/model_summary")
def metrics_model_summary():
    try:
        return {"models": rows("SELECT model, auc, ap, best_f1, trained_at, n_train FROM model_metrics ORDER BY trained_at DESC")}
    except Exception:
        return {"models": []}

@app.get("/metrics/export_topk_csv", response_class=PlainTextResponse)
def export_topk_csv(since: Optional[str] = None, until: Optional[str] = None, k: float = 0.10):
    data = metrics_topk(since=since, until=until, k=k)
    header = "method,total,important,topk_count,topk_important,recall,precision,lift\n"
    def row(method: str):
        m = data[method]
        return f"{method},{m['total']},{m['important']},{m['topk_count']},{m['topk_important']},{m['recall']},{m['precision']},{m['lift']}"
    return header + "\n".join([row("wazuh"), row("rf"), row("brf")])

# --- tile used by Monitoring page -------------------------------------------
@app.get("/metrics")
def get_metrics(model: str = Query("rf", pattern="^(rf|brf|if)$")):
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        stats = dict(c.execute(
            f"SELECT COUNT(*) AS total, ROUND(AVG(risk_score), 4) AS avg_score, "
            f"MIN(risk_score) AS min_score, MAX(risk_score) AS max_score "
            f"FROM wz_scores_{model}").fetchone())
        buckets = [dict(r) for r in c.execute(
            f"SELECT risk_bucket, COUNT(*) AS n FROM wz_scores_{model} GROUP BY risk_bucket")]
    return {"stats": stats, "buckets": buckets}

@app.get("/metrics/precision-recall")
def metrics_precision_recall(thr: float = 0.32,
                             model: str = Query("rf", pattern="^(rf|brf|if)$"),
                             since: Optional[str] = None,
                             until: Optional[str] = None):
    # IMPORTANT: filter on the CTE column name "timestamp"
    ts_where, ts_params = _ts_clause("timestamp", since, until)
    sql = (f"WITH win AS ("
           f"  SELECT s.id, s.risk_score AS score, l.is_important AS y, a.timestamp "
           f"  FROM wz_scores_{model} s "
           f"  JOIN ml_labels l ON l.id = s.id "
           f"  JOIN alerts_enriched a ON a.id = s.id "
           f"  WHERE l.is_important IN (0,1)"
           f") SELECT "
           f"  SUM(CASE WHEN score>=? AND y=1 THEN 1 ELSE 0 END) AS tp, "
           f"  SUM(CASE WHEN score>=? AND y=0 THEN 1 ELSE 0 END) AS fp, "
           f"  SUM(CASE WHEN score<? AND y=1 THEN 1 ELSE 0 END) AS fn, "
           f"  COUNT(*) AS n, "
           f"  MIN(timestamp) AS from_ts, "
           f"  MAX(timestamp) AS to_ts "
           f"FROM win WHERE 1=1")
    params: List[Any] = [thr, thr, thr]
    if ts_where:
        sql += f" AND {ts_where}"
        params += list(ts_params)
    r = single(sql, tuple(params)) or {}
    n  = int(r.get("n")  or 0)
    tp = int(r.get("tp") or 0)
    fp = int(r.get("fp") or 0)
    fn = int(r.get("fn") or 0)
    prec = (tp / (tp + fp)) if (tp + fp) > 0 else None
    rec  = (tp / (tp + fn)) if (tp + fn) > 0 else None
    f1   = (2*prec*rec/(prec+rec)) if (prec is not None and rec is not None and (prec+rec)>0) else None
    return {"n": n, "thr": thr, "precision": prec, "recall": rec, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn, "used_fallback": False,
            "from_ts": r.get("from_ts"), "to_ts": r.get("to_ts"),
            "since": since, "until": until}


# === Extra Thesis Metrics ====================================================

@app.get("/metrics/models")
def get_model_metrics_full():
    q = ("SELECT model, auc, ap, best_f1, best_thr, n_train, n_test, "
         "pos_rate_test, trained_at, features_json "
         "FROM model_metrics ORDER BY trained_at DESC")
    return {"models": rows(q)}

@app.get("/metrics/fp_reduction")
def metrics_fp_reduction(since: Optional[str] = None, until: Optional[str] = None, k: float = 0.10):
    topk = metrics_topk(since=since, until=until, k=k)
    def fp_of(m): return max(0, m["topk_count"] - m["topk_important"])
    wz = topk["wazuh"]; rf = topk["rf"]; brf = topk["brf"]
    wz_fp, rf_fp, brf_fp = fp_of(wz), fp_of(rf), fp_of(brf)
    def red(fp): return ((wz_fp - fp) / wz_fp) if wz_fp > 0 else 0.0
    return {
        "k": k,
        "wazuh": {"fp": wz_fp, "fpr": wz_fp / wz["topk_count"] if wz["topk_count"] else 0},
        "rf":    {"fp": rf_fp, "fpr": rf_fp / rf["topk_count"] if rf["topk_count"] else 0,
                  "fp_reduction_vs_wazuh": red(rf_fp)},
        "brf":   {"fp": brf_fp, "fpr": brf_fp / brf["topk_count"] if brf["topk_count"] else 0,
                  "fp_reduction_vs_wazuh": red(brf_fp)},
        "since": since, "until": until
    }

@app.get("/metrics/efficiency")
def metrics_efficiency(since: Optional[str] = None, until: Optional[str] = None, k: float = 0.15):
    topk = metrics_topk(since=since, until=until, k=k)
    wz, rf, brf = topk["wazuh"]["recall"], topk["rf"]["recall"], topk["brf"]["recall"]
    return {
        "k": k,
        "recall": {"wazuh": wz, "rf": rf, "brf": brf},
        "delta_vs_wazuh": {"rf": rf - wz, "brf": brf - wz},
        "since": since, "until": until
    }
