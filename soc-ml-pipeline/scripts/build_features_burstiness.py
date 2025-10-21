#!/usr/bin/env python3
"""
build_features_burstiness.py

Adds non-leaky behavioral features to ml_features, derived from wazuh_events:

  - src_hourly_count:           # of alerts from the same srcip within the same hour
  - src_distinct_dstport_hour:  # of distinct destination ports that srcip hit in that hour
  - pair_hourly_count:          # of alerts for the (srcip,dstip) pair within the same hour

Run:
  python3 build_features_burstiness.py --db /home/ubuntu/wazuh-logs/wazuh.db
"""

import argparse
import sqlite3
import time
import pandas as pd

def safe_alter_add_column(con: sqlite3.Connection, table: str, col: str, decl: str):
    try:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl};")
    except sqlite3.OperationalError as e:
        msg = str(e).lower()
        # SQLite has no IF NOT EXISTS for columns; ignore if already there
        if "duplicate column name" in msg or "already exists" in msg:
            pass
        else:
            raise

def chunked(iterable, size: int):
    buf = []
    for x in iterable:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="/home/ubuntu/wazuh-logs/wazuh.db", help="Path to SQLite DB")
    ap.add_argument("--chunk", type=int, default=50000, help="Update batch size")
    args = ap.parse_args()

    DB = args.db
    t0 = time.time()

    # PRAGMAs + columns
    with sqlite3.connect(DB) as con:
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        # Ensure ml_features has our new columns
        safe_alter_add_column(con, "ml_features", "src_hourly_count", "INTEGER DEFAULT 0")
        safe_alter_add_column(con, "ml_features", "src_distinct_dstport_hour", "INTEGER DEFAULT 0")
        safe_alter_add_column(con, "ml_features", "pair_hourly_count", "INTEGER DEFAULT 0")
        # Helpful index for updates (no-op if it exists)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ml_features_id ON ml_features(id);")

    print("✓ Columns ready. Loading minimal event fields…")
    t1 = time.time()
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        df = pd.read_sql_query(
            """
            SELECT
              e._id AS id,
              e.srcip,
              e.dstip,
              e.dstport,
              substr(e.timestamp,1,13) AS hour_key  -- 'YYYY-MM-DDTHH' (UTC)
            FROM wazuh_events e
            WHERE e.srcip IS NOT NULL AND e.srcip <> ''
              AND e.timestamp IS NOT NULL
            """,
            con,
        )
    print(f"  Loaded {len(df):,} rows in {time.time()-t1:.1f}s")

    # Normalize dstport for distinct counts (numeric only)
    df["dstport_num"] = pd.to_numeric(df["dstport"], errors="coerce")

    print("✓ Computing aggregates…")
    t2 = time.time()
    g_src_hour = df.groupby(["srcip", "hour_key"]).size().rename("src_hourly_count")
    g_src_dist = (
        df.groupby(["srcip", "hour_key"])["dstport_num"].nunique(dropna=True).rename("src_distinct_dstport_hour")
    )
    g_pair_hour = df.groupby(["srcip", "dstip", "hour_key"]).size().rename("pair_hourly_count")

    # Join back to each event row
    df = (
        df.join(g_src_hour, on=["srcip", "hour_key"])
          .join(g_src_dist, on=["srcip", "hour_key"])
          .join(g_pair_hour, on=["srcip", "dstip", "hour_key"])
    )

    # Prepare update tuples: (src_hourly_count, src_distinct_dstport_hour, pair_hourly_count, id)
    upd = (
        df[["id", "src_hourly_count", "src_distinct_dstport_hour", "pair_hourly_count"]]
        .dropna()
        .itertuples(index=False, name=None)
    )

    print(f"  Aggregates computed in {time.time()-t2:.1f}s. Writing updates in chunks of {args.chunk}…")
    t3 = time.time()
    total = 0
    with sqlite3.connect(DB) as con:
        con.execute("PRAGMA synchronous=NORMAL;")
        sql = """
            UPDATE ml_features
               SET src_hourly_count=?,
                   src_distinct_dstport_hour=?,
                   pair_hourly_count=?
             WHERE id=?
        """
        for batch in chunked(upd, args.chunk):
            # Cast to plain ints; ids stay as-is
            batch_param = [(int(a), int(b), int(c), i) for (i, a, b, c) in batch]
            con.executemany(sql, batch_param)
            total += len(batch_param)
    print(f"  Updated {total:,} rows in {time.time()-t3:.1f}s")

    print(f"\n✅ Added/updated burstiness features in ml_features in {time.time()-t0:.1f}s.")
    print("   Columns: src_hourly_count, src_distinct_dstport_hour, pair_hourly_count")

if __name__ == "__main__":
    main()
