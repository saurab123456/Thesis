#!/usr/bin/env bash
# inspect_db.sh — Explore all tables in a SQLite DB (schema + samples + common slices)

set -euo pipefail

DB="${1:-/home/ubuntu/wazuh-logs/wazuh.db}"

if [[ ! -f "$DB" ]]; then
  echo "DB not found: $DB" >&2
  exit 1
fi

divider() { printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '='; }
thin()    { printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '-'; }

has_column() {
  local t="$1" c="$2"
  sqlite3 "$DB" "PRAGMA table_info('$t');" | awk -F'|' '{print $2}' | grep -qx "$c"
}

list_tables() {
  sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
}

echo "Inspecting DB: $DB"
divider

for t in $(list_tables); do
  echo "📦 Table: $t"
  thin
  # Row count
  rc=$(sqlite3 "$DB" "SELECT COUNT(*) FROM '$t';" || echo "?")
  echo "Rows: $rc"

  # Min/Max timestamp (if exists)
  if has_column "$t" "timestamp"; then
    echo "Timestamp range:"
    sqlite3 "$DB" "SELECT MIN(timestamp), MAX(timestamp) FROM '$t';" | awk -F'|' '{print "  MIN = " $1 "\n  MAX = " $2}'
  fi

  # Schema
  echo "Schema (PRAGMA table_info):"
  sqlite3 -header -column "$DB" "PRAGMA table_info('$t');"

  # Risk distribution if present
  if has_column "$t" "risk_bucket"; then
    echo
    echo "risk_bucket distribution:"
    sqlite3 -header -column "$DB" "
      SELECT COALESCE(risk_bucket,'UNBUCKETED') AS bucket, COUNT(*) AS cnt
      FROM '$t'
      GROUP BY bucket
      ORDER BY cnt DESC;"
  fi

  # Score stats if present
  if has_column "$t" "risk_score"; then
    echo
    echo "risk_score stats:"
    sqlite3 -header -column "$DB" "
      SELECT ROUND(AVG(risk_score),3) AS avg_score,
             ROUND(MIN(risk_score),3) AS min_score,
             ROUND(MAX(risk_score),3) AS max_score,
             SUM(risk_score IS NOT NULL) AS scored_rows,
             SUM(risk_score IS NULL)     AS unscored_rows
      FROM '$t';"
  fi

  # Top IPs if present
  if has_column "$t" "source_ip"; then
    echo
    echo "Top source_ip:"
    sqlite3 -header -column "$DB" "
      SELECT source_ip, COUNT(*) AS cnt
      FROM '$t'
      GROUP BY source_ip
      ORDER BY cnt DESC
      LIMIT 10;"
  fi

  if has_column "$t" "destination_ip"; then
    echo
    echo "Top destination_ip:"
    sqlite3 -header -column "$DB" "
      SELECT destination_ip, COUNT(*) AS cnt
      FROM '$t'
      GROUP BY destination_ip
      ORDER BY cnt DESC
      LIMIT 10;"
  fi

  # Sample rows (prefer newest by timestamp)
  echo
  echo "Sample rows (up to 5):"
  if has_column "$t" "timestamp"; then
    sqlite3 -header -column "$DB" "SELECT * FROM '$t' ORDER BY timestamp DESC LIMIT 5;"
  else
    sqlite3 -header -column "$DB" "SELECT * FROM '$t' LIMIT 5;"
  fi

  divider
done
