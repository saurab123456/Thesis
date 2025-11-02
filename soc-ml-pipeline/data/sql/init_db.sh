#!/usr/bin/env bash
set -euo pipefail
DB_PATH="${1:-./datasets/wazuh.db}"
SQLDIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$(dirname "$DB_PATH")"
sqlite3 "$DB_PATH" < "$SQLDIR/01_tables.sql" 2>/dev/null || true
[ -s "$SQLDIR/02_indexes.sql" ] && sqlite3 "$DB_PATH" < "$SQLDIR/02_indexes.sql"
[ -s "$SQLDIR/03_views.sql" ]   && sqlite3 "$DB_PATH" < "$SQLDIR/03_views.sql"
[ -s "$SQLDIR/04_triggers.sql" ] && sqlite3 "$DB_PATH" < "$SQLDIR/04_triggers.sql"
echo "Initialized DB at $DB_PATH"
