#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:-./wazuh.db}"
SQL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Creating SQLite DB at: ${DB_PATH}"
: > "${DB_PATH}"            # create/empty file

echo "Applying 01_tables.sql..."
sqlite3 "${DB_PATH}" < "${SQL_DIR}/01_tables.sql"

echo "Applying 02_views.sql..."
sqlite3 "${DB_PATH}" < "${SQL_DIR}/02_views.sql"

# Optional migrations if present
if [ -f "${SQL_DIR}/update_features.sql" ]; then
  echo "Applying update_features.sql..."
  sqlite3 "${DB_PATH}" < "${SQL_DIR}/update_features.sql"
fi

if [ -f "${SQL_DIR}/recent_changes.sql" ]; then
  echo "Applying recent_changes.sql..."
  sqlite3 "${DB_PATH}" < "${SQL_DIR}/recent_changes.sql"
fi

echo "Done. Schema installed in ${DB_PATH}"
