#!/bin/sh
set -eu

LAB_ROOT="${REPO_CANARY_LAB:-/data/lab}"
export REPO_CANARY_LAB="$LAB_ROOT"

TEST_DIR="$LAB_ROOT/testdata"
DB_PATH="$LAB_ROOT/canary.db"
REPORT_DIR="$LAB_ROOT/reports"
HASH_FILE="$LAB_ROOT/known_hashes.txt"
LOG_FILE="$LAB_ROOT/error_log.txt"

mkdir -p "$TEST_DIR" "$REPORT_DIR"

cd /app

if [ ! -f "$TEST_DIR/.repo-canary-lab" ]; then
    echo "[+] Initialising disposable lab at $TEST_DIR"
    python scripts/reset_lab.py \
        --yes \
        --test-dir "$TEST_DIR" \
        --db-path "$DB_PATH" \
        --findings "$LAB_ROOT/findings.json"
fi

if [ ! -f "$HASH_FILE" ]; then
    if [ -f known_hashes.example.txt ]; then
        cp known_hashes.example.txt "$HASH_FILE"
    else
        : > "$HASH_FILE"
    fi
fi

case "${1:-engine}" in
    engine)
        exec python scripts/detection_engine.py \
            --test-dir "$TEST_DIR" \
            --db-path "$DB_PATH" \
            --report-dir "$REPORT_DIR" \
            --hash-file "$HASH_FILE" \
            --log-file "$LOG_FILE"
        ;;
    dashboard)
        exec python scripts/dashboard_server.py \
            --host 0.0.0.0 \
            --port 8000 \
            --db-path "$DB_PATH" \
            --log-file "$LOG_FILE"
        ;;
    *)
        exec "$@"
        ;;
esac
