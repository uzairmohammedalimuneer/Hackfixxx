#!/usr/bin/env bash
# HACKFIX AI — Startup Script (Linux/macOS)
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

echo "=========================================================="
echo "  HACKFIX AI — Website Security Scanner Engine            "
echo "=========================================================="

# 1. Start Vulnerable Test Target on Port 8001
echo "[1/3] Starting Vulnerable Test Target on http://127.0.0.1:8001..."
python3 -m uvicorn test_target.target_app:app --host 127.0.0.1 --port 8001 --app-dir "$DIR/backend" &
TARGET_PID=$!

# 2. Start Backend on Port 8000
echo "[2/3] Starting HACKFIX AI Backend on http://127.0.0.1:8000..."
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir "$DIR/backend" &
BACKEND_PID=$!

trap "kill $TARGET_PID $BACKEND_PID" EXIT

# 3. Start Frontend on Port 3000
echo "[3/3] Starting HACKFIX AI Frontend on http://localhost:3000..."
cd "$DIR/frontend"
npm run dev

