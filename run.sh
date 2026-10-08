#!/usr/bin/env bash
# Start SupplyGuard: API + dashboard on http://localhost:8000
cd "$(dirname "$0")/backend"
exec python3 -m uvicorn app.api:app --host 127.0.0.1 --port 8000
