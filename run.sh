#!/usr/bin/env bash
# Start the vdp-hunter API. Expects data/app.env (see data/app.env.example).
set -euo pipefail
cd "$(dirname "$0")"
if [ -f data/app.env ]; then set -a; . data/app.env; set +a; fi
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "${VDP_PORT:-8110}" --proxy-headers
