#!/bin/sh
# Checks what the web UI does while the API is down: it STOPS the dfip-backend container of the
# running stack for about a minute and starts it again. From the repository root:
#   sh tests/ui/outage.sh
set -eu
ROOT=$(pwd -W 2>/dev/null || pwd)
OUT=tests/ui/out/outage
mkdir -p "$OUT"
rm -f "$OUT"/ready-for-stop "$OUT"/backend-stopped "$OUT"/ready-for-start "$OUT"/backend-started "$OUT"/outage.log

MSYS_NO_PATHCONV=1 docker run --rm --add-host=host.docker.internal:host-gateway -v "$ROOT/tests/ui:/w:ro" -v "$ROOT/$OUT:/out" \
  mcr.microsoft.com/playwright/python:v1.48.0-jammy bash -c "pip install -q playwright==1.48.0 >/dev/null 2>&1; python /w/ui_outage.py" \
  > "$OUT/outage.log" 2>&1 &

wait_file() { i=0; while [ ! -f "$OUT/$1" ] && [ $i -lt 300 ]; do sleep 1; i=$((i + 1)); done; }
wait_file ready-for-stop
docker stop dfip-backend >/dev/null && touch "$OUT/backend-stopped"
wait_file ready-for-start
docker compose up -d --wait backend >/dev/null
touch "$OUT/backend-started"
wait
cat "$OUT/outage.log" | grep -E "PASS|FAIL|ui_outage"
