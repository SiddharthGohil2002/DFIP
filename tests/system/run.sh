#!/bin/sh
# Full API test of DFIP on an isolated, throwaway stack: its own MongoDB, Redis and storage
# volume, no host ports, so it never touches the data of a running DFIP.
#
# Needs Docker, the current backend image and the synthetic test image. From the repository root:
#   docker compose build backend celery_worker
#   docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-test-image.sh
#   docker run --rm --privileged -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-ntfs-image.sh
#   sh tests/system/run.sh
#
# Output: tests/system/out/<phase>.log and results-<phase>.json. Exits 1 if any check fails.
# Public samples (sh scripts/test-image/fetch-samples.sh) are used when present; SECTIONS=07b,12b runs a subset.
set -eu
cd "$(dirname "$0")"
HERE=$(pwd -W 2>/dev/null || pwd)
COMPOSE="docker compose -f compose.yml"
mkdir -p out

$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d --wait >/dev/null 2>&1

run_phase() {
  MSYS_NO_PATHCONV=1 $COMPOSE exec -T -e PYTHONDONTWRITEBYTECODE=1 -e DFIP_SECTIONS="${SECTIONS:-}" backend     python /tests/dfip_full_test.py "$1" > "out/$1.log" 2>&1 || true
  tail -1 "out/$1.log"
}

run_phase main
if [ -n "${SECTIONS:-}" ]; then
  # A partial run (SECTIONS=07b,12b sh tests/system/run.sh) checks only the selected sections.
  $COMPOSE down -v >/dev/null 2>&1
  if grep -h "  FAIL" out/main.log; then exit 1; fi
  echo "Selected system checks passed."
  exit 0
fi
T_DESKTOP_WRITES=true $COMPOSE up -d --wait backend >/dev/null 2>&1 && run_phase desktop_writes
T_REGISTRATION=open $COMPOSE up -d --wait backend >/dev/null 2>&1 && run_phase reg_open
T_REGISTRATION=disabled $COMPOSE up -d --wait backend >/dev/null 2>&1 && run_phase reg_disabled

# Text of the PDF reports saved by the main phase (pdftotext from poppler).
MSYS_NO_PATHCONV=1 docker run --rm -v "$HERE:/w" -v "$HERE/out:/out" mcr.microsoft.com/playwright/python:v1.48.0-jammy \
  bash -c "(apt-get update -qq && apt-get install -y -qq poppler-utils) >/dev/null 2>&1; python3 /w/check_pdf.py" > out/pdf.log 2>&1 || true
tail -1 out/pdf.log

$COMPOSE down -v >/dev/null 2>&1
if grep -h "  FAIL" out/*.log; then exit 1; fi
echo "All system checks passed."
