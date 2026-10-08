#!/bin/sh
# Browser tests of the web portal, and of the desktop UI build served the way `tauri dev` loads it,
# against a running DFIP stack (docker compose up). They create their own cases and users.
# ui_download expects an installer in storage/downloads (desktop/scripts/build-windows-docker.sh).
#
# From the repository root:  sh tests/ui/run.sh        (output in tests/ui/out/)
set -eu
ROOT=$(pwd -W 2>/dev/null || pwd)
(cd frontend && npm run build:desktop >/dev/null)
mkdir -p tests/ui/out

MSYS_NO_PATHCONV=1 docker run --rm --add-host=host.docker.internal:host-gateway \
  -v "$ROOT/tests/ui:/w:ro" -v "$ROOT/tests/ui/out:/out" \
  -v "$ROOT/storage/test-images:/img:ro" -v "$ROOT/frontend/dist-desktop:/dist:ro" \
  mcr.microsoft.com/playwright/python:v1.48.0-jammy bash -c '
    pip install -q playwright==1.48.0 >/dev/null 2>&1
    status=0
    for t in ui_e2e ui_desktop ui_roles ui_download ui_auth ui_signout ui_extra; do
      if python /w/$t.py > /out/$t.log 2>&1; then echo "$t: passed"; else echo "$t: FAILED (see tests/ui/out/$t.log)"; status=1; fi
    done
    exit $status'
