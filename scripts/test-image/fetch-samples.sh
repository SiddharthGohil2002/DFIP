#!/bin/sh
# Downloads the pinned public test samples into storage/test-images/samples/ (see fetch_samples.py).
# From the repository root:  sh scripts/test-image/fetch-samples.sh
set -eu
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/repo" -w /repo python:3.11-slim python scripts/test-image/fetch_samples.py "$@"
