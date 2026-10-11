#!/bin/sh
# Downloads the pinned public test samples into storage/test-images/samples/ (see fetch_samples.py), then builds
# storage/test-images/dfip-samples-disk.dd from some of them (see make-samples-image.sh).
# From the repository root:  sh scripts/test-image/fetch-samples.sh
set -eu
REPO="$(pwd -W 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 docker run --rm -v "$REPO:/repo" -w /repo python:3.11-slim python scripts/test-image/fetch_samples.py "$@"
MSYS_NO_PATHCONV=1 docker run --rm -v "$REPO:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-samples-image.sh
