#!/bin/sh
# Builds the Windows installer inside Docker (cross-compiled from Linux) and publishes it
# to storage/downloads, where the DFIP website offers it with its SHA-256.
#
# Run from the repository root (Git Bash or any POSIX shell with Docker):
#   sh desktop/scripts/build-windows-docker.sh
set -eu

docker build -t dfip-windows-cross -f desktop/scripts/Dockerfile.windows-cross desktop/scripts

# Sources are copied into the container (host node_modules are platform-specific);
# Cargo, npm and xwin caches live in named volumes so rebuilds are fast.
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$PWD:/repo:ro" \
  -v "$PWD/storage/downloads:/out" \
  -v dfip-cross-cargo:/usr/local/cargo/registry \
  -v dfip-cross-target:/build/desktop/src-tauri/target \
  -v dfip-cross-xwin:/root/.cache/cargo-xwin \
  dfip-windows-cross sh -c '
    set -eu
    mkdir -p /build
    cd /repo
    tar --exclude=node_modules --exclude=dist --exclude=dist-desktop --exclude=target -cf - frontend desktop | tar -xf - -C /build
    cd /build/frontend && npm ci --no-audit --no-fund
    cd /build/desktop && npm ci --no-audit --no-fund
    npx tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc --bundles nsis
    bundle=src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis
    ls "$bundle"/*-setup.exe >/dev/null 2>&1 || { echo "BUILD FAILED: no installer in $bundle" >&2; exit 1; }
    for f in "$bundle"/*-setup.exe; do
      name=$(basename "$f" | tr " " "-")
      cp "$f" "/out/$name"
      sha256sum "/out/$name"
    done
  '
