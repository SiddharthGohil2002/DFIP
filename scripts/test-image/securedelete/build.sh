#!/bin/sh
# Builds the scenario's Windows programs into $1 (run by make-test-image.sh, in a Debian container):
#   SecureDelete.exe  32-bit, compiled with mingw-w64 (version information from securedelete.rc, a fixed compile time),
#                     signed with osslsigncode by a self-signed "SecureDelete Project" certificate (so: signed, untrusted)
#   svchost.exe       the same program before signing, packed with UPX: a renamed, packed copy (masquerading)
# Needs: gcc-mingw-w64-i686 binutils-mingw-w64-i686 upx-ucl osslsigncode openssl python3
set -eu
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
mkdir -p "$OUT"
i686-w64-mingw32-windres "$HERE/securedelete.rc" -O coff -o "$WORK/res.o"
i686-w64-mingw32-gcc -O2 -s -municode -o "$WORK/SecureDelete.exe" "$HERE/securedelete.c" "$WORK/res.o" -Wl,--no-insert-timestamp
python3 "$HERE/set_pe_time.py" "$WORK/SecureDelete.exe" 1786613400   # 2026-08-13 09:30:00 UTC
upx -9 -q -o "$OUT/svchost.exe" "$WORK/SecureDelete.exe" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -not_before 20260101000000Z -not_after 20360101000000Z -subj "/CN=SecureDelete Project/O=SecureDelete Project/C=US" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
osslsigncode sign -certs "$WORK/cert.pem" -key "$WORK/key.pem" -h sha256 -n "SecureDelete" \
  -i "https://tools.example.org/securedelete" -st 1786614000 -in "$WORK/SecureDelete.exe" -out "$OUT/SecureDelete.exe" >/dev/null
cp "$WORK/cert.pem" "$OUT/signer-cert.pem"
rm -rf "$WORK"
