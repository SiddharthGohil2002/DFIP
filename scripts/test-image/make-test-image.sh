#!/bin/sh
# Builds storage/test-images/dfip-test-disk.dd: a 64 MiB MBR disk with one FAT32
# partition laid out like a Windows system, for end-to-end testing of DFIP's
# deleted-file, timeline, browser, USB and Windows activity (Prefetch, Recent, Recycle Bin) analysis.
#
# Run from the repository root (needs only Docker; no root, mounting or FUSE):
#   docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-test-image.sh
set -eu

apt-get update -qq >/dev/null && apt-get install -y -qq mtools dosfstools fdisk >/dev/null

WORK=$(mktemp -d)
TREE="$WORK/tree"
OUT_DIR=storage/test-images
IMG="$OUT_DIR/dfip-test-disk.dd"
mkdir -p "$OUT_DIR"
rm -f "$IMG"

python3 scripts/test-image/make_artifacts.py "$TREE" backend/tests/fixtures/SYSTEM.xz

# Give files distinct, known modification times so the timeline is meaningful.
stamp() { touch -d "$1" "$TREE/$2"; }
stamp '2011-04-07 10:31:37' 'Windows/System32/config/SYSTEM'
stamp '2026-09-01 10:12:46' 'Windows/INF/setupapi.dev.log'
stamp '2026-08-28 16:04:10' 'Users/alice/Documents/project-notes.txt'
stamp '2026-09-01 09:41:02' 'Users/alice/Documents/payroll-export.csv'
stamp '2026-09-01 10:06:30' 'Users/alice/Downloads/cleanup.ps1'
stamp '2026-09-01 10:20:15' 'Users/alice/AppData/Local/Google/Chrome/User Data/Default/History'
stamp '2026-09-01 10:33:05' 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite'
# Windows activity (UTC, the times Windows would have written): shortcut written when the payroll export was
# opened from E:, the $I index when it went to the Recycle Bin ($R keeps the file's own time), Prefetch ~10 s after a run.
stamp '2026-09-01 14:14:06' 'Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk'
stamp '2026-09-01 14:15:20' '$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$I3K9D2A.csv'
stamp '2026-09-01 09:41:02' '$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$R3K9D2A.csv'
touch -d '2026-09-01 14:18:40' "$TREE"/Windows/Prefetch/SECUREDELETE.EXE-*.pf
stamp '2026-08-31 17:22:00' 'Users/alice/Pictures/whiteboard.png'
stamp '2026-08-30 11:00:00' 'Users/alice/Documents/offer-letter.pdf'

# 64 MiB disk, MBR partition table, FAT32 (LBA) partition starting at sector 2048.
truncate -s 64M "$IMG"
printf 'label: dos\nstart=2048, type=c\n' | sfdisk -q "$IMG"
mkfs.vfat -F 32 -n EVIDENCE --offset 2048 "$IMG" 64512 >/dev/null

export MTOOLS_SKIP_CHECK=1
PART="$IMG@@1M"
mcopy -s -m -i "$PART" "$TREE/Users" "$TREE/Windows" "$TREE/\$Recycle.Bin" ::/
mdir -i "$PART" '::/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001'

# Delete a file so deleted-file recovery has something to find.
mdel -i "$PART" ::/Users/alice/Documents/payroll-export.csv

# Ground truth for the tests: every generated file with its size, SHA-256 and stamped time.
python3 scripts/test-image/write_manifest.py "$TREE" "$IMG" 2048 Users/alice/Documents/payroll-export.csv

rm -rf "$WORK"
echo "Built $IMG"
sha256sum "$IMG"
