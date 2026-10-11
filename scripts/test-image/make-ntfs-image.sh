#!/bin/sh
# Builds storage/test-images/dfip-ntfs-disk.dd: a 64 MiB MBR disk with one NTFS partition (sector 2048), alice's office
# desktop, for testing NTFS internals: timestomping ($STANDARD_INFORMATION vs $FILE_NAME times), alternate data streams
# (Zone.Identifier and a hidden note) and the USN change journal (a file renamed, overwritten and deleted). See
# make_ntfs.py for the story. Writes dfip-ntfs-disk.manifest.json next to it, the tests' ground truth.
#
# Needs a privileged container (ntfs-3g mounts the volume through FUSE). From the repository root:
#   docker run --rm --privileged -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-ntfs-image.sh
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq ntfs-3g faketime fdisk >/dev/null

OUT_DIR=storage/test-images
IMG="$OUT_DIR/dfip-ntfs-disk.dd"
WORK=$(mktemp -d)
VOL="$WORK/volume.img"
mkdir -p "$OUT_DIR"
rm -f "$IMG"

# 63 MiB NTFS volume (4 KiB clusters), told it starts at sector 2048 of a 255-head, 63-sector disk.
truncate -s 63M "$VOL"
mkntfs -q -F -L ALICE-DATA -c 4096 -p 2048 -H 255 -S 63 "$VOL" >/dev/null
python3 scripts/test-image/make_ntfs.py "$VOL" "$OUT_DIR/dfip-ntfs-disk.manifest.json"
ntfsfix -n "$VOL" >/dev/null

truncate -s 64M "$IMG"
printf 'label: dos\nstart=2048, type=7\n' | sfdisk -q "$IMG"
dd if="$VOL" of="$IMG" bs=1M seek=1 conv=notrunc status=none
rm -rf "$WORK"
echo "Built $IMG"
sha256sum "$IMG"
