#!/bin/sh
# Plaso's own timeline of the scenario disk, for the timeline import tests: the official Plaso image (pinned by digest)
# runs log2timeline on storage/test-images/dfip-test-disk.dd (reading local times in US Eastern, the computer's zone),
# then psort writes it as json_line and as l2tcsv next to the disk. Run after make-test-image.sh, from the repository root:
#   sh scripts/test-image/make-plaso-timeline.sh
set -eu
REPO="$(pwd -W 2>/dev/null || pwd)"
IMAGE=log2timeline/plaso@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950  # 20260720
MSYS_NO_PATHCONV=1 docker run --rm --user 0:0 --entrypoint sh -v "$REPO/storage/test-images:/img" "$IMAGE" -c '
  set -e
  cd /tmp
  log2timeline.py --unattended --quiet --timezone America/New_York --storage-file /tmp/disk.plaso /img/dfip-test-disk.dd >/dev/null
  rm -f /img/dfip-test-disk.plaso.jsonl /img/dfip-test-disk.plaso.csv
  psort.py --quiet -o json_line -w /img/dfip-test-disk.plaso.jsonl /tmp/disk.plaso >/dev/null
  psort.py --quiet -o l2tcsv -w /img/dfip-test-disk.plaso.csv /tmp/disk.plaso >/dev/null
  log2timeline.py --version 2>&1 | tail -1'
wc -l "$REPO/storage/test-images/dfip-test-disk.plaso.jsonl" "$REPO/storage/test-images/dfip-test-disk.plaso.csv"
