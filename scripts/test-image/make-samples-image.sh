#!/bin/sh
# Builds storage/test-images/dfip-samples-disk.dd: a 96 MiB FAT32 disk holding real public samples (Plaso test data,
# Apache-2.0) at the places Windows keeps them, so the system tests can analyse real files end to end:
#   Windows/System32/sru/SRUDB.dat                                  SRUM
#   ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb   Windows Search index
#   Users/bperry/AppData/Roaming/Microsoft/Windows/Recent/{Automatic,Custom}Destinations/   Jump Lists
#   Users/demouser/AppData/Local/ConnectedDevicesPlatform/L.demouser/ActivitiesCache.db     Windows Timeline
# The samples come from different computers; the disk is a container for testing parsers, not a scenario.
#
# Run from the repository root after the samples were fetched (fetch-samples.sh runs this itself):
#   docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-samples-image.sh
set -eu
S=storage/test-images/samples/plaso
IMG=storage/test-images/dfip-samples-disk.dd
JUMP=Users/bperry/AppData/Roaming/Microsoft/Windows/Recent
for f in SRUDB.dat Windows.edb windows/ActivitiesCache.db automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms \
         automaticDestinations-ms/9d1f905ce5044aee.automaticDestinations-ms customDestinations-ms/5afe4de1b92fc382.customDestinations-ms \
         customDestinations-ms/368d807282ccde9d.customDestinations-ms; do
  [ -f "$S/$f" ] || { echo "Missing sample $S/$f: run scripts/test-image/fetch-samples.sh first"; exit 1; }
done
apt-get update -qq >/dev/null && apt-get install -y -qq mtools dosfstools fdisk >/dev/null

WORK=$(mktemp -d)
T="$WORK/tree"
mkdir -p "$T/Windows/System32/sru" "$T/ProgramData/Microsoft/Search/Data/Applications/Windows" \
         "$T/$JUMP/AutomaticDestinations" "$T/$JUMP/CustomDestinations" \
         "$T/Users/demouser/AppData/Local/ConnectedDevicesPlatform/L.demouser"
cp "$S/SRUDB.dat" "$T/Windows/System32/sru/"
cp "$S/Windows.edb" "$T/ProgramData/Microsoft/Search/Data/Applications/Windows/"
cp "$S"/automaticDestinations-ms/*.automaticDestinations-ms "$T/$JUMP/AutomaticDestinations/"
cp "$S"/customDestinations-ms/*.customDestinations-ms "$T/$JUMP/CustomDestinations/"
cp "$S/windows/ActivitiesCache.db" "$T/Users/demouser/AppData/Local/ConnectedDevicesPlatform/L.demouser/"
find "$T" -type f -exec touch -d '2018-08-03 12:00:00 UTC' {} +

rm -f "$IMG"
truncate -s 96M "$IMG"
printf 'label: dos\nstart=2048, type=c\n' | sfdisk -q "$IMG"
mkfs.vfat -F 32 -n SAMPLES --offset 2048 "$IMG" 97280 >/dev/null
export MTOOLS_SKIP_CHECK=1 TZ=UTC
mcopy -s -m -i "$IMG@@1M" "$T/Windows" "$T/ProgramData" "$T/Users" ::/
rm -rf "$WORK"
echo "Built $IMG"
sha256sum "$IMG"
