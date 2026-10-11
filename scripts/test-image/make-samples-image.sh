#!/bin/sh
# Builds storage/test-images/dfip-samples-disk.dd: a 192 MiB FAT32 disk holding real public samples (Plaso test data,
# Apache-2.0) at the places Windows keeps them, so the system tests can analyse real files end to end:
#   Windows/System32/sru/SRUDB.dat                                  SRUM
#   ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb   Windows Search index
#   Users/bperry/AppData/Roaming/Microsoft/Windows/Recent/{Automatic,Custom}Destinations/   Jump Lists
#   Users/demouser/AppData/Local/ConnectedDevicesPlatform/L.demouser/ActivitiesCache.db     Windows Timeline
#   Users/nromanoff/Documents/Outlook Files/nromanoff@stark-research-labs.com.pst              Outlook mailbox
#   Users/nromanoff/AppData/Roaming/Skype/plaso.user/main.db                                  Skype (classic)
#   Users/nromanoff/AppData/Local/Google/Chrome/User Data/{Default,Profile 1}/                Chrome (older and Chrome 59)
#   Users/nromanoff/AppData/Roaming/Mozilla/Firefox/Profiles/plaso.default/places.sqlite      Firefox
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
         customDestinations-ms/368d807282ccde9d.customDestinations-ms 'nromanoff@stark-research-labs.com.pst' sqlite/skype_main.db \
         chrome/History chrome/History-59.0.3071.86 'chrome/Web Data' chrome/Cookies-68.0.3440.106 firefox/places.sqlite; do
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
N="$T/Users/nromanoff"
CHROME="$N/AppData/Local/Google/Chrome/User Data"
mkdir -p "$N/Documents/Outlook Files" "$N/AppData/Roaming/Skype/plaso.user" "$CHROME/Default" "$CHROME/Profile 1" \
         "$N/AppData/Roaming/Mozilla/Firefox/Profiles/plaso.default"
cp "$S/nromanoff@stark-research-labs.com.pst" "$N/Documents/Outlook Files/"
cp "$S/sqlite/skype_main.db" "$N/AppData/Roaming/Skype/plaso.user/main.db"
cp "$S/chrome/History" "$CHROME/Default/History"
cp "$S/chrome/Web Data" "$CHROME/Default/Web Data"
cp "$S/chrome/Cookies-68.0.3440.106" "$CHROME/Default/Cookies"
cp "$S/chrome/History-59.0.3071.86" "$CHROME/Profile 1/History"
cp "$S/firefox/places.sqlite" "$N/AppData/Roaming/Mozilla/Firefox/Profiles/plaso.default/places.sqlite"
find "$T" -type f -exec touch -d '2018-08-03 12:00:00 UTC' {} +

rm -f "$IMG"
truncate -s 192M "$IMG"
printf 'label: dos\nstart=2048, type=c\n' | sfdisk -q "$IMG"
mkfs.vfat -F 32 -n SAMPLES --offset 2048 "$IMG" 195584 >/dev/null
export MTOOLS_SKIP_CHECK=1 TZ=UTC
mcopy -s -m -i "$IMG@@1M" "$T/Windows" "$T/ProgramData" "$T/Users" ::/
rm -rf "$WORK"
echo "Built $IMG"
sha256sum "$IMG"
