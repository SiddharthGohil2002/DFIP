#!/bin/sh
# Builds storage/test-images/dfip-test-disk.dd: a 64 MiB MBR disk with one FAT32
# partition laid out like a Windows system, for end-to-end testing of DFIP's
# deleted-file, timeline, browser, USB and Windows activity (Prefetch, Recent, Recycle Bin) analysis,
# and of the computer, its users and its time zone (SYSTEM, SOFTWARE and SAM hives).
#
# FAT stores local time. The scenario computer is in the US Eastern time zone, so the file times are written
# as US Eastern local time (mtools runs with TZ=America/New_York), exactly as Windows would write them; DFIP
# must read the time zone from the SYSTEM hive to get them back to UTC.
#
# Run from the repository root (needs only Docker; no root, mounting or FUSE):
#   docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-test-image.sh
set -eu

apt-get update -qq >/dev/null && apt-get install -y -qq mtools dosfstools fdisk tzdata python3-hivex 7zip >/dev/null
# Encrypted ZIP and Office test files, and a PDF with an attachment.
pip install -q --root-user-action=ignore pyzipper==0.4.0 msoffcrypto-tool==6.0.0 pypdf==6.19.0

WORK=$(mktemp -d)
TREE="$WORK/tree"
OUT_DIR=storage/test-images
IMG="$OUT_DIR/dfip-test-disk.dd"
mkdir -p "$OUT_DIR"
rm -f "$IMG"

python3 scripts/test-image/make_artifacts.py "$TREE"
# Registry hives, written with hivex (Debian's python3 with python3-hivex).
(cd scripts/test-image && /usr/bin/python3 make_hives.py "$TREE" ../../backend/tests/fixtures/SYSTEM.xz)

# Give files distinct, known modification times (always stated in UTC) so the timeline is meaningful.
stamp() { touch -d "$1 UTC" "$TREE/$2"; }
for hive in SYSTEM SOFTWARE SAM; do stamp '2026-09-01 18:42:10' "Windows/System32/config/$hive"; done  # last shutdown
stamp '2026-09-01 18:42:08' 'Users/alice/NTUSER.DAT'                                   # written at logoff
stamp '2026-09-01 18:42:08' 'Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat'
stamp '2026-09-01 10:06:04' 'Windows/AppCompat/Programs/Amcache.hve'
# Event logs: written when their last event was.
stamp '2026-09-01 18:42:06' 'Windows/System32/winevt/Logs/Security.evtx'
stamp '2026-09-01 18:42:06' 'Windows/System32/winevt/Logs/System.evtx'
stamp '2026-09-01 14:24:32' 'Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx'
stamp '2026-09-01 14:24:34' 'Windows/System32/winevt/Logs/Windows PowerShell.evtx'
stamp '2026-09-01 14:41:10' 'Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx'
# Jump Lists, the Windows Timeline and the thumbnail cache: written when last updated.
JL='Users/alice/AppData/Roaming/Microsoft/Windows/Recent'
stamp '2026-09-01 14:14:07' "$JL/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms"
stamp '2026-09-01 14:13:03' "$JL/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms"
stamp '2026-09-01 10:21:40' "$JL/CustomDestinations/5d696d521de238c3.customDestinations-ms"
stamp '2026-09-01 14:21:05' 'Users/alice/AppData/Local/ConnectedDevicesPlatform/L.alice/ActivitiesCache.db'
stamp '2026-09-01 14:00:02' 'Users/alice/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db'
stamp '2026-09-01 14:12:46' 'Windows/INF/setupapi.dev.log'
stamp '2026-08-28 16:04:10' 'Users/alice/Documents/project-notes.txt'
stamp '2026-09-01 09:41:02' 'Users/alice/Documents/payroll-export.csv'
stamp '2026-09-01 10:06:30' 'Users/alice/Downloads/cleanup.ps1'
stamp '2026-09-01 10:20:15' 'Users/alice/AppData/Local/Google/Chrome/User Data/Default/History'
stamp '2026-09-01 10:33:05' 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite'
# Browser profiles, email, chat and cloud storage (Phase 9): written when last used.
CH='Users/alice/AppData/Local/Google/Chrome/User Data/Default'
FF='Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release'
TB='Users/alice/AppData/Roaming/Thunderbird/Profiles/q7w1.default-release/ImapMail/imap.corp.example'
stamp '2026-09-01 14:21:40' "$CH/Web Data"
stamp '2026-09-01 14:19:06' "$CH/Login Data"
stamp '2026-09-01 10:04:41' "$CH/Bookmarks"
stamp '2026-09-01 14:40:00' "$CH/Network/Cookies"
stamp '2026-09-01 14:31:41' "$FF/places.sqlite-wal"
stamp '2026-09-01 14:30:58' "$FF/formhistory.sqlite"
stamp '2026-09-01 14:31:30' "$FF/logins.json"
stamp '2026-09-01 13:35:14' "$TB/INBOX"
stamp '2026-09-01 13:35:14' "$TB/INBOX.msf"
stamp '2026-09-01 14:41:07' "$TB/Sent"
stamp '2026-09-01 14:41:07' "$TB/Sent.msf"
stamp '2025-03-12 18:27:34' 'Users/alice/AppData/Roaming/Skype/alice.example/main.db'
stamp '2026-09-01 14:26:12' 'Users/alice/AppData/Local/Microsoft/OneDrive/settings/Personal/SyncEngineDatabase.db'
stamp '2025-06-02 09:00:00' 'Users/alice/AppData/Local/Dropbox/info.json'
find "$TREE/Users/alice/AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm" -type f -exec touch -d '2026-09-01 14:24:50 UTC' {} +
find "$TREE/Users/alice/AppData/Roaming/Telegram Desktop" -type f -exec touch -d '2026-08-31 22:10:00 UTC' {} +
# Windows activity (the times Windows would have written): shortcut written when the payroll export was
# opened from E:, the $I index when it went to the Recycle Bin ($R keeps the file's own time), Prefetch ~10 s after a run.
stamp '2026-09-01 14:14:06' 'Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk'
stamp '2026-09-01 14:15:20' '$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$I3K9D2A.csv'
stamp '2026-09-01 09:41:02' '$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$R3K9D2A.csv'
touch -d '2026-09-01 14:18:40 UTC' "$TREE"/Windows/Prefetch/SECUREDELETE.EXE-*.pf
stamp '2026-08-31 17:22:00' 'Users/alice/Pictures/whiteboard.png'
stamp '2026-08-30 11:00:00' 'Users/alice/Documents/offer-letter.pdf'
# Hidden and encrypted files: the renamed copy keeps the export's own time, as a copy does.
stamp '2026-09-01 09:41:02' 'Users/alice/Pictures/holiday.jpg'
stamp '2026-09-01 14:16:40' 'Users/alice/Documents/private.zip'
stamp '2026-08-29 15:12:00' 'Users/alice/Documents/salary-review.docx'
stamp '2026-08-31 20:05:00' 'Users/alice/Documents/vault.dat'
stamp '2026-09-01 10:40:00' 'Users/alice/Downloads/eicar.com'
# Documents for content search and found data.
stamp '2026-08-27 18:30:00' 'Users/alice/Documents/contacts.txt'
stamp '2026-09-01 13:05:00' 'Users/alice/Documents/handover.docx'
stamp '2026-09-01 11:20:00' 'Users/alice/Documents/meeting-notes.rtf'
stamp '2026-09-01 14:11:30' 'Users/alice/Documents/notes-utf16.txt'
stamp '2026-08-26 09:15:00' 'Users/alice/Documents/budget.odt'
# Archives and documents with embedded files.
stamp '2026-09-01 14:16:20' 'Users/alice/Documents/export-backup.zip'
stamp '2026-08-31 16:45:00' 'Users/alice/Documents/q3-payroll.docx'
stamp '2026-08-29 09:30:00' 'Users/alice/Documents/statement.pdf'
# Standard time (EST, UTC-5): proves the conversion follows daylight saving by date, not one fixed offset.
stamp '2026-01-15 15:30:00' 'Users/alice/Documents/q1-forecast.txt'
stamp '2025-11-02 14:00:00' 'Users/alice/Documents/year-end-checklist.txt'

# 64 MiB disk, MBR partition table, FAT32 (LBA) partition starting at sector 2048.
truncate -s 64M "$IMG"
printf 'label: dos\nstart=2048, type=c\n' | sfdisk -q "$IMG"
mkfs.vfat -F 32 -n EVIDENCE --offset 2048 "$IMG" 64512 >/dev/null

export MTOOLS_SKIP_CHECK=1
export TZ=America/New_York  # FAT times are written in the computer's local time
PART="$IMG@@1M"
mcopy -s -m -i "$PART" "$TREE/Users" "$TREE/Windows" "$TREE/\$Recycle.Bin" ::/
mdir -i "$PART" '::/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001'

# Delete a file so deleted-file recovery has something to find.
mdel -i "$PART" ::/Users/alice/Documents/payroll-export.csv
unset TZ

# Ground truth for the tests: every generated file with its size, SHA-256 and stamped time (UTC).
python3 scripts/test-image/write_manifest.py "$TREE" "$IMG" 2048 Users/alice/Documents/payroll-export.csv

rm -rf "$WORK"
echo "Built $IMG"
sha256sum "$IMG"
