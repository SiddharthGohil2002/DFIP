"""Logical packages of the scenario computer, made from the same tree as the disk image (scripts/test-image/make-test-image.sh):
what a live collection on LAPTOP-07 would have taken, so the files deleted on the disk image are not in them.

- dfip-test-kape.zip: KAPE target output: the system drive under `C/` inside a timestamped collection folder, each
  file with the NTFS extra field (modified, accessed and created times as FILETIMEs, in UTC), as 7-Zip and KAPE's
  zip option keep them, and KAPE's copy log.
- dfip-test-velociraptor.zip: a Velociraptor offline collection: files under `uploads/auto/C%3A/` (the drive
  name URL-encoded, as Velociraptor stores it), each with the extended timestamp extra field (modified time, UTC),
  next to the collection's own JSON files.

Usage: make_packages.py TREE OUT_DIR [deleted path ...]
"""
import csv
import hashlib
import io
import json
import os
import struct
import sys
import time
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path

EPOCH_1601 = 11644473600


def filetime(ts: float) -> int:
    return int((ts + EPOCH_1601) * 10_000_000)


def ntfs_extra(st) -> bytes:
    body = struct.pack('<I', 0) + struct.pack('<HH', 1, 24) + struct.pack('<QQQ', filetime(st.st_mtime), filetime(st.st_atime),
                                                                             filetime(st.st_mtime))
    return struct.pack('<HH', 0x000A, len(body)) + body


def ut_extra(st) -> bytes:
    body = bytes([1]) + struct.pack('<i', int(st.st_mtime))
    return struct.pack('<HH', 0x5455, len(body)) + body


def files_of(tree: Path, skip: set[str]):
    for p in sorted(tree.rglob('*')):
        rel = p.relative_to(tree).as_posix()
        if p.is_file() and not p.is_symlink() and rel not in skip:
            yield rel, p


def local_dos_time(ts: float):
    # KAPE runs on the collected computer: its zip's plain times are that computer's local time (US Eastern here).
    os.environ['TZ'] = 'America/New_York'
    time.tzset()
    t = time.localtime(ts)
    return t[:6]


def main(tree: Path, out: Path, skip: set[str]):
    out.mkdir(parents=True, exist_ok=True)
    kape = out / 'dfip-test-kape.zip'
    log = io.StringIO()
    w = csv.writer(log)
    w.writerow(['CopiedTimestamp', 'SourceFile', 'DestinationFile', 'FileSize', 'SourceFileSha1', 'DeferredCopy', 'CreatedOnUtc',
                'ModifiedOnUtc', 'LastAccessedOnUtc', 'CopyDuration'])
    with zipfile.ZipFile(kape, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel, p in files_of(tree, skip):
            st = p.stat()
            info = zipfile.ZipInfo(f'2026-09-01T190512_LAPTOP-07/C/{rel}', date_time=local_dos_time(st.st_mtime))
            info.extra = ntfs_extra(st)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            data = p.read_bytes()
            z.writestr(info, data)
            iso = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            w.writerow(['2026-09-01 19:05:12', 'C:\\' + rel.replace('/', '\\'), f'C:\\kape\\out\\C\\{rel}'.replace('/', '\\'), len(data),
                        hashlib.sha1(data).hexdigest(), 'False', iso(st.st_mtime), iso(st.st_mtime), iso(st.st_atime), '00:00:00.0010000'])
        info = zipfile.ZipInfo('2026-09-01T190512_LAPTOP-07/2026-09-01T190512_CopyLog.csv', date_time=(2026, 9, 1, 15, 5, 12))
        z.writestr(info, log.getvalue())

    velo = out / 'dfip-test-velociraptor.zip'
    with zipfile.ZipFile(velo, 'w', zipfile.ZIP_DEFLATED) as z:
        uploads = []
        for rel, p in files_of(tree, skip):
            st = p.stat()
            name = 'uploads/auto/' + urllib.parse.quote('C:', safe='') + '/' + '/'.join(urllib.parse.quote(x, safe=' ') for x in rel.split('/'))
            info = zipfile.ZipInfo(name, date_time=time.gmtime(st.st_mtime)[:6])
            info.extra = ut_extra(st)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
            uploads.append({'Timestamp': '2026-09-01T19:05:12Z', 'started': '2026-09-01 19:05:12 +0000 UTC', 'vfs_path': 'C:\\' + rel.replace('/', '\\'),
                            '_Components': ['C:'] + rel.split('/'), 'file_size': st.st_size, 'uploaded_size': st.st_size, 'Type': ''})
        z.writestr('uploads.json', '\n'.join(json.dumps(u) for u in uploads) + '\n')
        z.writestr('client_info.json', json.dumps({'Hostname': 'LAPTOP-07', 'OS': 'windows', 'Platform': 'Microsoft Windows 10 Pro'}))
        z.writestr('collection_context.json', json.dumps({'client_id': 'C.0000000000000001', 'session_id': 'F.CRHGKJ9ID0SK0',
                                                          'artifacts': ['Windows.KapeFiles.Targets'], 'create_time': 1788289512}))
    print('Built', kape, 'and', velo)


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), set(sys.argv[3:]))
