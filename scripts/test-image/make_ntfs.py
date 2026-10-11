"""Fills the NTFS test volume (see make-ntfs-image.sh): alice's office desktop, ALICE-DESKTOP.

The story: SecureDelete.exe is downloaded with Chrome at 10:05 (its Zone.Identifier stream names the page) and
archiver.zip with Firefox at 10:33; at 14:15 alice saves payroll-copy.csv and notes.txt, with a note hidden in an
alternate data stream (notes.txt:hidden.txt); at 14:16 she writes budget-2025.txt and sets its times back to
2 March 2024 (timestomping: the $STANDARD_INFORMATION times become one whole-second value, while $FILE_NAME keeps when
the file was really created); at 14:18:44 SecureDelete renames payroll-copy.csv to AAAAAAAA.AAA, overwrites it and
deletes it. The USN change journal records all of it, including the time change and the wipe.

Files are written through ntfs-3g (FUSE) running under faketime, so Windows-like creation times land in both
$STANDARD_INFORMATION and $FILE_NAME. ntfs-3g does not keep a USN journal, so $Extend/$UsnJrnl ($J and $Max) is created
through libntfs-3g directly (the FUSE layer refuses to write in $Extend), before any file exists, and its records are
written at the end. Writes the manifest the tests compare with.

    python3 make_ntfs.py VOLUME MANIFEST          (as root, in a privileged container; see make-ntfs-image.sh)
"""
import ctypes
import glob
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone

MNT = '/mnt/ntfs'
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
JOURNAL_START = 8192           # the journal's first records follow two empty pages (Windows leaves its start sparse)
JOURNAL_SIZE = 12288
SECUREDELETE = b'SecureDelete.exe 1.4.0 test binary'
PAYROLL = ('employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))).encode()
NOTES = b'Meeting notes: Q3 review moved to Friday.\r\n'
HIDDEN = b'Copy the payroll to the SanDisk, then wipe it.\r\n'
BUDGET = b'Budget 2025 draft - figures to be confirmed.\r\n'
STOMPED = datetime(2024, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
ZONE_SECUREDELETE = ('[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://tools.example.org/securedelete\r\n'
                     'HostUrl=https://tools.example.org/securedelete/SecureDelete.exe\r\n').encode()
ZONE_ARCHIVER = ('[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://cdn.example.org/tools/\r\n'
                 'HostUrl=https://cdn.example.org/tools/archiver.zip\r\n').encode()
FILE_CREATE, DATA_EXTEND, DATA_OVERWRITE, NAMED_DATA_EXTEND, STREAM_CHANGE = 0x100, 0x2, 0x1, 0x20, 0x200000
BASIC_INFO_CHANGE, RENAME_OLD, RENAME_NEW, FILE_DELETE, CLOSE = 0x8000, 0x1000, 0x2000, 0x200, 0x80000000


def ft(dt: datetime) -> int:
    d = dt - EPOCH_1601
    return (d.days * 86_400 + d.seconds) * 10_000_000 + d.microseconds * 10


def at(h, m, s, us=0):
    return datetime(2026, 9, 1, h, m, s, us, tzinfo=timezone.utc)


def archiver_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr(zipfile.ZipInfo('archiver/README.txt', (2026, 8, 20, 9, 0, 0)), 'Archiver 2.1 - command-line archive tool.\n')
    return buf.getvalue()


# ---------------------------------------------------------------- libntfs-3g, for $Extend/$UsnJrnl
def libntfs():
    lib = ctypes.CDLL(glob.glob('/usr/lib/*/libntfs-3g.so.*')[0])
    p, i = ctypes.c_void_p, ctypes.c_int
    sig = {'ntfs_mount': (p, [ctypes.c_char_p, ctypes.c_ulong]), 'ntfs_umount': (i, [p, i]),
           'ntfs_pathname_to_inode': (p, [p, p, ctypes.c_char_p]),
           'ntfs_create': (p, [p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint8, ctypes.c_uint32]),
           'ntfs_attr_add': (i, [p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint8, ctypes.c_char_p, ctypes.c_int64]),
           'ntfs_attr_remove': (i, [p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32]),
           'ntfs_attr_open': (p, [p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32]),
           'ntfs_attr_pwrite': (ctypes.c_int64, [p, ctypes.c_int64, ctypes.c_int64, ctypes.c_char_p]),
           'ntfs_attr_close': (None, [p]), 'ntfs_inode_close': (i, [p])}
    for name, (res, args) in sig.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = res, args
    return lib


J, MAX = '$J'.encode('utf-16-le'), '$Max'.encode('utf-16-le')


def create_journal(volume: str):
    """$Extend/$UsnJrnl with $J (kept as the first data stream, as Windows has it: readers such as the Sleuth Kit
    take the lowest-numbered one) and $Max, and without the unnamed data stream a new file gets."""
    lib = libntfs()
    vol = lib.ntfs_mount(volume.encode(), 0)
    ext = lib.ntfs_pathname_to_inode(vol, None, b'/$Extend')
    ni = lib.ntfs_create(ext, 0, '$UsnJrnl'.encode('utf-16-le'), 8, 0o100000)
    assert vol and ext and ni, 'could not create $Extend/$UsnJrnl'
    assert lib.ntfs_attr_remove(ni, 0x80, b'\0\0', 0) == 0
    assert lib.ntfs_attr_add(ni, 0x80, J, 2, b'\0', 1) == 0
    assert lib.ntfs_attr_add(ni, 0x80, MAX, 4, struct.pack('<QQQQ', 32 << 20, 8 << 20, 0x01DD1A2B3C4D5E6F, 0), 32) == 0
    na = lib.ntfs_attr_open(ni, 0x80, J, 2)
    assert lib.ntfs_attr_pwrite(na, 0, JOURNAL_SIZE, bytes(JOURNAL_SIZE)) == JOURNAL_SIZE
    lib.ntfs_attr_close(na)
    lib.ntfs_inode_close(ni)
    lib.ntfs_inode_close(ext)
    assert lib.ntfs_umount(vol, 0) == 0


def write_journal(volume: str, data: bytes):
    lib = libntfs()
    vol = lib.ntfs_mount(volume.encode(), 0)
    ni = lib.ntfs_pathname_to_inode(vol, None, b'/$Extend/$UsnJrnl')
    na = lib.ntfs_attr_open(ni, 0x80, J, 2)
    assert vol and ni and na
    assert lib.ntfs_attr_pwrite(na, JOURNAL_START, len(data), data) == len(data)
    lib.ntfs_attr_close(na)
    lib.ntfs_inode_close(ni)
    assert lib.ntfs_umount(vol, 0) == 0


def usn_record(usn, entry, parent, when, reason, name) -> bytes:
    """A USN_RECORD_V2 (sequence number 1: every file here is new), padded to 8 bytes."""
    n = name.encode('utf-16-le')
    size = 60 + len(n)
    size += -size % 8
    return (struct.pack('<IHHQQQQIIIIHH', size, 2, 0, entry | (1 << 48), parent | (1 << 48), usn, ft(when), reason, 0, 0, 0x20,
                        len(n), 60) + n).ljust(size, b'\0')


# ---------------------------------------------------------------- MFT records, read and patched in place
def mft_record_offset(volume: str, entry: int) -> int:
    """Byte offset of an MFT record: the boot sector gives $MFT's first cluster and the record size; $MFT's own
    $DATA run list maps record numbers to clusters."""
    with open(volume, 'rb') as f:
        boot = f.read(512)
        bps, spc = struct.unpack_from('<HB', boot, 0x0B)
        cluster = bps * spc
        mft_lcn = struct.unpack_from('<Q', boot, 0x30)[0]
        cpr = struct.unpack_from('<b', boot, 0x40)[0]
        rec_size = cpr * cluster if cpr > 0 else 1 << -cpr
        f.seek(mft_lcn * cluster)
        rec0 = f.read(rec_size)
    pos = struct.unpack_from('<H', rec0, 0x14)[0]
    while True:
        kind, length = struct.unpack_from('<II', rec0, pos)
        if kind == 0x80:
            break
        pos += length
    runs_at = pos + struct.unpack_from('<H', rec0, pos + 0x20)[0]
    want, vcn, lcn, p = entry * rec_size // cluster, 0, 0, runs_at
    while rec0[p]:
        h = rec0[p]
        nl, no = h & 0x0F, h >> 4
        run_len = int.from_bytes(rec0[p + 1:p + 1 + nl], 'little')
        lcn += int.from_bytes(rec0[p + 1 + nl:p + 1 + nl + no], 'little', signed=True)
        if vcn <= want < vcn + run_len:
            return (lcn + want - vcn) * cluster + (entry * rec_size) % cluster
        vcn += run_len
        p += 1 + nl + no
    raise ValueError(f'MFT record {entry} not found')


def file_name_times(volume: str, entry: int, new: bytes | None = None) -> bytes:
    """The four FILETIMEs of a record's $FILE_NAME attribute (created, modified, MFT changed, accessed); replaced when
    `new` is given. These bytes are not at a sector end, so the record's fix-up values are unaffected."""
    off = mft_record_offset(volume, entry)
    with open(volume, 'r+b') as f:
        f.seek(off)
        rec = f.read(1024)
        pos = struct.unpack_from('<H', rec, 0x14)[0]
        while pos < len(rec) - 8:
            kind, length = struct.unpack_from('<II', rec, pos)
            if kind == 0xFFFFFFFF:
                break
            if kind == 0x30:
                at = pos + struct.unpack_from('<H', rec, pos + 0x14)[0] + 8
                if new is not None:
                    f.seek(off + at)
                    f.write(new)
                return rec[at:at + 32]
            pos += length
    raise ValueError(f'MFT record {entry} has no $FILE_NAME')


# ---------------------------------------------------------------- ntfs-3g under a fake clock
class Mounted:
    def __init__(self, volume, when: str):
        self.volume, self.when = volume, when

    def __enter__(self):
        os.makedirs(MNT, exist_ok=True)
        self.proc = subprocess.Popen(['faketime', '-f', f'@{self.when}', 'ntfs-3g', '-o', 'streams_interface=windows', self.volume, MNT])
        for _ in range(200):
            if os.path.ismount(MNT):
                return self
            time.sleep(0.05)
        raise RuntimeError('ntfs-3g did not mount the volume')

    def __exit__(self, *exc):
        subprocess.run(['umount', MNT], check=True)
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def put(rel: str, data: bytes, streams: dict | None = None) -> int:
    path = os.path.join(MNT, rel)
    with open(path, 'wb') as f:
        f.write(data)
    for name, content in (streams or {}).items():
        with open(f'{path}:{name}', 'wb') as f:
            f.write(content)
    return os.stat(path).st_ino


def main():
    volume, manifest_path = sys.argv[1], sys.argv[2]
    if len(sys.argv) > 3 and sys.argv[3] == '--create-journal':
        create_journal(volume)
        return
    # The journal exists before the files (created under the fake clock, so its own times are plausible).
    subprocess.run(['faketime', '-f', '@2026-08-20 09:00:00', sys.executable, __file__, volume, manifest_path, '--create-journal'], check=True)
    ino = {}
    with Mounted(volume, '2026-09-01 10:05:00'):
        os.makedirs(f'{MNT}/Users/alice/Downloads')
        os.makedirs(f'{MNT}/Users/alice/Documents')
        ino['Downloads'] = os.stat(f'{MNT}/Users/alice/Downloads').st_ino
        ino['Documents'] = os.stat(f'{MNT}/Users/alice/Documents').st_ino
        ino['SecureDelete.exe'] = put('Users/alice/Downloads/SecureDelete.exe', SECUREDELETE, {'Zone.Identifier': ZONE_SECUREDELETE})
    with Mounted(volume, '2026-09-01 10:33:05'):
        ino['archiver.zip'] = put('Users/alice/Downloads/archiver.zip', archiver_zip(), {'Zone.Identifier': ZONE_ARCHIVER})
    with Mounted(volume, '2026-09-01 14:15:09'):
        ino['payroll-copy.csv'] = put('Users/alice/Documents/payroll-copy.csv', PAYROLL)
        ino['notes.txt'] = put('Users/alice/Documents/notes.txt', NOTES, {'hidden.txt': HIDDEN})
    with Mounted(volume, '2026-09-01 14:16:04'):
        ino['budget-2025.txt'] = put('Users/alice/Documents/budget-2025.txt', BUDGET)
    names = file_name_times(volume, ino['budget-2025.txt'])
    with Mounted(volume, '2026-09-01 14:16:40'):
        # Creation, modification and access times set to one whole-second value, as SetFileTime would (Windows then
        # sets the change time to now). ntfs-3g also rewrites the $FILE_NAME times, which Windows does not: they are
        # put back below.
        os.setxattr(f'{MNT}/Users/alice/Documents/budget-2025.txt', 'system.ntfs_times', struct.pack('<4Q', *([ft(STOMPED)] * 4)))
    file_name_times(volume, ino['budget-2025.txt'], names)
    with Mounted(volume, '2026-09-01 14:18:44'):
        os.rename(f'{MNT}/Users/alice/Documents/payroll-copy.csv', f'{MNT}/Users/alice/Documents/AAAAAAAA.AAA')
        with open(f'{MNT}/Users/alice/Documents/AAAAAAAA.AAA', 'r+b') as f:
            f.write(bytes(len(PAYROLL)))
        os.remove(f'{MNT}/Users/alice/Documents/AAAAAAAA.AAA')

    dl, docs = ino['Downloads'], ino['Documents']
    plan = [  # (entry, parent, time, reason, name)
        (ino['SecureDelete.exe'], dl, at(10, 5, 0, 123456), FILE_CREATE, 'SecureDelete.exe'),
        (ino['SecureDelete.exe'], dl, at(10, 5, 0, 130123), FILE_CREATE | DATA_EXTEND, 'SecureDelete.exe'),
        (ino['SecureDelete.exe'], dl, at(10, 5, 9, 45312), FILE_CREATE | DATA_EXTEND | CLOSE, 'SecureDelete.exe'),
        (ino['SecureDelete.exe'], dl, at(10, 5, 9, 61234), NAMED_DATA_EXTEND | STREAM_CHANGE, 'SecureDelete.exe'),
        (ino['SecureDelete.exe'], dl, at(10, 5, 9, 62345), NAMED_DATA_EXTEND | STREAM_CHANGE | CLOSE, 'SecureDelete.exe'),
        (ino['archiver.zip'], dl, at(10, 33, 5, 201000), FILE_CREATE | DATA_EXTEND | CLOSE, 'archiver.zip'),
        (ino['archiver.zip'], dl, at(10, 33, 5, 230500), NAMED_DATA_EXTEND | STREAM_CHANGE | CLOSE, 'archiver.zip'),
        (ino['payroll-copy.csv'], docs, at(14, 15, 9, 250000), FILE_CREATE, 'payroll-copy.csv'),
        (ino['payroll-copy.csv'], docs, at(14, 15, 9, 260125), FILE_CREATE | DATA_EXTEND | CLOSE, 'payroll-copy.csv'),
        (ino['notes.txt'], docs, at(14, 15, 30, 500000), FILE_CREATE | DATA_EXTEND | CLOSE, 'notes.txt'),
        (ino['notes.txt'], docs, at(14, 15, 31, 125000), NAMED_DATA_EXTEND | STREAM_CHANGE | CLOSE, 'notes.txt'),
        (ino['budget-2025.txt'], docs, at(14, 16, 4, 510000), FILE_CREATE | DATA_EXTEND | CLOSE, 'budget-2025.txt'),
        (ino['budget-2025.txt'], docs, at(14, 16, 40, 250000), BASIC_INFO_CHANGE, 'budget-2025.txt'),
        (ino['budget-2025.txt'], docs, at(14, 16, 40, 250000), BASIC_INFO_CHANGE | CLOSE, 'budget-2025.txt'),
        (ino['payroll-copy.csv'], docs, at(14, 18, 44, 100000), RENAME_OLD, 'payroll-copy.csv'),
        (ino['payroll-copy.csv'], docs, at(14, 18, 44, 100000), RENAME_NEW, 'AAAAAAAA.AAA'),
        (ino['payroll-copy.csv'], docs, at(14, 18, 44, 100000), RENAME_NEW | CLOSE, 'AAAAAAAA.AAA'),
        (ino['payroll-copy.csv'], docs, at(14, 18, 44, 600000), DATA_OVERWRITE, 'AAAAAAAA.AAA'),
        (ino['payroll-copy.csv'], docs, at(14, 18, 44, 600000), DATA_OVERWRITE | CLOSE, 'AAAAAAAA.AAA'),
        (ino['payroll-copy.csv'], docs, at(14, 18, 45, 0), FILE_DELETE | CLOSE, 'AAAAAAAA.AAA'),
    ]
    data, records = b'', []
    for entry, parent, when, reason, name in plan:
        usn = JOURNAL_START + len(data)
        data += usn_record(usn, entry, parent, when, reason, name)
        records.append({'usn': usn, 'entry': entry, 'sequence': 1, 'parent_entry': parent, 'time': when.isoformat(),
                        'time_raw': ft(when), 'reason_flags': reason, 'name': name})
    assert len(data) <= JOURNAL_SIZE - JOURNAL_START
    write_journal(volume, data)

    sha = lambda b: hashlib.sha256(b).hexdigest()
    manifest = {
        'files': {'/Users/alice/Downloads/SecureDelete.exe': {'sha256': sha(SECUREDELETE), 'size': len(SECUREDELETE)},
                  '/Users/alice/Downloads/archiver.zip': {'sha256': sha(archiver_zip()), 'size': len(archiver_zip())},
                  '/Users/alice/Documents/notes.txt': {'sha256': sha(NOTES), 'size': len(NOTES)},
                  '/Users/alice/Documents/budget-2025.txt': {'sha256': sha(BUDGET), 'size': len(BUDGET)}},
        'streams': {'/Users/alice/Downloads/SecureDelete.exe:Zone.Identifier': ZONE_SECUREDELETE.decode(),
                    '/Users/alice/Downloads/archiver.zip:Zone.Identifier': ZONE_ARCHIVER.decode(),
                    '/Users/alice/Documents/notes.txt:hidden.txt': HIDDEN.decode()},
        'timestomped': {'path': '/Users/alice/Documents/budget-2025.txt', 'si': STOMPED.isoformat()},
        'wiped': {'entry': ino['payroll-copy.csv'], 'names': ['payroll-copy.csv', 'AAAAAAAA.AAA'], 'size': len(PAYROLL)},
        'entries': ino, 'usn': records,
    }
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=1)


if __name__ == '__main__':
    main()
