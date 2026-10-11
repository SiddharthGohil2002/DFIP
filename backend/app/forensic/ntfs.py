"""NTFS internals, read with libfsntfs (pyfsntfs): the times in both $STANDARD_INFORMATION and $FILE_NAME (to find times
that were altered), alternate data streams (with the Zone.Identifier "Mark of the Web") and the USN change journal
($Extend/$UsnJrnl:$J, the volume's record of files created, changed, renamed and deleted).

Timestomping: programs (and attackers) can set a file's $STANDARD_INFORMATION times freely, but $FILE_NAME times are set
by Windows when the name is created. A file whose $SI creation time is earlier than its $FN creation time, or whose $SI
times are whole seconds while its $FN times are not (setting times through the API often drops the fraction), is
flagged with the reason. Neither proves tampering: copying, extracting archives and some installers change times too.
"""
from __future__ import annotations
import hashlib
import re
import struct
from datetime import datetime, timedelta, timezone

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
FIRST_USER_ENTRY = 24          # MFT entries 0-23 are the file system's own metadata files
MAX_STREAM_READ = 64 * 1024    # bytes of an alternate data stream read for its preview and Zone.Identifier
ZONES = {0: 'Local computer', 1: 'Local intranet', 2: 'Trusted sites', 3: 'Internet', 4: 'Restricted sites'}
REASONS = [
    (0x00000001, 'DATA_OVERWRITE'), (0x00000002, 'DATA_EXTEND'), (0x00000004, 'DATA_TRUNCATION'),
    (0x00000010, 'NAMED_DATA_OVERWRITE'), (0x00000020, 'NAMED_DATA_EXTEND'), (0x00000040, 'NAMED_DATA_TRUNCATION'),
    (0x00000100, 'FILE_CREATE'), (0x00000200, 'FILE_DELETE'), (0x00000400, 'EA_CHANGE'), (0x00000800, 'SECURITY_CHANGE'),
    (0x00001000, 'RENAME_OLD_NAME'), (0x00002000, 'RENAME_NEW_NAME'), (0x00004000, 'INDEXABLE_CHANGE'),
    (0x00008000, 'BASIC_INFO_CHANGE'), (0x00010000, 'HARD_LINK_CHANGE'), (0x00020000, 'COMPRESSION_CHANGE'),
    (0x00040000, 'ENCRYPTION_CHANGE'), (0x00080000, 'OBJECT_ID_CHANGE'), (0x00100000, 'REPARSE_POINT_CHANGE'),
    (0x00200000, 'STREAM_CHANGE'), (0x00400000, 'TRANSACTED_CHANGE'), (0x00800000, 'INTEGRITY_CHANGE'), (0x80000000, 'CLOSE'),
]
FILE_NAME = 0x30


def filetime(n: int | None) -> datetime | None:
    if not n or n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


def reason_names(flags: int) -> list[str]:
    return [name for bit, name in REASONS if flags & bit]


class OffsetFile:
    """A file object over a volume that starts `offset` bytes into an image (for libyal's open_file_object)."""

    def __init__(self, path, offset: int):
        self.f = open(path, 'rb')
        self.offset, self.pos = offset, 0
        self.f.seek(0, 2)
        self.size = self.f.tell() - offset

    def seek(self, pos, whence=0):
        self.pos = pos if whence == 0 else self.pos + pos if whence == 1 else self.size + pos
        return self.pos

    def tell(self):
        return self.pos

    def get_size(self):
        return self.size

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        self.f.seek(self.offset + self.pos)
        data = self.f.read(max(0, min(n, self.size - self.pos)))
        self.pos += len(data)
        return data

    def close(self):
        self.f.close()


def open_volume(image, offset_bytes: int = 0):
    import pyfsntfs
    fobj = OffsetFile(image, offset_bytes)
    vol = pyfsntfs.volume()
    try:
        vol.open_file_object(fobj)
    except Exception:
        fobj.close()
        raise
    return vol, fobj


def _int(fn):
    try:
        return fn()
    except Exception:
        return None


def file_names(fe) -> list[dict]:
    """The $FILE_NAME attributes of an entry (name space 2 = DOS 8.3 names are listed after the long names)."""
    out = []
    for i in range(_int(lambda: fe.number_of_attributes) or 0):
        try:
            a = fe.get_attribute(i)
            if a.attribute_type != FILE_NAME:
                continue
            out.append({'attribute_index': i, 'name': a.name, 'name_space': _int(lambda: a.name_space),
                        'parent': _int(lambda: a.parent_file_reference),
                        'created': filetime(_int(a.get_creation_time_as_integer)),
                        'modified': filetime(_int(a.get_modification_time_as_integer)),
                        'changed': filetime(_int(a.get_entry_modification_time_as_integer)),
                        'accessed': filetime(_int(a.get_access_time_as_integer)),
                        'created_raw': _int(a.get_creation_time_as_integer)})
        except Exception:
            continue
    out.sort(key=lambda x: x['name_space'] == 2)
    return out


USER_FOLDERS = re.compile(r'^[\\/](Users|Documents and Settings)[\\/][^\\/]+[\\/]', re.I)


def timestomp_reasons(si_raw: dict, fn: dict, path: str | None = None) -> tuple[str | None, list[str]]:
    """How strongly an entry's $STANDARD_INFORMATION times look altered, and why: (level, reasons).

    strong: the $SI creation time is earlier than its name's ($FN) creation, and the $SI creation, modification and
            access times are one whole-second value (what SetFileTime-based tools write; Windows then sets the change
            time to the moment of the change), while the $FN time has a fraction.
    possible: an earlier, whole-second $SI creation time in a user's folder. Elsewhere this is normal: Windows and
            installers keep the times files had on the installation media (a real Windows XP $MFT has thousands).
    """
    si_created, fn_created = si_raw.get('created'), fn.get('created_raw')
    if not si_created or not fn_created:
        return None, []
    earlier = fn_created - si_created > 10_000_000  # more than a second earlier
    whole = all(v % 10_000_000 == 0 for v in (si_raw.get('created'), si_raw.get('modified')) if v) and fn_created % 10_000_000 != 0
    same = len({si_raw.get(k) for k in ('created', 'modified', 'accessed')}) == 1
    reasons = []
    if earlier:
        reasons.append('created ($SI) is earlier than the name was created ($FN)')
    if whole:
        reasons.append('$SI times are whole seconds while $FN times are not')
    if same:
        reasons.append('$SI created, modified and accessed are the same')
    if earlier and whole and same:
        return 'strong', reasons
    if earlier and whole and path and USER_FOLDERS.match(path):
        return 'possible', reasons
    return None, []


def entries(vol, first: int = FIRST_USER_ENTRY, max_entries: int = 5_000_000):
    """Every MFT entry from `first` on that has a $FILE_NAME: {entry, sequence, allocated, name, path, si, fn, streams}."""
    n = min(_int(lambda: vol.number_of_file_entries) or 0, max_entries)
    for i in range(first, n):
        try:
            fe = vol.get_file_entry(i)
        except Exception:
            continue
        names = file_names(fe)
        if not names:
            continue
        ref = _int(lambda: fe.file_reference) or 0
        si_raw = {'created': _int(fe.get_creation_time_as_integer), 'modified': _int(fe.get_modification_time_as_integer),
                  'changed': _int(fe.get_entry_modification_time_as_integer), 'accessed': _int(fe.get_access_time_as_integer)}
        try:
            hint = fe.get_path_hint(names[0]['attribute_index'])
        except Exception:
            hint = None
        streams = []
        for k in range(_int(lambda: fe.number_of_alternate_data_streams) or 0):
            try:
                s = fe.get_alternate_data_stream(k)
                streams.append({'name': s.name, 'size': _int(lambda: s.size), 'stream': s})
            except Exception:
                continue
        yield {'entry': i, 'sequence': ref >> 48, 'allocated': bool(_int(fe.is_allocated)), 'name': names[0]['name'],
               'path_hint': hint, 'si': {k: filetime(v) for k, v in si_raw.items()}, 'si_raw': si_raw, 'fn': names[0],
               'streams': streams, 'is_dir': bool(_int(fe.has_directory_entries_index))}


def windows_path(hint: str | None) -> str | None:
    """libfsntfs path hints are \\Users\\alice\\x; the file index uses /Users/alice/x."""
    return hint.replace('\\', '/') if hint else None


def read_stream(stream, limit: int = MAX_STREAM_READ) -> tuple[bytes, str | None]:
    """The first `limit` bytes of a stream, and the SHA-256 of all of it."""
    h, head, pos = hashlib.sha256(), b'', 0
    size = _int(lambda: stream.size) or 0
    stream.seek(0)
    while pos < size:
        data = stream.read(min(1 << 20, size - pos))
        if not data:
            break
        h.update(data)
        if len(head) < limit:
            head += data[:limit - len(head)]
        pos += len(data)
    return head, h.hexdigest()


def zone_identifier(text: str) -> dict:
    """The [ZoneTransfer] section of a Zone.Identifier stream: ZoneId (with its name), HostUrl, ReferrerUrl and the rest."""
    out = {}
    for line in text.replace('\r', '').split('\n'):
        k, sep, v = line.partition('=')
        if sep and re.fullmatch(r'[A-Za-z]{2,40}', k.strip()):
            out[k.strip()] = v.strip()
    if 'ZoneId' in out:
        try:
            out['ZoneName'] = ZONES.get(int(out['ZoneId']), f'zone {out["ZoneId"]}')
        except ValueError:
            pass
    return out


# ---------------------------------------------------------------------------- the USN change journal
def parse_usn_record(data: bytes) -> dict | None:
    """One USN_RECORD (version 2 with 64-bit file references, version 3 with 128-bit ones); None for others (version 4
    records hold changed byte ranges, without a name)."""
    if len(data) < 8:
        return None
    length, major, minor = struct.unpack_from('<IHH', data, 0)
    if major == 2 and len(data) >= 60:
        ref, parent, usn, ts, reason, source, security, attrs, nlen, noff = struct.unpack_from('<QQQQIIIIHH', data, 8)
    elif major == 3 and len(data) >= 76:
        ref = int.from_bytes(data[8:24], 'little') & 0xFFFFFFFFFFFFFFFF
        parent = int.from_bytes(data[24:40], 'little') & 0xFFFFFFFFFFFFFFFF
        usn, ts, reason, source, security, attrs, nlen, noff = struct.unpack_from('<QQIIIIHH', data, 40)
    else:
        return None
    name = data[noff:noff + nlen].decode('utf-16-le', 'replace') if noff + nlen <= len(data) else None
    return {'version': f'{major}.{minor}', 'usn': usn, 'time': filetime(ts), 'time_raw': ts, 'entry': ref & 0xFFFFFFFFFFFF,
            'sequence': ref >> 48, 'parent_entry': parent & 0xFFFFFFFFFFFF, 'parent_sequence': parent >> 48, 'reason_flags': reason,
            'reasons': reason_names(reason), 'source_info': source, 'file_attributes': attrs, 'name': name}


def usn_records(vol, max_records: int = 1_000_000):
    """The journal's records in order (libfsntfs skips its sparse, zeroed start). Yields dicts; stops at max_records."""
    try:
        journal = vol.get_usn_change_journal()
    except Exception:
        journal = None
    if journal is None:
        return
    n = 0
    while n < max_records:
        try:
            data = journal.read_usn_record()
        except Exception:
            break
        if not data:
            break
        rec = parse_usn_record(data)
        if rec:
            n += 1
            yield rec
