"""Jump Lists: the recent and pinned items Windows keeps per application.

AutomaticDestinations (`<AppID>.automaticDestinations-ms`) are OLE compound files: one stream per item holding a shell
link (named by the item's entry number in hexadecimal) and a `DestList` stream that lists the items with when each was
last used, whether it is pinned, how often it was used (Windows 10) and the computer and NTFS object identifiers of the
target (distributed link tracking). CustomDestinations (`<AppID>.customDestinations-ms`) are written by the application
itself: categories (named ones, the known Frequent and Recent lists, and Tasks) of shell links.

The AppID is a hash of the application's path or AppUserModelID; well-known ones are named below.

Formats: libyal/dtformats "Jump lists format", checked against the version 1 and 3 samples of Plaso's test data.
"""
from __future__ import annotations
import io
import struct
import uuid
from datetime import datetime, timedelta, timezone

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
LNK_HEADER = b'\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
LNK_CLSID = uuid.UUID('00021401-0000-0000-c000-000000000046').bytes_le
CUSTOM_FOOTER = 0xBABFFBAB
MAX_ENTRIES = 5000

# Well-known AppIDs (published lists of Jump List application identifiers). Unknown ones are shown by their AppID.
APP_IDS = {
    '1b4dd67f29cb1962': 'Windows Explorer (Windows 7)',
    'f01b4d95cf55d32a': 'Windows Explorer',
    '5f7b5f1e01b83767': 'Windows Explorer (Quick Access)',
    '9b9cdc69c1c24e2b': 'Notepad (64-bit)',
    '918e0ecb43d17e23': 'Notepad (32-bit)',
    '12dc1ea8e34b5a6': 'Microsoft Paint',
    '7e4dca80246863e3': 'Control Panel',
    '1bc392b8e104a00e': 'Remote Desktop Connection',
    '5d696d521de238c3': 'Google Chrome',
    '6824f4a902c78fbd': 'Mozilla Firefox',
    '9839aec31243a928': 'Microsoft Excel 2010',
    'a7bd71699cd38d1c': 'Microsoft Word 2010',
    'd00655d2aa12ff6d': 'Microsoft PowerPoint 2010',
    '9fda41b86ddcf1db': 'VLC media player',
    '290532160612e071': 'WinRAR',
    '23646679aaccfae0': 'Adobe Reader',
}


def app_name(app_id: str) -> str | None:
    return APP_IDS.get((app_id or '').lower())


def filetime(n: int) -> datetime | None:
    if not n or n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


def _guid(b: bytes) -> str | None:
    return None if not b.strip(b'\0') else str(uuid.UUID(bytes_le=b))


def _mac(droid_file: bytes) -> str | None:
    """The MAC address in a version 1 UUID (droid file identifiers are time-based UUIDs made on the target's computer)."""
    if not droid_file.strip(b'\0'):
        return None
    u = uuid.UUID(bytes_le=droid_file)
    return ':'.join(f'{(u.node >> (8 * i)) & 0xFF:02x}' for i in range(5, -1, -1)) if u.version == 1 else None


def lnk_size(data: bytes, start: int = 0) -> int | None:
    """The length of the shell link at `start` ([MS-SHLLINK]: header, ID list, LinkInfo, strings, extra blocks)."""
    try:
        if data[start:start + 20] != LNK_HEADER:
            return None
        flags = struct.unpack_from('<I', data, start + 0x14)[0]
        pos = start + 0x4C
        if flags & 0x01:  # HasLinkTargetIDList
            pos += 2 + struct.unpack_from('<H', data, pos)[0]
        if flags & 0x02:  # HasLinkInfo
            pos += struct.unpack_from('<I', data, pos)[0]
        unicode = bool(flags & 0x80)
        for bit in (0x04, 0x08, 0x10, 0x20, 0x40):  # name, relative path, working directory, arguments, icon location
            if flags & bit:
                pos += 2 + struct.unpack_from('<H', data, pos)[0] * (2 if unicode else 1)
        while True:  # extra data blocks, ended by a block size below 4
            size = struct.unpack_from('<I', data, pos)[0]
            if size < 4:
                return pos + 4 - start
            pos += size
            if pos > len(data):
                return None
    except struct.error:
        return None


def parse_lnk_bytes(data: bytes) -> dict:
    """A shell link held in memory, with the same fields as windows_activity.parse_lnk."""
    from .windows_activity import parse_lnk
    return parse_lnk(io.BytesIO(data))


# ---------------------------------------------------------------------------- AutomaticDestinations
def _destlist(data: bytes) -> tuple[dict, list[dict]]:
    version, count, pinned = struct.unpack_from('<III', data, 0)
    header = {'version': version, 'entries': count, 'pinned': pinned, 'last_entry_number': struct.unpack_from('<Q', data, 16)[0]}
    entries, pos = [], 32
    v1 = version == 1
    while pos + (114 if v1 else 130) <= len(data) and len(entries) < min(count, MAX_ENTRIES):
        e = data[pos:]
        number = struct.unpack_from('<I', e, 88)[0]
        counter = struct.unpack_from('<f', e, 96)[0]
        modified = struct.unpack_from('<Q', e, 100)[0]
        pin = struct.unpack_from('<i', e, 108)[0]
        if v1:
            length, path_at, access_count = struct.unpack_from('<H', e, 112)[0], 114, None
        else:
            access_count = struct.unpack_from('<I', e, 116)[0]
            length, path_at = struct.unpack_from('<H', e, 128)[0], 130
        path = e[path_at:path_at + 2 * length].decode('utf-16-le', 'replace')
        entries.append({
            'offset': pos, 'entry_number': number, 'path': path, 'last_used': filetime(modified), 'pinned': pin != -1,
            'pin_position': pin if pin != -1 else None, 'access_count': access_count, 'counter': round(counter, 3),
            'hostname': e[72:88].split(b'\0', 1)[0].decode('ascii', 'replace') or None,
            'droid_volume_id': _guid(e[8:24]), 'droid_file_id': _guid(e[24:40]),
            'birth_droid_volume_id': _guid(e[40:56]), 'birth_droid_file_id': _guid(e[56:72]), 'mac_address': _mac(e[24:40]),
        })
        pos += path_at + 2 * length + (0 if v1 else 4)
    return header, entries


def parse_automatic(path) -> dict:
    """{status, app_id, version, entries: [{entry_number, path, last_used, pinned, access_count, hostname, droid ids,
    lnk: {...}}], errors}. Streams without a DestList entry are listed too."""
    import olefile
    out = {'status': 'COMPLETED', 'entries': [], 'errors': [], 'version': None}
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as exc:
        return dict(out, status='FAILED', errors=[f'not a compound file: {exc}'])
    try:
        streams = {'/'.join(s): s for s in ole.listdir(streams=True, storages=False)}
        entries = []
        if 'DestList' in streams:
            try:
                header, entries = _destlist(ole.openstream('DestList').read())
                out['version'] = header['version']
                out['pinned'] = header['pinned']
            except struct.error as exc:
                out['errors'].append(f'DestList is damaged: {exc}')
        else:
            out['errors'].append('no DestList stream')
        listed = set()
        for e in entries:
            name = format(e['entry_number'], 'x')
            listed.add(name)
            e['lnk'] = _stream_lnk(ole, streams, name, out)
        for name in sorted(n for n in streams if n != 'DestList' and n not in listed):
            entries.append({'entry_number': int(name, 16) if all(c in '0123456789abcdef' for c in name.lower()) else None,
                            'path': None, 'last_used': None, 'pinned': False, 'lnk': _stream_lnk(ole, streams, name, out),
                            'note': 'stream without a DestList entry'})
        out['entries'] = entries
        return out
    finally:
        ole.close()


def _stream_lnk(ole, streams, name, out):
    if name not in streams:
        return None
    data = ole.openstream(streams[name]).read()
    lnk = parse_lnk_bytes(data)
    if lnk.get('status') != 'COMPLETED':
        out['errors'].append(f'stream {name}: {lnk.get("error")}')
        return None
    return {k: v for k, v in lnk.items() if k != 'status'}


# ---------------------------------------------------------------------------- CustomDestinations
CATEGORY_KNOWN = {1: 'Frequent', 2: 'Recent'}


def parse_custom(path) -> dict:
    """{status, categories: [{name, kind}], entries: [{category, kind, lnk: {...}}], errors}."""
    out = {'status': 'COMPLETED', 'categories': [], 'entries': [], 'errors': []}
    try:
        data = open(path, 'rb').read()
    except OSError as exc:
        return dict(out, status='FAILED', errors=[str(exc)])
    if len(data) < 12:
        return out
    version, count = struct.unpack_from('<II', data, 0)
    out['version'] = version
    pos = 12
    try:
        for _ in range(min(count, 100)):
            kind = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            if kind == 0:
                n = struct.unpack_from('<H', data, pos)[0]
                name = data[pos + 2:pos + 2 + 2 * n].decode('utf-16-le', 'replace')
                pos += 2 + 2 * n
                items = struct.unpack_from('<I', data, pos)[0]
                pos += 4
                label = 'custom'
            elif kind == 1:  # Windows fills the Frequent and Recent lists from the AutomaticDestinations file
                known = struct.unpack_from('<I', data, pos)[0]
                pos += 4
                out['categories'].append({'name': CATEGORY_KNOWN.get(known, f'known list {known}'), 'kind': 'known'})
                if pos + 4 <= len(data) and struct.unpack_from('<I', data, pos)[0] == CUSTOM_FOOTER:
                    pos += 4
                continue
            elif kind == 2:
                name, label = 'Tasks', 'tasks'
                items = struct.unpack_from('<I', data, pos)[0]
                pos += 4
            else:
                out['errors'].append(f'unknown category type {kind} at offset {pos - 4}')
                return _scan(data, out)
            out['categories'].append({'name': name, 'kind': label})
            for _ in range(min(items, MAX_ENTRIES)):
                if data[pos:pos + 16] == LNK_CLSID:
                    pos += 16
                size = lnk_size(data, pos)
                if size is None:
                    out['errors'].append(f'no shell link at offset {pos}')
                    return _scan(data, out)
                lnk = parse_lnk_bytes(data[pos:pos + size])
                out['entries'].append({'category': name, 'kind': label, 'offset': pos,
                                       'lnk': {k: v for k, v in lnk.items() if k != 'status'} if lnk.get('status') == 'COMPLETED' else None})
                pos += size
            if pos + 4 <= len(data) and struct.unpack_from('<I', data, pos)[0] == CUSTOM_FOOTER:
                pos += 4
    except struct.error as exc:
        out['errors'].append(f'damaged at offset {pos}: {exc}')
        return _scan(data, out)
    return out


def _scan(data: bytes, out: dict) -> dict:
    """A damaged file: every shell link that can still be found by its header, after those already read."""
    seen = {e['offset'] for e in out['entries']}
    pos = data.find(LNK_HEADER)
    while pos != -1 and len(out['entries']) < MAX_ENTRIES:
        size = lnk_size(data, pos)
        if size and pos not in seen:
            lnk = parse_lnk_bytes(data[pos:pos + size])
            if lnk.get('status') == 'COMPLETED':
                out['entries'].append({'category': None, 'kind': 'recovered', 'offset': pos, 'lnk': {k: v for k, v in lnk.items() if k != 'status'}})
        pos = data.find(LNK_HEADER, pos + 1)
    return out
