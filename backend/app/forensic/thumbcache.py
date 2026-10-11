"""Explorer thumbnail caches: thumbcache_<size>.db under AppData/Local/Microsoft/Windows/Explorer.

A cache file ("CMMM" header: format version, cache type, offset of the first entry) is a chain of entries, each with its
own "CMMM" header: entry size, the 64-bit cache entry hash (the thumbnail cache ID, which Windows Search keeps for
indexed files as System_ThumbnailCacheId), the identifier string, padding, and the thumbnail itself (JPEG, PNG or BMP),
with its width and height from Windows 8 on. A thumbnail stays in the cache after its file is deleted or wiped, so it
shows what a picture looked like.

Formats: the database and entry layouts documented by Thumbcache Viewer (Eric Kutcher) for Windows Vista to 11.
"""
from __future__ import annotations
import struct

VERSIONS = {0x14: 'Windows Vista', 0x15: 'Windows 7', 0x1A: 'Windows 8', 0x1C: 'Windows 8', 0x1E: 'Windows 8',
            0x1F: 'Windows 8.1', 0x20: 'Windows 10 or 11'}
MAX_ENTRIES = 50_000


def image_type(head: bytes) -> str | None:
    if head.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if head.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if head.startswith(b'BM'):
        return 'bmp'
    return None


def parse_thumbcache(path, max_entries: int = MAX_ENTRIES) -> dict:
    """{status, version, windows, cache_type, entries: [{offset, hash, identifier, width, height, data_offset, data_size,
    image_type}], errors}. The image bytes are read with read_data()."""
    out = {'status': 'COMPLETED', 'entries': [], 'errors': []}
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as exc:
        return dict(out, status='FAILED', errors=[str(exc)])
    if len(data) < 24 or data[:4] != b'CMMM':
        return dict(out, status='FAILED', errors=['not a thumbnail cache (no CMMM header)'])
    version, cache_type = struct.unpack_from('<II', data, 4)
    old = version <= 0x15  # Windows Vista and 7
    first = struct.unpack_from('<I', data, 12 if old else 16)[0]
    out.update(version=version, windows=VERSIONS.get(version, f'unknown version 0x{version:x}'), cache_type=cache_type)
    pos = first
    while pos + 48 <= len(data) and len(out['entries']) < max_entries:
        if data[pos:pos + 4] != b'CMMM':
            if any(data[pos:pos + 4]):
                out['errors'].append(f'no entry header at offset {pos}')
            break
        size, hash_ = struct.unpack_from('<IQ', data, pos + 4)
        if version == 0x14:     # Vista: an 8-byte extension field, no dimensions
            ident_size, padding, data_size = struct.unpack_from('<III', data, pos + 24)
            width = height = None
            header = 56
        elif old:               # Windows 7
            ident_size, padding, data_size = struct.unpack_from('<III', data, pos + 16)
            width = height = None
            header = 48
        else:                   # Windows 8 and later
            ident_size, padding, data_size, width, height = struct.unpack_from('<IIIII', data, pos + 16)
            header = 56
        if size < header or pos + size > len(data):
            out['errors'].append(f'entry at offset {pos} has an impossible size {size}')
            break
        ident = data[pos + header:pos + header + ident_size].decode('utf-16-le', 'replace').rstrip('\0')
        data_at = pos + header + ident_size + padding
        if data_size and data_at + data_size <= pos + size:
            out['entries'].append({'offset': pos, 'hash': f'{hash_:016x}', 'identifier': ident, 'width': width or None,
                                   'height': height or None, 'data_offset': data_at, 'data_size': data_size,
                                   'image_type': image_type(data[data_at:data_at + 8])})
        pos += size
    return out


def read_data(path, entry: dict) -> bytes:
    with open(path, 'rb') as f:
        f.seek(entry['data_offset'])
        return f.read(entry['data_size'])
