"""Volume Shadow Copies: Windows' snapshots of an NTFS volume, read in-process with libvshadow.

Each snapshot is opened as a file system of its own (volume id `p<start>/vss<n>`, n counting from the oldest) and
compared with the volume as it is now, by path (NTFS names ignore case):
- DELETED_SINCE: there in the snapshot, gone now (the snapshot still holds the old content);
- CHANGED_SINCE: there in both, with a different size or modification time (the snapshot holds the old version);
- ADDED_SINCE: there now, not in the snapshot.
NTFS's own metadata files ($MFT, $LogFile ... $Extend), Sleuth Kit's virtual entries, alternate data streams and the
shadow copy files themselves (System Volume Information) are left out: they change with every snapshot.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .source import OffsetFile, SECTOR

NTFS_METADATA = {'$mft', '$mftmirr', '$logfile', '$volume', '$attrdef', '$bitmap', '$boot', '$badclus', '$secure', '$upcase',
                 '$extend', '$orphanfiles', '$quota', '$objid', '$reparse', '$txf_data', '$tops'}
CHANGES = ('DELETED_SINCE', 'CHANGED_SINCE', 'ADDED_SINCE')


def stores(image: Path, start_sector: int) -> list[dict]:
    """The volume's shadow copies, oldest first: number (1-based), identifiers, creation time (UTC), volume size.
    An empty list when the volume has none (or is not NTFS)."""
    import pyvshadow
    window = OffsetFile(image, start_sector * SECTOR)
    try:
        if not pyvshadow.check_volume_signature_file_object(window):
            return []
        vss = pyvshadow.volume()
        vss.open_file_object(window)
        out = []
        for i in range(vss.number_of_stores):
            s = vss.get_store(i)
            created = s.creation_time
            out.append({'store': i + 1, 'identifier': str(s.identifier), 'copy_identifier': str(s.copy_identifier),
                        'copy_set_identifier': str(s.copy_set_identifier),
                        'created': created.replace(tzinfo=timezone.utc) if created and created.tzinfo is None else created,
                        'volume_size': int(s.volume_size)})
        vss.close()
        return out
    finally:
        window.close()


def skipped(path: str) -> bool:
    parts = path.strip('/').split('/')
    first = parts[0].lower() if parts else ''
    return (first in NTFS_METADATA or first == 'system volume information'
            or ':' in parts[-1])  # an alternate data stream listed by fls ("file.txt:Zone.Identifier")


def _epoch(v) -> int | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return int((v if v.tzinfo else v.replace(tzinfo=timezone.utc)).timestamp())
    return int(v) or None


def compare(snapshot: Iterable[dict], current: dict[str, dict]) -> Iterator[tuple[str, dict | None, dict | None]]:
    """(change, snapshot entry, current entry) for every difference. `snapshot`: walk(times=True) entries of the shadow
    copy; `current`: the volume's allocated file-index entries now, keyed by lower-case path."""
    seen = set()
    for s in snapshot:
        if s.get('deleted') or s.get('is_virtual') or skipped(s['path']):
            continue
        key = s['path'].lower()
        seen.add(key)
        now = current.get(key)
        if now is None:
            yield 'DELETED_SINCE', s, None
        elif not s['is_dir'] and not now.get('is_dir') and (
                (s.get('size') or 0) != (now.get('size') or 0) or _epoch(s.get('mtime')) != _epoch(now.get('mtime'))):
            yield 'CHANGED_SINCE', s, now
    for key, now in current.items():
        if key not in seen and not skipped(now['path']):
            yield 'ADDED_SINCE', None, now


def to_datetime(v) -> datetime | None:
    t = _epoch(v)
    return datetime.fromtimestamp(t, timezone.utc) if t else None
