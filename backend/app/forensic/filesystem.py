"""Filesystem listing via Sleuth Kit `fls -r -m` (bodyfile format).

The bodyfile is written to DFIP's analysis directory and kept, so investigators
can independently re-run `mactime -b <bodyfile>` or load it into other tools
to cross-check DFIP's timeline.

Bodyfile (TSK 3.x+) columns:
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
Times are Unix epoch seconds; 0 means "not recorded by this filesystem".
"""
from __future__ import annotations
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .tools import TOOLS

_DELETED_SUFFIX = re.compile(r' \((deleted|deleted-realloc|realloc)\)$')
# icat address forms: "123" (FAT/ext) or "64-128-2" (NTFS type/id)
INODE_RE = re.compile(r'^\d+(-\d+(-\d+)?)?$')


def _ts(value: str):
    try:
        n = int(value)
    except ValueError:
        return None
    if n <= 0:
        return None
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def parse_bodyfile_line(line: str) -> dict | None:
    """Parses one bodyfile line into a filesystem entry, or None if malformed.

    The name field can itself contain '|', so the fixed columns are taken from
    both ends and everything in between is the name.
    """
    parts = line.rstrip('\r\n').split('|')
    if len(parts) < 11:
        return None
    inode, mode, uid, gid, size, atime, mtime, ctime, crtime = parts[-9:]
    name = '|'.join(parts[1:-9])
    if not name:
        return None
    status = None
    m = _DELETED_SUFFIX.search(name)
    if m:
        status = m.group(1)
        name = name[:m.start()]
    try:
        size_n = int(size)
    except ValueError:
        size_n = None
    return {
        'path': name,
        'name': name.rsplit('/', 1)[-1],
        'inode': inode,
        'mode': mode,
        'is_dir': mode.startswith('d'),
        # Sleuth Kit virtual entries ($MBR, $FAT1, $OrphanFiles ...) have mode v/v or V/V.
        'is_virtual': mode[:1] in ('v', 'V'),
        'deleted': status is not None,
        'deleted_status': status,  # 'deleted' | 'deleted-realloc' | 'realloc'
        'size': size_n,
        'uid': uid,
        'gid': gid,
        'atime': _ts(atime),
        'mtime': _ts(mtime),
        'ctime': _ts(ctime),
        'crtime': _ts(crtime),
    }


def write_bodyfile(image: Path, offset: int, destination: Path, timeout: int = 3600) -> dict:
    """Runs `fls -r -m / [-o offset] image` streaming stdout to `destination`."""
    binary = shutil.which(TOOLS['sleuthkit_fls'])
    if not binary:
        return {'status': 'TOOL_UNAVAILABLE', 'tool': 'fls'}
    destination.parent.mkdir(parents=True, exist_ok=True)
    args = [binary, '-r', '-m', '/']
    if offset:
        args += ['-o', str(offset)]
    args.append(str(image))
    try:
        with destination.open('wb') as out:
            proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'tool': 'fls', 'offset': offset}
    return {'status': 'COMPLETED' if proc.returncode == 0 else 'FAILED', 'tool': 'fls', 'offset': offset,
            'returncode': proc.returncode, 'bodyfile': str(destination),
            'stderr': (proc.stderr or b'').decode(errors='replace')[-5000:]}


def iter_bodyfile(path: Path) -> Iterator[dict]:
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            entry = parse_bodyfile_line(line)
            if entry:
                yield entry
