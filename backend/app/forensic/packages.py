"""Logical evidence: collected files packed as ZIP or TAR (KAPE targets, a Velociraptor offline collection, CyLR, UAC,
or any folder), unpacked once into the analysis area and read like a file system (source.DirectorySource).

Unpacking never trusts the archive: names are reduced to plain path components (a name with '..' is refused; an
absolute name is kept inside the package without its leading /), links and special files are recorded but never created, Velociraptor's URL-encoded names
(C%3A) are decoded, and the total size is bounded (and checked against free space) before anything is written.
Every file is hashed as it is written; the manifest (each member's name, where it was put, size, SHA-256 and the
times the archive kept) is stored next to it and hashed into the chain of custody. The files are left read-only.

Times: a TAR keeps UTC modification times (PAX headers can add access, change and creation times). A ZIP keeps a
local time unless an extra field gives UTC times: NTFS (0x000a: modified, accessed, created, as FILETIMEs) or
extended timestamp (0x5455). Plain ZIP times are local times of the computer that made the archive; they are kept
as recorded and flagged, and converted with the evidence's time zone when the file system index is built.

The roots of the collected file systems are then found: a folder holding Windows or Users (a Windows drive, such as
KAPE's and CyLR's `C/`, or Velociraptor's `uploads/auto/C:/`), etc with home or var (Linux), or Users with Library
(macOS). The system drive becomes volume `pkg`; further drives `pkg-d`, `pkg-e` ...
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat
import struct
import tarfile
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

EXTENSIONS = ('.zip', '.tar', '.tgz', '.tar.gz')
MAX_MEMBERS = 2_000_000
MAX_TOTAL = 256 << 30           # bytes unpacked at most
MAX_RATIO = 200                 # unpacked size / archive size above which (and 1 GiB) a ZIP is taken for a bomb
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_DRIVE = re.compile(r'^[A-Za-z]:$')


class PackageError(ValueError):
    pass


def is_package_name(name: str) -> bool:
    return name.lower().endswith(EXTENSIONS)


def archive_kind(path: Path) -> str | None:
    """ZIP, TAR or TAR.GZ from the file's own bytes; None for anything else."""
    with path.open('rb') as f:
        head = f.read(512)
    if head[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
        return 'ZIP'
    if len(head) >= 262 and head[257:262] == b'ustar':
        return 'TAR'
    if head[:2] == b'\x1f\x8b':
        try:
            with tarfile.open(path, 'r:gz') as t:
                t.next()
            return 'TAR.GZ'
        except (tarfile.TarError, OSError, EOFError):
            return None
    return None


def safe_parts(name: str, decode: bool = False) -> list[str] | None:
    """A member name as plain path components, or None when it must not be written (.., empty)."""
    parts = []
    for p in name.replace('\\', '/').split('/'):
        if decode:
            p = urllib.parse.unquote(p)
        if p in ('', '.'):
            continue
        if p == '..' or '/' in p or '\0' in p or len(p.encode()) > 255:
            return None
        parts.append(p)
    return parts or None


def _filetime(v: int) -> datetime | None:
    return EPOCH_1601 + timedelta(microseconds=v // 10) if v else None


def _zip_extra_times(extra: bytes) -> dict:
    """UTC times from a ZIP extra field: NTFS (0x000a) or extended timestamp (0x5455, modification time only in the
    central directory)."""
    out, i = {}, 0
    while i + 4 <= len(extra):
        tag, size = struct.unpack('<HH', extra[i:i + 4])
        body = extra[i + 4:i + 4 + size]
        if tag == 0x000A and len(body) >= 32:
            j = 4
            while j + 4 <= len(body):
                t, n = struct.unpack('<HH', body[j:j + 4])
                if t == 1 and n >= 24:
                    m, a, c = struct.unpack('<QQQ', body[j + 4:j + 28])
                    out.update(mtime=_filetime(m), atime=_filetime(a), crtime=_filetime(c))
                j += 4 + n
        elif tag == 0x5455 and len(body) >= 5 and body[0] & 1 and 'mtime' not in out:
            out['mtime'] = datetime.fromtimestamp(struct.unpack('<i', body[1:5])[0], timezone.utc)
        i += 4 + size
    return out


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def unpack(archive: Path, dest: Path, kind: str, ensure_space=None, cancelled=None, manifest_path: Path | None = None) -> dict:
    """Unpacks into dest (which must not exist) and writes dest.with_suffix('.manifest.jsonl'). Returns a summary."""
    dest.mkdir(parents=True)
    manifest = manifest_path or dest.parent / f'{dest.name}.manifest.jsonl'
    counts = {'files': 0, 'folders': 0, 'links': 0, 'skipped': 0, 'bytes': 0}
    zip_local_times = False
    with manifest.open('w', encoding='utf-8') as out:
        def record(doc):
            out.write(json.dumps({k: _iso(v) for k, v in doc.items() if v is not None}) + '\n')

        def write(parts, reader, size, times):
            target = dest.joinpath(*parts)
            if target.exists():  # a second member of the same name, or a folder of that name
                counts['skipped'] += 1
                return None
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
            except (FileExistsError, NotADirectoryError):  # a file is in the way of the folder
                counts['skipped'] += 1
                return None
            h = hashlib.sha256()
            n = 0
            with target.open('wb') as f:
                while chunk := reader.read(1 << 20):
                    n += len(chunk)
                    if counts['bytes'] + n > MAX_TOTAL:
                        raise PackageError(f'The package unpacks to more than {MAX_TOTAL >> 30} GiB; it was not unpacked')
                    h.update(chunk)
                    f.write(chunk)
            counts['bytes'] += n
            counts['files'] += 1
            m = times.get('mtime')
            if isinstance(m, datetime):
                a = times.get('atime') or m
                os.utime(target, (a.timestamp(), m.timestamp()))
            target.chmod(0o444)
            if cancelled and counts['files'] % 500 == 0 and cancelled():
                raise InterruptedError('Cancelled')
            return {'size': n, 'sha256': h.hexdigest()}

        if kind == 'ZIP':
            with zipfile.ZipFile(archive) as z:
                infos = z.infolist()
                if len(infos) > MAX_MEMBERS:
                    raise PackageError(f'The package has {len(infos):,} members; at most {MAX_MEMBERS:,} are unpacked')
                total = sum(i.file_size for i in infos)
                if total > MAX_TOTAL or (total > 1 << 30 and total > MAX_RATIO * max(1, archive.stat().st_size)):
                    raise PackageError(f'The package declares {total:,} bytes unpacked from a {archive.stat().st_size:,}-byte archive: '
                                       'refused as a possible archive bomb')
                if ensure_space:
                    ensure_space(total)
                velociraptor = any(i.filename.startswith('uploads/') and '%' in i.filename for i in infos[:5000])
                for info in infos:
                    parts = safe_parts(info.filename, decode=velociraptor)
                    mode = (info.external_attr >> 16) & 0xFFFF
                    doc = {'name': info.filename, 'path': '/'.join(parts) if parts else None}
                    if not parts:
                        counts['skipped'] += 1
                        record(dict(doc, kind='skipped', reason='unsafe name'))
                        continue
                    if info.is_dir():
                        dest.joinpath(*parts).mkdir(parents=True, exist_ok=True)
                        counts['folders'] += 1
                        continue
                    if stat.S_ISLNK(mode):
                        counts['links'] += 1
                        record(dict(doc, kind='link', link_target=z.read(info).decode('utf-8', errors='replace')[:4096]))
                        continue
                    times = _zip_extra_times(info.extra)
                    if 'mtime' not in times:
                        times = {'mtime_local': datetime(*info.date_time).isoformat()}
                        zip_local_times = True
                    if info.flag_bits & 0x1:
                        counts['skipped'] += 1
                        record(dict(doc, kind='skipped', reason='encrypted member'))
                        continue
                    with z.open(info) as src:
                        r = write(parts, src, info.file_size, times)
                    record(dict(doc, kind='file', **times, **r) if r else dict(doc, kind='skipped', reason='name already used'))
        else:
            with tarfile.open(archive, 'r:gz' if kind == 'TAR.GZ' else 'r:') as t:
                n = 0
                for m in t:
                    n += 1
                    if n > MAX_MEMBERS:
                        raise PackageError(f'The package has more than {MAX_MEMBERS:,} members')
                    parts = safe_parts(m.name)
                    doc = {'name': m.name, 'path': '/'.join(parts) if parts else None}
                    if not parts:
                        counts['skipped'] += 1
                        record(dict(doc, kind='skipped', reason='unsafe name'))
                        continue
                    if m.isdir():
                        dest.joinpath(*parts).mkdir(parents=True, exist_ok=True)
                        counts['folders'] += 1
                        continue
                    if m.issym() or m.islnk():
                        counts['links'] += 1
                        record(dict(doc, kind='link', link_target=m.linkname[:4096]))
                        continue
                    if not m.isfile():
                        counts['skipped'] += 1
                        record(dict(doc, kind='skipped', reason='special file'))
                        continue
                    if ensure_space and (m.size > 64 << 20 or n % 1000 == 1):
                        ensure_space(m.size)
                    pax = m.pax_headers or {}
                    ts = lambda k: datetime.fromtimestamp(float(pax[k]), timezone.utc) if pax.get(k) else None
                    times = {'mtime': datetime.fromtimestamp(m.mtime, timezone.utc), 'atime': ts('atime'), 'ctime': ts('ctime'),
                             'crtime': ts('LIBARCHIVE.creationtime')}
                    src = t.extractfile(m)
                    r = write(parts, src, m.size, times)
                    record(dict(doc, kind='file', **times, **r) if r else dict(doc, kind='skipped', reason='name already used'))
    h = hashlib.sha256()
    with manifest.open('rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return dict(counts, manifest=str(manifest), manifest_sha256=h.hexdigest(), zip_local_times=zip_local_times, roots=find_roots(dest))


def remove_tree(path: Path):
    """Deletes a folder of unpacked files, clearing the read-only flag where the storage needs it (Windows-backed volumes)."""
    import shutil

    def again(func, p, _exc):
        os.chmod(p, 0o700 if os.path.isdir(p) else 0o600)
        func(p)
    shutil.rmtree(path, onerror=again)


def _children(p: Path) -> dict[str, Path]:
    try:
        return {c.name.lower(): c for c in p.iterdir() if c.is_dir() and not c.is_symlink()}
    except OSError:
        return {}


def _os_of(p: Path) -> str | None:
    kids = _children(p)
    # Phones (full file system extractions): Android's /data/data next to /data/system or /system, iOS's /private/var/mobile.
    if 'data' in kids:
        data = _children(kids['data'])
        if 'data' in data and ({'system', 'app', 'misc'} & set(data) or 'system' in kids):
            return 'android'
    if 'private' in kids:
        var = _children(kids['private']).get('var')
        if var is not None and 'mobile' in _children(var):
            return 'ios'
    if 'users' in kids and ({'library', 'applications', 'private', 'system'} & set(kids)):
        return 'macos'
    if 'windows' in kids or ('users' in kids and ({'programdata', 'program files', '$recycle.bin', 'program files (x86)'} & set(kids))):
        return 'windows'
    if 'etc' in kids and ({'home', 'var', 'root', 'usr'} & set(kids)):
        return 'linux'
    if 'users' in kids:
        return 'windows'
    return None


def find_roots(dest: Path, max_depth: int = 5) -> list[dict]:
    """The file system roots in an unpacked package: [{'volume_id', 'path' (relative), 'os', 'label'}], system drive first."""
    found, frontier = [], [(dest, 0)]
    while frontier:
        p, depth = frontier.pop(0)
        os_name = _os_of(p)
        if os_name:
            rel = p.relative_to(dest).as_posix()
            found.append({'path': '' if rel == '.' else rel, 'os': os_name, 'label': p.name if _DRIVE.match(p.name) or len(p.name) == 1 else None})
            continue
        if depth < max_depth:
            frontier += [(c, depth + 1) for c in sorted(_children(p).values())]
    if not found:
        return [{'volume_id': 'pkg', 'path': '', 'os': None, 'label': None}]
    # The system drive first: the one holding Windows (or the first found).
    found.sort(key=lambda r: ('windows' not in _children(dest / r['path']), r['path']))
    for i, r in enumerate(found):
        letter = (r['label'] or '').rstrip(':').lower()
        r['volume_id'] = 'pkg' if i == 0 else f'pkg-{letter}' if letter and len(letter) == 1 else f'pkg-{i + 1}'
    return found


def read_manifest(path: Path) -> dict[str, dict]:
    """The manifest's files by their unpacked path."""
    out = {}
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            d = json.loads(line)
            if d.get('kind') == 'file' and d.get('path'):
                out[d['path']] = d
    return out
