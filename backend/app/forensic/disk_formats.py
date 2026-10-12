"""Disk image formats and image sets: what an upload is, whether it is complete, and how its media is read.

One evidence item is one disk, which may arrive as several files:
- EnCase segments (`<name>.E01`, `.E02` ... `.E99`, `.EAA` ...; `.Ex01`, `.Ex02` ...), read by libewf from the first;
- a raw image split into numbered parts (`<name>.000` or `<name>.001`, then `.002` ...), read one after the other;
- a virtual disk (VHD, VHDX, VMDK, QCOW2) with the disks it builds on: the parent of a differencing VHD or VHDX
  (matched by its identifier), the parent of a VMDK snapshot (by content identifier), a QCOW2 backing file (by
  name), and the extent files a VMDK descriptor names.
A set is checked when it is uploaded: a missing segment or parent is refused with what is missing. Virtual disks
are read with libyal (libvhdi, libvmdk, libqcow); the result is the disk's media, written once to a raw working
copy that every tool reads (see working_image.py).
"""
from __future__ import annotations
import hashlib
import re
import shutil
from pathlib import Path

VIRTUAL = ('VHD', 'VHDX', 'VMDK', 'QCOW2')
EWF = ('E01', 'EX01')
RAW = 'RAW'
LABELS = {'E01': 'EnCase (E01)', 'EX01': 'EnCase (Ex01)', 'RAW': 'Raw (dd)', 'AFF': 'Advanced Forensic Format', 'AFF4': 'AFF4',
          'VHD': 'Virtual Hard Disk (VHD)', 'VHDX': 'Virtual Hard Disk v2 (VHDX)', 'VMDK': 'VMware disk (VMDK)', 'QCOW2': 'QEMU disk (QCOW2)'}
# File name extensions accepted for upload (numbered parts of a split raw image are accepted too).
EXTENSIONS = ('E01', 'EX01', 'RAW', 'DD', 'IMG', 'AFF', 'AFF4', 'VHD', 'VHDX', 'VMDK', 'QCOW2', 'QCOW')
_SPLIT = re.compile(r'^(?P<base>.+)\.(?P<n>\d{3,4})$')
_EWF = re.compile(r'^(?P<base>.+)\.(?P<seg>E(?:X)?(?:\d\d|[A-Z][A-Z]))$', re.I)
CHUNK = 4 << 20


class SetError(ValueError):
    """The files uploaded together are not one complete disk image."""


def extension_ok(name: str) -> bool:
    ext = Path(name).suffix.lstrip('.').upper()
    return ext in EXTENSIONS or bool(_SPLIT.match(name)) or bool(_EWF.match(name))


def detect(path: Path) -> str:
    """The format from the file's own bytes (never its name): E01, EX01, VHD, VHDX, VMDK, QCOW2, or RAW."""
    size = path.stat().st_size
    with path.open('rb') as f:
        head = f.read(512)
        tail = b''
        if size >= 512:
            f.seek(size - 512)
            tail = f.read(512)
    if head.startswith(b'EVF\x09\x0d\x0a\xff\x00'):
        return 'E01'
    if head.startswith(b'EVF2\x0d\x0a\x81\x00'):
        return 'EX01'
    if head.startswith(b'vhdxfile'):
        return 'VHDX'
    if head.startswith(b'conectix') or tail.startswith(b'conectix'):
        return 'VHD'
    if head.startswith(b'KDMV') or head.startswith(b'COWD') or head.lstrip().startswith(b'# Disk DescriptorFile'):
        return 'VMDK'
    if head.startswith(b'QFI\xfb'):
        return 'QCOW2'
    if path.suffix.upper() in ('.AFF', '.AFF4'):
        return path.suffix.upper().lstrip('.')
    return RAW


def ewf_segment(path: Path) -> tuple[int, str | None]:
    """(segment number from the header, 'next' or 'done') of an EWF (E01) segment file: every segment but the last
    ends with a 'next' section, the last with 'done'. (None for the ending when the sections can't be followed.)"""
    with path.open('rb') as f:
        head = f.read(13)
        number = int.from_bytes(head[9:11], 'little')
        off, size = 13, path.stat().st_size
        for _ in range(1_000_000):
            f.seek(off)
            desc = f.read(76)
            if len(desc) < 76:
                return number, None
            kind = desc[:16].rstrip(b'\0').decode('ascii', errors='replace')
            if kind in ('next', 'done'):
                return number, kind
            nxt = int.from_bytes(desc[16:24], 'little')
            if nxt <= off or nxt >= size:
                return number, None
            off = nxt
    return number, None


def ewf_index(ext: str) -> int | None:
    """The segment number of an EWF extension: E01 -> 1 ... E99 -> 99, EAA -> 100 ...; Ex01 -> 1."""
    e = ext.upper().lstrip('.')
    m = re.fullmatch(r'EX?(\d\d)', e)
    if m:
        return int(m.group(1)) or None
    m = re.fullmatch(r'E([A-Z])([A-Z])', e)
    if m:
        return 100 + (ord(m.group(1)) - 65) * 26 + (ord(m.group(2)) - 65)
    return None


# -------------------------------------------------------------------------------------- virtual disk chains
def _open_virtual(fmt: str, path: Path):
    if fmt in ('VHD', 'VHDX'):
        import pyvhdi
        f = pyvhdi.file()
        f.open(str(path))
        return f
    if fmt == 'VMDK':
        import pyvmdk
        f = pyvmdk.handle()
        f.open(str(path))
        return f
    if fmt == 'QCOW2':
        import pyqcow
        f = pyqcow.file()
        f.open(str(path))
        return f
    raise SetError(f'{path.name}: not a virtual disk')


def _vmdk_extents(handle) -> list[str]:
    names = []
    for d in handle.extent_descriptors:
        name = getattr(d, 'filename', None)
        if name:
            names.append(Path(name.replace('\\', '/')).name)
    return names


def _needs(fmt: str, handle) -> dict:
    """What a virtual disk needs besides itself: {'parent': (kind, value, shown), 'extents': [names]}."""
    out = {'parent': None, 'extents': []}
    if fmt in ('VHD', 'VHDX'):
        pid = handle.parent_identifier
        if pid:
            out['parent'] = ('identifier', str(pid).lower(), (handle.parent_filename or '').replace('\\', '/').rsplit('/', 1)[-1] or str(pid))
    elif fmt == 'VMDK':
        pcid = handle.parent_content_identifier
        if pcid not in (None, 0xFFFFFFFF) and handle.parent_filename:
            out['parent'] = ('content_identifier', int(pcid), handle.parent_filename.replace('\\', '/').rsplit('/', 1)[-1])
        out['extents'] = _vmdk_extents(handle)
    elif fmt == 'QCOW2':
        backing = handle.backing_filename
        if backing:
            name = backing.replace('\\', '/').rsplit('/', 1)[-1]
            out['parent'] = ('name', name.lower(), name)
    return out


def _identity(fmt: str, handle, path: Path) -> dict:
    ids = {'name': path.name.lower()}
    if fmt in ('VHD', 'VHDX'):
        ids['identifier'] = str(handle.identifier).lower()
    elif fmt == 'VMDK':
        ids['content_identifier'] = int(handle.content_identifier)
    return ids


def classify(paths: list[Path]) -> dict:
    """Checks the files of one upload and returns {format, kind, order, roles}: `order` is the primary file first,
    then the rest in reading order (segments) or from child to parent (virtual disks); SetError says what is wrong."""
    if not paths:
        raise SetError('No file was uploaded')
    names = [p.name for p in paths]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise SetError(f'The same file name was uploaded twice: {", ".join(sorted(dup))}')
    formats = {p: detect(p) for p in paths}
    if len(paths) == 1:
        p = paths[0]
        fmt = formats[p]
        if fmt in VIRTUAL:
            _check_virtual(fmt, p, [])
        if fmt == 'E01':
            number, ending = ewf_segment(p)
            if number != 1 or ending == 'next':
                raise SetError(f'{p.name} is segment {number} of an EnCase image with more segments. '
                               'Upload every segment (.E01, .E02, ...) together.')
        m = _SPLIT.match(p.name)
        if fmt == RAW and m and int(m.group('n')) > 1:
            raise SetError(f'{p.name} looks like part {int(m.group("n"))} of a split image. Upload every part together.')
        return {'format': fmt, 'kind': 'single', 'order': [p], 'roles': {p.name: 'image'}}

    kinds = set(formats.values())
    if kinds <= set(EWF):
        return _ewf_set(paths, formats)
    if kinds == {RAW} and all(_SPLIT.match(p.name) for p in paths):
        return _split_set(paths)
    if kinds & set(VIRTUAL) and kinds <= set(VIRTUAL) | {RAW}:
        return _virtual_set(paths, formats)
    if kinds == {RAW}:
        raise SetError('Several raw files were uploaded, but they are not numbered parts of one image (name.001, name.002, ...). '
                       'Upload each disk image on its own.')
    raise SetError('These files are not one disk image: ' + ', '.join(f'{p.name} ({formats[p]})' for p in paths)
                   + '. Upload EnCase segments, the numbered parts of a split raw image, or a virtual disk with its parents together.')


def _ewf_set(paths, formats):
    parsed = {}
    for p in paths:
        m = _EWF.match(p.name)
        idx = ewf_index(m.group('seg')) if m else None
        if not m or idx is None:
            raise SetError(f'{p.name} is an EnCase segment, but its name does not end in a segment number (.E01, .E02, ...)')
        parsed[p] = (m.group('base'), idx)
    bases = {b.lower() for b, _ in parsed.values()}
    if len(bases) > 1:
        raise SetError(f'The EnCase segments belong to different images: {", ".join(sorted(bases))}')
    order = sorted(paths, key=lambda p: parsed[p][1])
    have = [parsed[p][1] for p in order]
    want = list(range(1, len(order) + 1))
    if have != want:
        missing = sorted(set(range(1, max(have) + 1)) - set(have))
        raise SetError(f'EnCase segments are missing: {", ".join(_ewf_ext(n, order[0]) for n in missing) or "the first segment (.E01)"}. '
                       'Upload every segment of the image together.')
    if len({formats[p] for p in order}) > 1:
        raise SetError('E01 and Ex01 segments cannot be mixed')
    if formats[order[0]] == 'E01':
        for i, p in enumerate(order, 1):
            number, ending = ewf_segment(p)
            if number != i:
                raise SetError(f'{p.name} says it is segment {number}, but its name makes it segment {i}: the segments were renamed '
                               'or come from different images.')
            if i == len(order) and ending == 'next':
                raise SetError(f'{p.name} is not the last segment of the image: more segments follow it. Upload every segment together.')
    return {'format': formats[order[0]], 'kind': 'segments', 'order': order,
            'roles': {p.name: f'segment {i}' for i, p in enumerate(order, 1)}}


def _ewf_ext(n: int, sample: Path) -> str:
    x = 'Ex' if sample.suffix.upper().startswith('.EX') else 'E'
    if n < 100:
        return f'.{x}{n:02d}'
    n -= 100
    return f'.E{chr(65 + n // 26)}{chr(65 + n % 26)}'


def _split_set(paths):
    parsed = {p: _SPLIT.match(p.name) for p in paths}
    bases = {m.group('base').lower() for m in parsed.values()}
    widths = {len(m.group('n')) for m in parsed.values()}
    if len(bases) > 1 or len(widths) > 1:
        raise SetError(f'The numbered parts belong to different images: {", ".join(sorted(p.name for p in paths))}')
    order = sorted(paths, key=lambda p: int(parsed[p].group('n')))
    nums = [int(parsed[p].group('n')) for p in order]
    first = nums[0]
    if first not in (0, 1) or nums != list(range(first, first + len(nums))):
        expected = set(range(1 if first else 0, max(nums) + 1))
        missing = sorted(expected - set(nums))
        w = widths.pop()
        raise SetError('Parts of the split image are missing: ' + ', '.join(f'.{n:0{w}d}' for n in missing)
                       + '. Upload every part together.')
    sizes = [p.stat().st_size for p in order]
    if any(s != sizes[0] for s in sizes[:-1]) or sizes[-1] > sizes[0]:
        raise SetError('The parts of a split image must all have the same size except the last, which may be smaller: '
                       + ', '.join(f'{p.name} {s:,} bytes' for p, s in zip(order, sizes)))
    return {'format': RAW, 'kind': 'split', 'order': order, 'roles': {p.name: f'part {i}' for i, p in enumerate(order, 1)}}


def _check_virtual(fmt: str, path: Path, others: list[Path]):
    h = _open_virtual(fmt, path)
    try:
        need = _needs(fmt, h)
    finally:
        h.close()
    if need['parent']:
        raise SetError(f'{path.name} is a differencing disk: it records only changes to its parent disk '
                       f'({need["parent"][2]}). Upload the parent together with it.')
    present = {p.name.lower() for p in others} | {path.name.lower()}
    missing = [e for e in need['extents'] if e.lower() not in present]
    if missing:
        raise SetError(f'{path.name} is a VMDK descriptor whose data is in other files: upload {", ".join(missing)} with it.')


def _virtual_set(paths, formats):
    disks, extents_of = {}, {}
    for p in paths:
        fmt = formats[p]
        if fmt not in VIRTUAL:
            continue
        h = _open_virtual(fmt, p)
        try:
            disks[p] = {'format': fmt, 'need': _needs(fmt, h), 'id': _identity(fmt, h, p)}
        finally:
            h.close()
    by_name = {p.name.lower(): p for p in paths}
    extent_files = set()
    for p, d in disks.items():
        for e in d['need']['extents']:
            if e.lower() == p.name.lower():
                continue  # a monolithic VMDK names itself
            if e.lower() not in by_name:
                raise SetError(f'{p.name} is a VMDK descriptor whose data is in other files: upload {e} with it.')
            extent_files.add(by_name[e.lower()])
            extents_of.setdefault(p, []).append(by_name[e.lower()])
    parent_of = {}
    for p, d in disks.items():
        need = d['need']['parent']
        if not need:
            continue
        kind, value, shown = need
        match = [q for q, o in disks.items() if q != p and o['id'].get(kind) == value] if kind != 'name' else \
            [by_name[value]] if value in by_name else []
        if not match:
            raise SetError(f'{p.name} is a differencing disk, and its parent ({shown}) is not among the uploaded files. '
                           'Upload the parent (and its own parents) together with it.')
        if formats[match[0]] == RAW:
            raise SetError(f'{p.name} builds on a raw file ({match[0].name}); only virtual disks are supported as parents')
        parent_of[p] = match[0]
    children = [p for p in disks if p not in parent_of.values() and p not in extent_files]
    if len(children) != 1:
        raise SetError('These virtual disks are not one chain of a disk and its parents: '
                       + ', '.join(sorted(p.name for p in children)) + ' are each the top of a chain. Upload one disk at a time.')
    order, roles, cur = [], {}, children[0]
    while cur is not None:
        if cur in order:
            raise SetError('The parent identifiers of these disks form a loop')
        order.append(cur)
        roles[cur.name] = 'disk' if cur == children[0] else 'parent'
        for e in extents_of.get(cur, []):
            order.append(e)
            roles[e.name] = f'extent of {cur.name}'
        cur = parent_of.get(cur)
    unused = [p.name for p in paths if p not in order]
    if unused:
        raise SetError(f'{", ".join(unused)} is not part of {children[0].name} or its parents')
    return {'format': formats[children[0]], 'kind': 'chain', 'order': order, 'roles': roles, 'parents': {
        c.name: p.name for c, p in parent_of.items()}}


# ------------------------------------------------------------------------------------------------ media
class VirtualMedia:
    """The media of a virtual disk and its parents, as one readable object (read, seek, size)."""

    def __init__(self, files: list[dict]):
        """`files`: the evidence's image files in set order, each {name, path, role}."""
        self._handles = []
        disks = [f for f in files if not str(f.get('role', '')).startswith('extent')]
        # Open from the oldest parent down, so each disk can be given its (already open) parent.
        parent = None
        for f in reversed(disks):
            path = Path(f['path'])
            fmt = detect(path)
            h = _open_virtual(fmt, path)
            if fmt == 'VMDK':
                h.open_extent_data_files()
            if parent is not None:
                h.set_parent(parent)
            self._handles.append(h)
            parent = h
        self._top = parent
        self.size = int(self._top.get_media_size())

    def read(self, offset: int, length: int) -> bytes:
        self._top.seek(offset)
        return self._top.read(length)

    def close(self):
        for h in reversed(self._handles):
            try:
                h.close()
            except Exception:
                pass


def open_media(evidence: dict) -> VirtualMedia:
    files = evidence.get('image_files') or [{'name': evidence.get('filename'), 'path': evidence['storage_path'], 'role': 'disk'}]
    return VirtualMedia(files)


def media_size(evidence: dict) -> int:
    m = open_media(evidence)
    try:
        return m.size
    finally:
        m.close()


def ensure_space(folder: Path, needed: int, what: str):
    """Refuses (with the numbers) when the folder's file system has less free space than `needed` plus a margin."""
    folder.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(folder).free
    margin = 256 << 20
    if free < needed + margin:
        raise ValueError(f'Not enough free space for {what}: it needs {_gib(needed)} and {_gib(free)} is free in '
                         f'{folder}. Free space or move the storage, then try again.')


def _gib(n: int) -> str:
    return f'{n / (1 << 30):.2f} GiB' if n >= 1 << 30 else f'{n / (1 << 20):.1f} MiB'


def write_raw(read, size: int, dest: Path, progress=None, cancelled=None) -> dict:
    """Writes `size` bytes from read(offset, length) to dest (all-zero chunks are skipped, so the copy is sparse
    where the file system allows it), hashing as it goes. Returns {size, md5, sha256, sha512}."""
    md5, sha256, sha512 = hashlib.md5(), hashlib.sha256(), hashlib.sha512()
    zero = bytes(CHUNK)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('wb') as out:
        pos = 0
        while pos < size:
            n = min(CHUNK, size - pos)
            data = read(pos, n)
            if len(data) != n:
                raise ValueError(f'The image ended early: {pos + len(data):,} of {size:,} bytes could be read')
            md5.update(data)
            sha256.update(data)
            sha512.update(data)
            if data == zero[:n]:
                out.seek(n, 1)
            else:
                out.write(data)
            pos += n
            if progress and pos % (64 * CHUNK) == 0:
                progress(pos / size)
            if cancelled and pos % (16 * CHUNK) == 0 and cancelled():
                raise InterruptedError('Cancelled')
        out.truncate(size)
    return {'size': size, 'md5': md5.hexdigest(), 'sha256': sha256.hexdigest(), 'sha512': sha512.hexdigest()}


class ConcatenatedParts:
    """The parts of a split raw image read as one."""

    def __init__(self, paths: list[Path]):
        self._parts = []
        start = 0
        for p in paths:
            n = p.stat().st_size
            self._parts.append((start, n, p))
            start += n
        self.size = start

    def read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        for start, n, p in self._parts:
            if offset + length <= start or offset >= start + n:
                continue
            a = max(offset, start)
            b = min(offset + length, start + n)
            with p.open('rb') as f:
                f.seek(a - start)
                out += f.read(b - a)
        return bytes(out)
