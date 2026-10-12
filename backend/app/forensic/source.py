"""Where evidence content comes from, behind one interface.

Analysis modules and the file viewer read files through an EvidenceSource instead of calling Sleuth Kit tools
directly, so the same code works on a disk image (TskImageSource, in-process through pytsk3) and on a folder of
loose files such as an unpacked triage package (DirectorySource).

A volume is named by a `volume_id`: `p<start sector>` for a partition of a disk image (`p0` when the image is a
bare file system), `p<start>/vss<n>` for its n-th Volume Shadow Copy (read through libvshadow), and later `pkg`
for a logical package. A `BlobRef`
names one piece of content: a file by inode (images) or path (folders), optionally one of its data streams, and,
for content found inside other content (an archive member, an e-mail attachment), the chain of containers.
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

SECTOR = 512
_VOLUME_RE = re.compile(r'^p(\d+)$')
_ANY_VOLUME_RE = re.compile(r'^p(\d+)(?:/vss(\d+))?$')
_INODE_RE = re.compile(r'^(\d+)(?:-(\d+)(?:-(\d+))?)?$')


def volume_id(partition_offset: int) -> str:
    return f'p{int(partition_offset or 0)}'


def offset_of(vid: str) -> int:
    """The start sector of a partition volume id ('p2048' -> 2048); ValueError for anything else."""
    m = _VOLUME_RE.match(vid or '')
    if not m:
        raise ValueError(f'Not a partition volume id: {vid!r}')
    return int(m.group(1))


def parse_volume(vid: str) -> tuple[int, int | None]:
    """(start sector, shadow copy number or None): 'p2048' -> (2048, None), 'p2048/vss2' -> (2048, 2)."""
    m = _ANY_VOLUME_RE.match(vid or '')
    if not m or (m.group(2) is not None and int(m.group(2)) < 1):
        raise ValueError(f'Not a volume id: {vid!r}')
    return int(m.group(1)), (int(m.group(2)) if m.group(2) else None)


def shadow_volume_id(start_sector: int, store: int) -> str:
    return f'p{int(start_sector)}/vss{int(store)}'


class OffsetFile:
    """A window of a file (a partition of a disk image) as a file object for libyal's readers."""

    def __init__(self, path: Path, start: int, size: int | None = None):
        self._f = open(path, 'rb')
        total = os.path.getsize(path)
        self._start = start
        self._size = max(0, total - start) if size is None else min(size, max(0, total - start))
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or self._pos + n > self._size:
            n = self._size - self._pos
        if n <= 0:
            return b''
        self._f.seek(self._start + self._pos)
        data = self._f.read(n)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        base = {os.SEEK_SET: 0, os.SEEK_CUR: self._pos, os.SEEK_END: self._size}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._size

    def close(self):
        self._f.close()


@dataclass(frozen=True)
class BlobRef:
    evidence_id: str
    volume_id: str
    inode: str | None = None
    path: str | None = None
    stream: str | None = None
    chain: tuple = field(default_factory=tuple)


class Blob:
    """Random-access content of one file."""
    size: int = 0

    def read(self, start: int, length: int) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


class EvidenceSource:
    def volumes(self) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def walk(self, vid: str) -> Iterator[dict]:  # pragma: no cover - interface
        raise NotImplementedError

    def open(self, ref: BlobRef) -> Blob:  # pragma: no cover - interface
        raise NotImplementedError

    def find(self, vid: str, path: str) -> str | None:  # pragma: no cover - interface
        """The inode (images) or path (folders) of a file by its path, or None."""
        raise NotImplementedError

    def read_range(self, ref: BlobRef, start: int, length: int) -> bytes:
        blob = self.open(ref)
        if start >= blob.size:
            return b''
        return blob.read(start, min(length, blob.size - start))

    def copy_to(self, ref: BlobRef, dest: Path, chunk: int = 1 << 20) -> tuple[int, str]:
        """Copies a file out (for parsers that need a path), returning its size and SHA-256."""
        import hashlib
        blob = self.open(ref)
        h = hashlib.sha256()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('wb') as out:
            for start in range(0, blob.size, chunk):
                data = blob.read(start, min(chunk, blob.size - start))
                h.update(data)
                out.write(data)
        return blob.size, h.hexdigest()


# ---------------------------------------------------------------------------------------------- disk images
class _TskBlob(Blob):
    def __init__(self, f, attr_type, attr_id):
        self._f = f
        self._type = attr_type
        self._id = attr_id
        self.size = int(f.info.meta.size or 0) if f.info.meta else 0
        if attr_type is not None:
            for attr in f:
                if int(attr.info.type) == attr_type and int(attr.info.id) == attr_id:
                    self.size = int(attr.info.size)
                    break

    def read(self, start: int, length: int) -> bytes:
        if length <= 0 or start >= self.size:
            return b''
        length = min(length, self.size - start)
        if self._type is None:
            return self._f.read_random(start, length)
        return self._f.read_random(start, length, self._type, self._id)


class TskImageSource(EvidenceSource):
    """A raw disk image (or an E01's verified raw working copy) read in-process with pytsk3."""

    def __init__(self, image: Path, offsets: list[int] | None = None):
        import pytsk3
        self._tsk = pytsk3
        self.image = Path(image)
        self._img = pytsk3.Img_Info(str(self.image))
        self._offsets = offsets
        self._fs: dict = {}
        self._keep: list = []  # libvshadow objects a shadow copy's file system reads through

    def volumes(self) -> list[str]:
        if self._offsets is not None:
            return [volume_id(o) for o in self._offsets]
        found = []
        try:
            vs = self._tsk.Volume_Info(self._img)
            for part in vs:
                desc = part.desc.decode(errors='replace') if isinstance(part.desc, bytes) else str(part.desc)
                if part.flags == self._tsk.TSK_VS_PART_FLAG_ALLOC and 'extended' not in desc.lower():
                    found.append(int(part.start))
        except OSError:
            pass  # no partition table: a bare file system
        return [volume_id(o) for o in (found or [0])]

    def _filesystem(self, vid: str):
        off, store = parse_volume(vid)
        if (off, store) not in self._fs:
            if store is None:
                self._fs[(off, store)] = self._tsk.FS_Info(self._img, offset=off * SECTOR)
            else:
                self._fs[(off, store)] = self._tsk.FS_Info(self._shadow_image(off, store))
        return self._fs[(off, store)]

    def _shadow_image(self, off: int, store: int):
        """A shadow copy of the volume at `off`, as a pytsk3 image (libvshadow reads it in-process)."""
        import pyvshadow
        window = OffsetFile(self.image, off * SECTOR)
        vss = pyvshadow.volume()
        vss.open_file_object(window)
        if not 1 <= store <= vss.number_of_stores:
            raise ValueError(f'The volume has no shadow copy {store}')
        snap = vss.get_store(store - 1)
        tsk = self._tsk

        class StoreImage(tsk.Img_Info):
            def __init__(self):
                super().__init__(url='', type=tsk.TSK_IMG_TYPE_EXTERNAL)

            def read(self, offset, size):
                snap.seek(offset)
                return snap.read(size)

            def get_size(self):
                return snap.volume_size

        self._keep += [window, vss, snap]
        img = StoreImage()
        self._keep.append(img)
        return img

    def find(self, vid: str, path: str) -> str | None:
        """Sleuth Kit's path lookup (case-insensitive on FAT and NTFS); allocated files only."""
        try:
            f = self._filesystem(vid).open(path)
        except OSError:
            return None
        return str(f.info.meta.addr) if f.info.meta else None

    def open(self, ref: BlobRef) -> Blob:
        m = _INODE_RE.match(ref.inode or '')
        if not m:
            raise ValueError('Invalid inode address')
        f = self._filesystem(ref.volume_id).open_meta(inode=int(m.group(1)))
        attr_type = int(m.group(2)) if m.group(2) else None
        attr_id = int(m.group(3)) if m.group(3) else (0 if attr_type is not None else None)
        return _TskBlob(f, attr_type, attr_id)

    def walk(self, vid: str, times: bool = False) -> Iterator[dict]:
        """Every named entry of a volume (allocated and deleted), depth first: {path, inode, size, is_dir, deleted}, and
        with times=True the entry's modified, accessed, changed and created times (seconds since 1970, or None)."""
        fs = self._filesystem(vid)
        seen = set()

        def visit(directory, parent):
            for entry in directory:
                name = entry.info.name.name
                name = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else str(name)
                if name in ('.', '..') or entry.info.meta is None:
                    continue
                meta = entry.info.meta
                path = f'{parent}/{name}' if parent != '/' else f'/{name}'
                virtual = meta.type in (self._tsk.TSK_FS_META_TYPE_VIRT, self._tsk.TSK_FS_META_TYPE_VIRT_DIR)
                is_dir = meta.type in (self._tsk.TSK_FS_META_TYPE_DIR, self._tsk.TSK_FS_META_TYPE_VIRT_DIR)
                deleted = bool(int(entry.info.name.flags) & int(self._tsk.TSK_FS_NAME_FLAG_UNALLOC))
                # Sleuth Kit's own entries ($MBR, $FAT1, $OrphanFiles, ...) are flagged as in the file index.
                item = {'path': path, 'inode': str(meta.addr), 'size': int(meta.size or 0), 'is_dir': is_dir,
                        'deleted': deleted, 'is_virtual': virtual}
                if times:
                    item.update({k: (int(getattr(meta, k)) or None) for k in ('mtime', 'atime', 'ctime', 'crtime')})
                yield item
                if is_dir and not deleted and meta.addr not in seen:
                    seen.add(meta.addr)
                    try:
                        yield from visit(entry.as_directory(), path)
                    except OSError:
                        continue

        yield from visit(fs.open_dir(path='/'), '/')


# --------------------------------------------------------------------------------------------- loose files
class _FileBlob(Blob):
    def __init__(self, path: Path):
        self._path = path
        self.size = path.stat().st_size

    def read(self, start: int, length: int) -> bytes:
        with self._path.open('rb') as f:
            f.seek(start)
            return f.read(length)


class DirectorySource(EvidenceSource):
    """A folder of loose files (an unpacked logical package); paths are '/'-rooted and never leave the folder."""

    VOLUME = 'pkg'

    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def volumes(self) -> list[str]:
        return [self.VOLUME]

    def _local(self, path: str) -> Path:
        local = (self.root / path.lstrip('/')).resolve()
        if local != self.root and self.root not in local.parents:
            raise ValueError('Path is outside the package')
        return local

    def find(self, vid: str, path: str) -> str | None:
        try:
            local = self._local(path)
        except ValueError:
            return None
        if local.is_file() and not local.is_symlink():
            return path
        # Windows paths are case-insensitive: match each part regardless of case.
        cur = self.root
        for part in path.strip('/').split('/'):
            match = next((c for c in cur.iterdir() if c.name.lower() == part.lower()), None) if cur.is_dir() else None
            if match is None or match.is_symlink():
                return None
            cur = match
        return '/' + cur.relative_to(self.root).as_posix() if cur.is_file() else None

    def open(self, ref: BlobRef) -> Blob:
        local = self._local(ref.path or '')
        if not local.is_file() or local.is_symlink():
            raise FileNotFoundError(ref.path)
        return _FileBlob(local)

    def walk(self, vid: str = VOLUME) -> Iterator[dict]:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames.sort()
            rel = Path(dirpath).relative_to(self.root).as_posix()
            rel = '' if rel == '.' else '/' + rel
            for d in dirnames:
                yield {'path': f'{rel}/{d}', 'inode': None, 'size': 0, 'is_dir': True, 'deleted': False}
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.is_symlink():
                    continue
                yield {'path': f'{rel}/{name}', 'inode': None, 'size': p.stat().st_size, 'is_dir': False, 'deleted': False}


# --------------------------------------------------------------------------------------------- container members
def members_root() -> Path:
    """Where members taken out of archives and documents are kept, under generated names (never their own)."""
    from ..core.config import settings
    return Path(settings.storage_path).resolve() / 'analysis' / 'members'


def member_path(entry: dict) -> Path:
    root = members_root()
    p = (root / entry['container']['store']).resolve()
    if root not in p.parents:
        raise ValueError('Member store path outside the members folder')
    return p


def open_entry(src: EvidenceSource, evidence_id: str, entry: dict) -> Blob:
    """The content of a file-index entry: a file on the evidence, or a member taken out of a container."""
    if entry.get('container'):
        if not (entry['container'].get('store')):
            raise ValueError('This member was not extracted (encrypted, or over a size limit)')
        return _FileBlob(member_path(entry))
    return src.open(BlobRef(evidence_id, entry.get('volume_id') or 'p0', inode=entry.get('inode')))
