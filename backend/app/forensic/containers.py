"""Files inside other files: archive members, embedded objects and media of Office documents, PDF attachments.

Readers, by the container's real type (from file processing):
  zip     ZIP archives (zipfile; read in place, never unpacked as a whole)
  ooxml   media and embedded objects of Word, Excel and PowerPoint files (word/media, xl/embeddings...)
  odf     pictures and embedded objects of OpenDocument files
  ole     legacy Office and other compound files: embedded packages (Ole10Native), embedded documents (Package,
          CONTENTS)
  pdf     PDF attachments (pdfdetach, one attachment at a time to a path DFIP chooses)
  7z      7z, RAR, tar, gzip, bzip2, xz, CAB and other archives 7-Zip reads (listed first, then unpacked into an
          empty folder under a file-size limit)

Every member is written under a generated name (its own name is only data), never through a symbolic link and
never outside the members folder. Encrypted members are listed, not extracted. Limits stop archive bombs: a
member may not be larger than MAX_MEMBER_BYTES or expand more than MAX_RATIO times, and a container (with its
nested containers) or an evidence item may not unpack more than its budget.
"""
from __future__ import annotations
import os
import re
import shutil
import struct
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .filetypes import ARCHIVE_MIMES, BlobFile, _LEGACY_OFFICE, _OOXML

MAX_DEPTH = 2                       # a container in a container is opened; one more level is listed only
MAX_MEMBERS = 10_000                # per container
MAX_MEMBER_BYTES = 512 << 20
MAX_RATIO = 200                     # uncompressed / compressed, for members over RATIO_MIN_BYTES
RATIO_MIN_BYTES = 16 << 20
MAX_CONTAINER_BYTES = 4 << 30       # unpacked from one top-level container, nested ones included
MAX_EVIDENCE_BYTES = 32 << 30
MAX_COPY_BYTES = 8 << 30            # largest container copied to a work file for 7-Zip or pdfdetach
TOOL_TIMEOUT = 1800
DUMMY_PASSWORD = '-pDFIP-NO-PASSWORD'  # so 7-Zip never waits for a password; encrypted members fail to unpack

_OOXML_EMBEDDED = re.compile(r'^(word|xl|ppt)/(media|embeddings)/[^/]+$')
_ODF_EMBEDDED = re.compile(r'^(Pictures/[^/]+|Object [^/]+/(?!content\.xml$|styles\.xml$|meta\.xml$|settings\.xml$)[^/]+)$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


@dataclass
class Member:
    name: str
    size: int | None
    packed: int | None = None
    modified: str | None = None       # as recorded in the container (no time zone)
    encrypted: bool = False
    store: Path | None = None         # where its bytes were written; None when listed only
    note: str | None = None           # why it was not extracted


class Budget:
    """Bytes that may still be unpacked from the evidence item and from the current top-level container."""

    def __init__(self, evidence: int = MAX_EVIDENCE_BYTES):
        self.evidence = evidence
        self.container = MAX_CONTAINER_BYTES

    def start_container(self):
        self.container = MAX_CONTAINER_BYTES

    def fits(self, n: int) -> bool:
        return n <= self.evidence and n <= self.container

    def spend(self, n: int):
        self.evidence -= n
        self.container -= n


def kind_for(entry: dict) -> str | None:
    """Which reader opens this file, from its real type; None when it holds no files."""
    mime = entry.get('mime') or ''
    enc = entry.get('encryption') or {}
    if mime in _OOXML:
        return None if enc else 'ooxml'
    if mime.startswith('application/vnd.oasis.opendocument'):
        return None if enc else 'odf'
    if mime in ('application/zip', 'application/epub+zip', 'application/java-archive'):
        return 'zip'  # an encrypted ZIP is listed (its members flagged), not extracted
    if mime in ARCHIVE_MIMES:
        return '7z'
    if mime in _LEGACY_OFFICE and mime != 'application/encrypted' and not enc:
        return 'ole'
    if mime == 'application/pdf' and not enc:
        return 'pdf'
    return None


def clean_name(name: str) -> str:
    return _CONTROL.sub('?', name or '').strip() or '(unnamed)'


def _new_store(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / uuid.uuid4().hex


def _check_limits(m: Member, budget: Budget) -> str | None:
    if m.size is None:
        return None
    if m.size > MAX_MEMBER_BYTES:
        return f'larger than the {MAX_MEMBER_BYTES >> 20} MiB member limit: listed only'
    if m.packed and m.size > RATIO_MIN_BYTES and m.size / max(1, m.packed) > MAX_RATIO:
        return f'expands {m.size // max(1, m.packed):,} times: possible archive bomb, not extracted'
    if not budget.fits(m.size):
        return 'over the unpacking limit for this container or evidence item: listed only'
    return None


# ------------------------------------------------------------------ ZIP, Office Open XML, OpenDocument
def read_zip(blob, kind: str, out_dir: Path, budget: Budget) -> list[Member]:
    z = zipfile.ZipFile(BlobFile(blob))
    members = []
    for info in z.infolist():
        if info.is_dir():
            continue
        if kind == 'ooxml' and not _OOXML_EMBEDDED.match(info.filename):
            continue
        if kind == 'odf' and not _ODF_EMBEDDED.match(info.filename):
            continue
        if len(members) >= MAX_MEMBERS:
            members.append(Member('…', None, note=f'more than {MAX_MEMBERS:,} members: the rest were not listed'))
            break
        m = Member(clean_name(info.filename), info.file_size, info.compress_size,
                   '%04d-%02d-%02d %02d:%02d:%02d' % info.date_time, bool(info.flag_bits & 0x1))
        if m.encrypted:
            m.note = 'encrypted: listed only'
        else:
            m.note = _check_limits(m, budget)
        if not m.note:
            dest = _new_store(out_dir)
            written = 0
            try:
                with z.open(info) as src, dest.open('wb') as out:
                    while chunk := src.read(1 << 20):
                        written += len(chunk)
                        if written > info.file_size:  # the header understated the size
                            raise ValueError('member is larger than its header says')
                        out.write(chunk)
                m.store = dest
                budget.spend(written)
            except Exception as exc:
                dest.unlink(missing_ok=True)
                m.note = f'could not be extracted: {str(exc)[:150]}'
        members.append(m)
    return members


# ------------------------------------------------------------------ OLE compound files
def parse_ole10native(data: bytes) -> tuple[str, bytes] | None:
    """(original file name, content) of an Ole10Native stream (an embedded 'package'), or None."""
    try:
        pos = 4 + 2  # total size, then a flag
        def cstr():
            nonlocal pos
            end = data.index(b'\x00', pos)
            s = data[pos:end].decode('latin-1')
            pos = end + 1
            return s
        label = cstr()
        src_path = cstr()
        pos += 8
        cstr()  # temporary path
        size, = struct.unpack_from('<I', data, pos)
        pos += 4
        if size > len(data) - pos:
            return None
        name = (src_path or label).replace('\\', '/').rsplit('/', 1)[-1] or label
        return name, data[pos:pos + size]
    except (ValueError, struct.error):
        return None


def read_ole(blob, out_dir: Path, budget: Budget) -> list[Member]:
    import olefile
    ole = olefile.OleFileIO(BlobFile(blob))
    members = []
    try:
        for parts in ole.listdir(streams=True, storages=False):
            last = parts[-1]
            if last not in ('\x01Ole10Native', 'Package', 'CONTENTS'):
                continue
            raw = ole.openstream(parts).read(MAX_MEMBER_BYTES + 1)
            where = '/'.join(p.replace('\x01', '') for p in parts)
            if last == '\x01Ole10Native':
                native = parse_ole10native(raw)
                if not native:
                    members.append(Member(where, len(raw), note='embedded package could not be read'))
                    continue
                name, data = native
                m = Member(clean_name(name), len(data))
            else:
                data = raw
                m = Member(where, len(data))
            m.note = _check_limits(m, budget)
            if not m.note:
                dest = _new_store(out_dir)
                dest.write_bytes(data)
                m.store = dest
                budget.spend(len(data))
            members.append(m)
            if len(members) >= MAX_MEMBERS:
                break
    finally:
        ole.close()
    return members


# ------------------------------------------------------------------ PDF attachments
def _copy(blob, dest: Path):
    if blob.size > MAX_COPY_BYTES:
        raise ValueError(f'container larger than {MAX_COPY_BYTES >> 30} GiB: not opened')
    with dest.open('wb') as out:
        for start in range(0, blob.size, 1 << 20):
            out.write(blob.read(start, min(1 << 20, blob.size - start)))


def read_pdf(blob, out_dir: Path, budget: Budget, run_tool, work: Path) -> list[Member]:
    work.mkdir(parents=True, exist_ok=True)
    src = work / f'{uuid.uuid4().hex}.pdf'
    try:
        _copy(blob, src)
        r = run_tool(['pdfdetach', '-list', str(src)], timeout=120)
        if r.get('status') != 'COMPLETED':
            raise ValueError(f'pdfdetach: {(r.get("stderr") or r.get("status") or "")[:200]}')
        names = [m.group(1) for m in re.finditer(r'^\s*\d+:\s*(.*)$', r.get('stdout') or '', re.M)]
        members = []
        for i, name in enumerate(names[:MAX_MEMBERS], 1):
            dest = _new_store(out_dir)
            r = run_tool(['pdfdetach', '-save', str(i), '-o', str(dest), str(src)], timeout=300,
                         file_bytes=min(MAX_MEMBER_BYTES, max(1, budget.container), max(1, budget.evidence)))
            m = Member(clean_name(name), dest.stat().st_size if dest.exists() else None)
            if r.get('status') != 'COMPLETED' or not dest.exists():
                dest.unlink(missing_ok=True)
                m.note = 'could not be extracted (or over the size limit)'
            else:
                m.store = dest
                budget.spend(m.size or 0)
            members.append(m)
        return members
    finally:
        src.unlink(missing_ok=True)


# ------------------------------------------------------------------ 7-Zip (7z, RAR, tar, gzip, bzip2, xz, CAB...)
def parse_7z_listing(text: str) -> list[dict]:
    """Entries of `7z l -slt -ba` output: one block of 'Key = value' lines per entry."""
    entries, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        key, sep, value = line.partition(' = ')
        if sep:
            if key == 'Path' and cur.get('Path') is not None:
                entries.append(cur)
                cur = {}
            cur[key] = value
    if cur:
        entries.append(cur)
    return [e for e in entries if 'Path' in e]


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def read_7z(blob, out_dir: Path, budget: Budget, run_tool, work: Path) -> tuple[list[Member], bool]:
    """Members, and whether the archive's names themselves are encrypted (nothing could be listed)."""
    work.mkdir(parents=True, exist_ok=True)
    src = work / f'{uuid.uuid4().hex}.archive'
    unpack = work / f'{uuid.uuid4().hex}.unpacked'
    try:
        _copy(blob, src)
        r = run_tool(['7z', 'l', '-slt', '-ba', DUMMY_PASSWORD, str(src)], timeout=TOOL_TIMEOUT, max_output=20_000_000)
        listing = parse_7z_listing(r.get('stdout') or '')
        if not listing:
            text = (r.get('stdout') or '') + (r.get('stderr') or '')
            if 'Wrong password' in text or 'encrypted' in text.lower():
                return [], True
            raise ValueError(f'7-Zip could not list it: {text.strip()[:200]}')
        members = []
        for e in listing:
            if 'D' in (e.get('Attributes') or '') or e.get('Folder') == '+':
                continue
            if len(members) >= MAX_MEMBERS:
                members.append(Member('…', None, note=f'more than {MAX_MEMBERS:,} members: the rest were not listed'))
                break
            m = Member(clean_name(e['Path']), _int(e.get('Size')), _int(e.get('Packed Size')), e.get('Modified') or None,
                       e.get('Encrypted') == '+')
            m.note = 'encrypted: listed only' if m.encrypted else _check_limits(m, budget)
            members.append(m)
        wanted = {m.name: m for m in members if not m.note and m.name != '…'}
        total = sum(m.size or 0 for m in wanted.values())
        if wanted and not budget.fits(total):
            for m in wanted.values():
                m.note = 'over the unpacking limit for this container or evidence item: listed only'
            wanted = {}
        if wanted:
            unpack.mkdir()
            # Links in the archive are never followed: only regular files inside the folder are taken below.
            r = run_tool(['7z', 'x', '-y', '-bd', DUMMY_PASSWORD, f'-o{unpack}', str(src)], timeout=TOOL_TIMEOUT,
                         file_bytes=MAX_MEMBER_BYTES + 1)
            root = unpack.resolve()
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                for fn in filenames:
                    p = Path(dirpath) / fn
                    if p.is_symlink() or not p.is_file() or root not in p.resolve().parents:
                        continue
                    rel = p.relative_to(root).as_posix()
                    m = wanted.pop(clean_name(rel), None)
                    if m is None:
                        continue
                    dest = _new_store(out_dir)
                    shutil.move(str(p), dest)
                    m.store = dest
                    m.size = dest.stat().st_size
                    budget.spend(m.size)
            for m in wanted.values():
                m.note = 'not extracted by 7-Zip' + (f' ({r.get("status").lower()})' if r.get('status') != 'COMPLETED' else '')
        return members, False
    finally:
        src.unlink(missing_ok=True)
        shutil.rmtree(unpack, ignore_errors=True)


def read_container(kind: str, blob, out_dir: Path, budget: Budget, run_tool, work: Path) -> tuple[list[Member], bool]:
    """(members, names encrypted) of one container."""
    if kind in ('zip', 'ooxml', 'odf'):
        return read_zip(blob, kind, out_dir, budget), False
    if kind == 'ole':
        return read_ole(blob, out_dir, budget), False
    if kind == 'pdf':
        return read_pdf(blob, out_dir, budget, run_tool, work), False
    if kind == '7z':
        return read_7z(blob, out_dir, budget, run_tool, work)
    raise ValueError(f'Unknown container kind {kind}')
