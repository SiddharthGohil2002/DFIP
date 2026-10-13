"""Raw working copies: one raw file per evidence item that is not a single raw image.

Every analysis tool reads a raw disk, so evidence in another form gets a raw working copy in the analysis area,
made once and kept read-only; the uploaded original is never modified and is still what integrity checks hash.
- EnCase (E01/EX01, one file or segments): the Sleuth Kit build in the backend image (4.12 with libewf 20140816)
  crashes on EWF images, while libewf's own tools read them correctly, so the image is checked with `ewfverify`
  (internal checksums and the stored media hash) and exported with `ewfexport`.
- Virtual disks (VHD, VHDX, VMDK, QCOW2, with their parents): the media is read with libyal (libvhdi, libvmdk,
  libqcow) and written out.
- A raw image split into parts: the parts are written out one after the other.
The copy is hashed as it is written (all-zero stretches are left sparse), and the copy, its hashes and how it was
made go into the chain of custody. Free space is checked first.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import settings
from .disk_formats import EWF, LABELS, LOGICAL, VIRTUAL, ConcatenatedParts, ensure_space, open_media, write_raw

EWF_FORMATS = set(EWF)
_METHOD = {'VHD': 'libvhdi', 'VHDX': 'libvhdi', 'VMDK': 'libvmdk', 'QCOW2': 'libqcow'}


class WorkingCopyUnavailable(Exception):
    """The working copy has not been made yet (run the analysis first)."""


def image_files(evidence: dict) -> list[Path]:
    """The evidence's stored files in set order (segments in order; a virtual disk before its parents)."""
    if evidence.get('image_files'):
        return [Path(f['path']) for f in evidence['image_files']]
    return [Path(evidence['storage_path'])]


def files_sha256(paths: list[Path]) -> str:
    """SHA-256 over the files one after the other: the evidence's hash (for one file, that file's hash)."""
    h = hashlib.sha256()
    for p in paths:
        with p.open('rb') as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
    return h.hexdigest()


def evidence_sha256(evidence: dict) -> str:
    missing = [p.name for p in image_files(evidence) if not p.exists()]
    if missing:
        raise FileNotFoundError(f'Original evidence object is unavailable ({", ".join(missing)})')
    return files_sha256(image_files(evidence))


def changed_files(evidence: dict) -> list[str]:
    """For an image set whose hash no longer matches: which of its files changed."""
    out = []
    for f in evidence.get('image_files') or []:
        p = Path(f['path'])
        if not p.exists() or files_sha256([p]) != f.get('sha256'):
            out.append(f['name'])
    return out


def needs_working_copy(evidence: dict) -> bool:
    fmt = str(evidence.get('format', '')).upper()
    return fmt in EWF_FORMATS or fmt in VIRTUAL or fmt == LOGICAL or (evidence.get('image_set') or {}).get('kind') == 'split'


def working_copy_path(evidence: dict) -> Path:
    """The raw working copy, or for a logical package the folder it is unpacked into."""
    analysis = Path(settings.storage_path).resolve() / 'analysis'
    if str(evidence.get('format', '')).upper() == LOGICAL:
        return analysis / 'package' / evidence['evidence_id']
    return analysis / 'working' / f"{evidence['evidence_id']}.raw"


def analysis_image(evidence: dict, create: bool = False, db=None, actor: str = 'system') -> Path:
    """The file the Sleuth Kit should read: the original for a raw image, else the working copy.

    With create=False a missing working copy raises WorkingCopyUnavailable instead of starting a long export
    inside a web request."""
    if not needs_working_copy(evidence):
        return Path(evidence['storage_path'])
    target = working_copy_path(evidence)
    # A package is ready once its manifest is written (the folder exists while it is being unpacked).
    ready = target.with_name(f'{target.name}.manifest.jsonl').exists() if str(evidence.get('format', '')).upper() == LOGICAL else target.exists()
    if ready:
        return target
    if not create:
        what = LABELS.get(str(evidence.get('format', '')).upper(), evidence.get('format'))
        raise WorkingCopyUnavailable(f'This {what} image has not been prepared for examination yet. Run the analysis first.')
    return prepare_working_copy(evidence, db, actor)


def prepare_working_copy(evidence: dict, db=None, actor: str = 'system', timeout: int = 6 * 3600) -> Path:
    target = working_copy_path(evidence)
    partial = target.with_suffix('.partial')
    fmt = str(evidence.get('format', '')).upper()
    if fmt == LOGICAL:
        return _unpack(evidence, db, actor)
    if fmt in EWF_FORMATS:
        info = _export_ewf(evidence, partial, timeout)
    elif fmt in VIRTUAL:
        media = open_media(evidence)
        try:
            ensure_space(target.parent, media.size, 'the raw working copy')
            info = write_raw(media.read, media.size, partial)
        finally:
            media.close()
        names = [f['name'] for f in evidence.get('image_files') or []] or [evidence.get('filename')]
        info.update(method=_METHOD[fmt], detail=f'{LABELS[fmt]} read with {_METHOD[fmt]}'
                    + (f' (with its parent {", ".join(names[1:])})' if len(names) > 1 else '') + ' and written to a raw working copy')
    else:
        parts = ConcatenatedParts(image_files(evidence))
        ensure_space(target.parent, parts.size, 'the raw working copy')
        info = write_raw(parts.read, parts.size, partial)
        info.update(method='concatenated', detail=f'{len(parts._parts)} parts of a split raw image written one after the other '
                                                  'to a raw working copy')
    partial.chmod(0o444)
    partial.replace(target)

    if db is not None:
        now = datetime.now(timezone.utc)
        record = {'path': str(target), 'format': 'RAW', 'size': info['size'], 'sha256': info['sha256'], 'md5': info['md5'],
                  'method': info['method'], 'created_at': now}
        for k in ('ewfverify', 'stored_md5_match'):
            if k in info:
                record[k] = info[k]
        db['evidence'].update_one({'evidence_id': evidence['evidence_id']}, {'$set': {'working_copy': record}})
        db['chain_of_custody'].insert_one({
            'evidence_id': evidence['evidence_id'], 'case_id': evidence['case_id'], 'timestamp': now,
            'user_id': 'system', 'user_name': actor, 'action': 'WORKING_COPY_CREATED', 'sha256': info['sha256'], 'status': 'VERIFIED',
            'detail': info['detail'] + '; the original is unchanged'})
    return target


def _export_ewf(evidence: dict, partial: Path, timeout: int) -> dict:
    original = Path(evidence['storage_path'])
    for tool in ('ewfverify', 'ewfexport'):
        if not shutil.which(tool):
            raise RuntimeError(f'{tool} (libewf tools) is not installed, so E01 images cannot be examined')
    check = subprocess.run(['ewfverify', '-q', str(original)], capture_output=True, text=True, timeout=timeout)
    if check.returncode != 0:
        detail = (check.stderr or check.stdout or '').strip()[-300:]
        raise ValueError(f'ewfverify failed: the E01 image is corrupt or incomplete. {detail}'.strip())

    info = subprocess.run(['ewfinfo', str(original)], capture_output=True, text=True, timeout=600).stdout
    size_match = re.search(r'Media size:.*?\((\d+) bytes\)', info)
    if not size_match:
        raise ValueError('ewfinfo did not report the media size of the E01 image')
    media_size = int(size_match.group(1))
    stored_md5 = re.search(r'^\s*MD5:\s+([0-9a-f]{32})\s*$', info, re.M)
    ensure_space(partial.parent, media_size, 'the raw working copy')
    with partial.open('wb') as out:
        export = subprocess.run(['ewfexport', '-q', '-u', '-f', 'raw', '-t', '-', str(original)],
                                stdout=out, stderr=subprocess.PIPE, timeout=timeout)
    if export.returncode != 0 or partial.stat().st_size < media_size:
        partial.unlink(missing_ok=True)
        raise ValueError(f'ewfexport could not export the E01 image: {export.stderr.decode(errors="replace").strip()[-300:]}')
    # ewfexport writes its status line ("ewfexport: SUCCESS") to stdout after the media data.
    with partial.open('r+b') as f:
        f.truncate(media_size)
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with partial.open('rb') as f:
        while chunk := f.read(4 * 1024 * 1024):
            md5.update(chunk)
            sha256.update(chunk)
    if stored_md5 and md5.hexdigest() != stored_md5.group(1):
        partial.unlink(missing_ok=True)
        raise ValueError('The exported media does not match the MD5 stored in the E01 image; analysis refused')
    md5_note = 'matches the MD5 stored in the E01' if stored_md5 else 'the E01 stores no MD5 to compare'
    segments = len(evidence.get('image_files') or []) or 1
    return {'size': media_size, 'md5': md5.hexdigest(), 'sha256': sha256.hexdigest(), 'method': 'ewfexport', 'ewfverify': 'SUCCESS',
            'stored_md5_match': bool(stored_md5),
            'detail': f'E01 ({segments} segment{"s" if segments > 1 else ""}) checked with ewfverify and exported to a raw working copy ({md5_note})'}


def _unpack(evidence: dict, db=None, actor: str = 'system') -> Path:
    """Unpacks a logical package (ZIP or TAR) into the analysis area, read-only, with its manifest (packages.py)."""
    from .packages import archive_kind, remove_tree, unpack
    target = working_copy_path(evidence)
    manifest = target.with_name(f'{target.name}.manifest.jsonl')
    partial_manifest = target.with_name(f'{target.name}.manifest.partial')
    # Unpacked in place (folders are not renamed: Windows-backed storage refuses that); the manifest, renamed last, marks it complete.
    if target.exists():
        remove_tree(target)  # an unpack that was interrupted
    partial_manifest.unlink(missing_ok=True)
    original = Path(evidence['storage_path'])
    kind = archive_kind(original)
    if not kind:
        raise ValueError('The package is not a ZIP or TAR archive')
    try:
        info = unpack(original, target, kind, ensure_space=lambda n: ensure_space(target.parent, n, 'the unpacked package'),
                      manifest_path=partial_manifest)
    except BaseException:
        if target.exists():
            remove_tree(target)
        partial_manifest.unlink(missing_ok=True)
        raise
    partial_manifest.replace(manifest)
    roots = info['roots']
    package = {'archive': kind, 'files': info['files'], 'folders': info['folders'], 'links': info['links'], 'skipped': info['skipped'],
               'bytes': info['bytes'], 'roots': roots, 'manifest': str(manifest), 'manifest_sha256': info['manifest_sha256'],
               'zip_local_times': info['zip_local_times'], 'unpacked_at': datetime.now(timezone.utc)}
    evidence['package'] = package
    if db is not None:
        db['evidence'].update_one({'evidence_id': evidence['evidence_id']}, {'$set': {'package': package}})
        where = ', '.join(f'{r["volume_id"]} = {r["path"] or "(top)"} ({r["os"] or "unknown system"})' for r in roots)
        db['chain_of_custody'].insert_one({
            'evidence_id': evidence['evidence_id'], 'case_id': evidence['case_id'], 'timestamp': package['unpacked_at'],
            'user_id': 'system', 'user_name': actor, 'action': 'PACKAGE_UNPACKED', 'sha256': info['manifest_sha256'], 'status': 'VERIFIED',
            'detail': f'{info["files"]:,} files ({info["bytes"]:,} bytes) unpacked read-only from the {kind} package; {info["links"]} links and '
                      f'{info["skipped"]} unsafe or duplicate entries recorded but not written; the SHA-256 is that of the manifest. '
                      f'File systems: {where}. The package is unchanged'})
    return target
