"""Raw working copy for EnCase (E01/EX01) evidence.

The Sleuth Kit build in the backend image (4.12 with libewf 20140816) crashes on
EWF images, while libewf's own tools read them correctly. EWF evidence is
therefore checked with `ewfverify` (the image's internal checksums and stored
media hash) and exported once with `ewfexport` to a raw working copy in the
analysis area. Every analysis tool reads that copy; the uploaded original is
never modified and is still what integrity checks hash.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import settings

EWF_FORMATS = {'E01', 'EX01'}


class WorkingCopyUnavailable(Exception):
    """The E01 has not been prepared yet (run the analysis first)."""


def needs_working_copy(evidence: dict) -> bool:
    return str(evidence.get('format', '')).upper() in EWF_FORMATS


def working_copy_path(evidence: dict) -> Path:
    return Path(settings.storage_path).resolve() / 'analysis' / 'working' / f"{evidence['evidence_id']}.raw"


def analysis_image(evidence: dict, create: bool = False, db=None, actor: str = 'system') -> Path:
    """The file the Sleuth Kit should read: the original for raw images, the working copy for E01.

    With create=False a missing working copy raises WorkingCopyUnavailable instead of
    starting a long export inside a web request."""
    if not needs_working_copy(evidence):
        return Path(evidence['storage_path'])
    target = working_copy_path(evidence)
    if target.exists():
        return target
    if not create:
        raise WorkingCopyUnavailable('This E01 image has not been prepared for examination yet. Run the analysis first.')
    return prepare_working_copy(evidence, db, actor)


def prepare_working_copy(evidence: dict, db=None, actor: str = 'system', timeout: int = 6 * 3600) -> Path:
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

    target = working_copy_path(evidence)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix('.partial')
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
    digest = sha256.hexdigest()
    partial.chmod(0o444)
    partial.replace(target)

    if db is not None:
        now = datetime.now(timezone.utc)
        md5_note = 'matches the MD5 stored in the E01' if stored_md5 else 'the E01 stores no MD5 to compare'
        db['evidence'].update_one({'evidence_id': evidence['evidence_id']}, {'$set': {'working_copy': {
            'path': str(target), 'format': 'RAW', 'size': media_size, 'sha256': digest, 'md5': md5.hexdigest(),
            'ewfverify': 'SUCCESS', 'stored_md5_match': bool(stored_md5), 'created_at': now}}})
        db['chain_of_custody'].insert_one({
            'evidence_id': evidence['evidence_id'], 'case_id': evidence['case_id'], 'timestamp': now,
            'user_id': 'system', 'user_name': actor, 'action': 'WORKING_COPY_CREATED', 'sha256': digest, 'status': 'VERIFIED',
            'detail': f'E01 checked with ewfverify and exported to a raw working copy ({md5_note}); the original is unchanged'})
    return target
