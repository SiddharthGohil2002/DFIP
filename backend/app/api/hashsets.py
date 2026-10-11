"""Hash sets: known-good, known-bad and notable file hashes that every evidence file is compared with.

Administrators import sets (an upload, or a large file such as the NSRL placed in storage/hashsets/incoming on
the server); every signed-in user can see which sets exist. Importing or deleting a set re-matches every
evidence item whose files were hashed.
"""
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from ..core.config import settings
from ..database import get_db
from ..forensic.hashsets import KINDS, root, store_path
from ..security import current_user, require_write
from ..services.audit import log
from ..services.sequences import next_sequence

r = APIRouter(prefix='/hashsets', tags=['hashsets'])
_PUBLIC = ('set_id', 'name', 'kind', 'description', 'status', 'format', 'count', 'counts', 'algorithms', 'invalid_lines', 'error',
           'source_filename', 'source_size', 'source_sha256', 'imported_by_name', 'imported_at', 'ready_at', 'job_id')
_NAME_RE = re.compile(r'^[\w .()+,&@#-]{1,120}$')
_FILE_RE = re.compile(r'^[\w.+-]{1,200}$')


def _public(doc) -> dict:
    return {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in doc.items() if k in _PUBLIC}


def _incoming() -> Path:
    p = root() / 'incoming'
    p.mkdir(parents=True, exist_ok=True)
    return p


def _check(name: str, kind: str):
    if not _NAME_RE.match(name.strip()):
        raise HTTPException(400, 'Give the set a name of 1-120 letters, digits, spaces or simple punctuation')
    if kind not in KINDS:
        raise HTTPException(400, f'kind must be one of {", ".join(KINDS)}')


def _create(u, name, kind, description, source: Path, uploaded: bool, filename: str, sha256: str, size: int) -> dict:
    from ..services.jobs import queue
    db = get_db()
    set_id = f'HS-{next_sequence("hash_sets", floor=db["hash_sets"].count_documents({})):04d}'
    doc = {'set_id': set_id, 'name': name.strip(), 'kind': kind, 'description': (description or '').strip()[:1000] or None,
           'status': 'IMPORTING', 'source_filename': filename, 'source_path': str(source), 'source_uploaded': uploaded,
           'source_size': size, 'source_sha256': sha256, 'imported_by': str(u['_id']), 'imported_by_name': u.get('name'),
           'imported_at': datetime.now(timezone.utc)}
    db['hash_sets'].insert_one(doc)
    job_id = queue.enqueue('HASHSET_IMPORT', {'set_id': set_id}, u['_id'])
    db['hash_sets'].update_one({'set_id': set_id}, {'$set': {'job_id': job_id}})
    log(u, 'HASHSET_IMPORTED', 'hash_set', set_id, {'name': doc['name'], 'kind': kind, 'source': filename, 'sha256': sha256})
    return {'set_id': set_id, 'job_id': job_id}


@r.get('')
def list_sets(u=Depends(current_user)):
    return {'data': [_public(x) for x in get_db()['hash_sets'].find().sort('imported_at', -1)]}


@r.get('/incoming')
def incoming(u=Depends(require_write('HASHSET_MANAGE'))):
    """Files an administrator placed in storage/hashsets/incoming on the server, for large sets such as the NSRL."""
    return {'data': [{'filename': p.name, 'size': p.stat().st_size} for p in sorted(_incoming().iterdir()) if p.is_file()]}


@r.post('')
async def upload_set(file: UploadFile = File(...), name: str = Form(...), kind: str = Form(...),
                     description: Optional[str] = Form(None), u=Depends(require_write('HASHSET_MANAGE'))):
    _check(name, kind)
    uploads = root() / 'uploads'
    uploads.mkdir(parents=True, exist_ok=True)
    dest = uploads / f'{datetime.now(timezone.utc):%Y%m%dT%H%M%S%f}.src'
    h, written = hashlib.sha256(), 0
    with dest.open('wb') as out:
        while chunk := await file.read(1024 * 1024):
            written += len(chunk)
            if written > settings.max_upload_bytes:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f'File exceeds the configured limit of {settings.max_upload_bytes} bytes')
            h.update(chunk)
            out.write(chunk)
    if not written:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, 'The file is empty')
    return _create(u, name, kind, description, dest, True, Path(file.filename or 'upload').name, h.hexdigest(), written)


class LocalImport(BaseModel):
    filename: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    kind: str
    description: Optional[str] = Field(default=None, max_length=1000)


@r.post('/import-local')
def import_local(x: LocalImport, u=Depends(require_write('HASHSET_MANAGE'))):
    _check(x.name, x.kind)
    if not _FILE_RE.match(x.filename) or x.filename.startswith('.'):
        raise HTTPException(400, 'Give the name of a file in storage/hashsets/incoming (no folders)')
    source = _incoming() / x.filename
    if not source.is_file() or source.is_symlink():
        raise HTTPException(404, f'{x.filename} is not in storage/hashsets/incoming')
    h = hashlib.sha256()
    with source.open('rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return _create(u, x.name, x.kind, x.description, source, False, x.filename, h.hexdigest(), source.stat().st_size)


@r.delete('/{set_id}')
def delete_set(set_id: str, u=Depends(require_write('HASHSET_MANAGE'))):
    from ..tasks import _rematch_all
    db = get_db()
    doc = db['hash_sets'].find_one({'set_id': set_id})
    if not doc:
        raise HTTPException(404, 'Hash set not found')
    if doc.get('status') == 'IMPORTING':
        raise HTTPException(409, 'The set is still being imported')
    store_path(set_id).unlink(missing_ok=True)
    if doc.get('source_uploaded'):
        Path(doc.get('source_path') or '').unlink(missing_ok=True)
    db['hash_sets'].delete_one({'set_id': set_id})
    log(u, 'HASHSET_DELETED', 'hash_set', set_id, {'name': doc.get('name'), 'kind': doc.get('kind')})
    return {'deleted': True, 'rematch_jobs': _rematch_all(str(u['_id']))}
