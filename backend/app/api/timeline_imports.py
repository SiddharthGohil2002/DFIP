"""Timelines made by Plaso, imported into a case: uploaded (json_line or l2tcsv), kept read-only with their SHA-256,
and their events added to the case timeline as PLASO_EVENT (with Plaso's parser and description). Deleting an
import removes its events."""
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from ..core.config import settings
from ..database import get_db
from ..forensic.plaso_import import TimelineError, detect
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from ..services.sequences import next_sequence
from ..websocket.manager import manager

r = APIRouter(prefix='/cases', tags=['timeline imports'])
_SAFE = re.compile(r'[^A-Za-z0-9._ -]+')


def imports_dir() -> Path:
    return Path(settings.storage_path).resolve() / 'imports'


def _plain(doc):
    out = {}
    for k, v in doc.items():
        if k == '_id':
            continue
        out[k] = v.isoformat() if hasattr(v, 'isoformat') else v
    return out


@r.get('/{case_id}/timeline-imports')
def list_imports(case_id: str, u=Depends(current_user)):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    rows = get_db()['timeline_imports'].find({'case_id': case_id}, {'path': 0}).sort('created_at', -1)
    return {'data': [_plain(x) for x in rows]}


@r.post('/{case_id}/timeline-imports')
async def add_import(case_id: str, file: UploadFile = File(...), evidence_id: str | None = Form(None),
                     u=Depends(require_write('ANALYSIS_RUN'))):
    """Imports a Plaso timeline (psort -o json_line or -o l2tcsv). `evidence_id` names the evidence it was made from."""
    import hashlib
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    if evidence_id and not db['evidence'].find_one({'evidence_id': evidence_id, 'case_id': case_id}):
        raise HTTPException(400, f'{evidence_id} is not evidence of {case_id}')
    import_id = f'TI-{next_sequence("timeline_imports", floor=db["timeline_imports"].count_documents({})):04d}'
    name = _SAFE.sub('_', Path((file.filename or 'timeline').replace('\\', '/')).name)[:120] or 'timeline'
    folder = imports_dir() / case_id
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f'{import_id}-{name}'
    # A new import ID has no file yet: one already there was left by an earlier database (storage/ outlives a reset
    # of the database, which starts the IDs again), and would make the exclusive create below fail.
    if target.exists():
        target.chmod(0o600)
        target.unlink()
    h, size = hashlib.sha256(), 0
    try:
        with target.open('xb') as out:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(413, f'File exceeds configured limit of {settings.max_upload_bytes} bytes')
                h.update(chunk)
                out.write(chunk)
        fmt = detect(target)
    except TimelineError as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(400, str(exc))
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    target.chmod(0o444)
    now = datetime.now(timezone.utc)
    doc = {'import_id': import_id, 'case_id': case_id, 'evidence_id': evidence_id, 'filename': name, 'path': str(target), 'size': size,
           'sha256': h.hexdigest(), 'format': fmt, 'tool': 'Plaso', 'status': 'QUEUED', 'created_by': str(u['_id']),
           'created_by_name': u.get('name'), 'created_at': now}
    db['timeline_imports'].insert_one(doc)
    log(u, 'TIMELINE_IMPORTED', 'case', case_id, {'import_id': import_id, 'filename': name, 'sha256': doc['sha256'], 'format': fmt,
                                                  'evidence_id': evidence_id})
    from ..services.jobs import queue
    job_id = queue.enqueue('TIMELINE_IMPORT', {'case_id': case_id, 'import_id': import_id, 'evidence_id': evidence_id}, u['_id'])
    db['timeline_imports'].update_one({'import_id': import_id}, {'$set': {'job_id': job_id}})
    manager.emit_sync('JOB_CREATED', {'job_id': job_id, 'type': 'TIMELINE_IMPORT', 'case_id': case_id, 'status': 'QUEUED'})
    return _plain(dict(doc, job_id=job_id, path=None))


@r.delete('/{case_id}/timeline-imports/{import_id}')
def delete_import(case_id: str, import_id: str, u=Depends(require_write('ANALYSIS_RUN'))):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    doc = db['timeline_imports'].find_one({'case_id': case_id, 'import_id': import_id})
    if not doc:
        raise HTTPException(404, 'No such import')
    if doc.get('status') in ('QUEUED', 'RUNNING'):
        raise HTTPException(409, 'The import is still running')
    removed = remove_import(db, doc)
    log(u, 'TIMELINE_IMPORT_DELETED', 'case', case_id, {'import_id': import_id, 'events_removed': removed})
    return {'deleted': import_id, 'events_removed': removed}


def remove_import(db, doc) -> int:
    """Deletes an import's events (and tags on them), its stored file and its record."""
    batch = []
    for x in db['timeline_events'].find({'import_id': doc['import_id']}, {'_id': 1}):
        batch.append(str(x['_id']))
        if len(batch) >= 5000:
            db['tags'].delete_many({'item_type': 'TIMELINE_EVENT', 'item_id': {'$in': batch}})
            batch = []
    db['tags'].delete_many({'item_type': 'TIMELINE_EVENT', 'item_id': {'$in': batch}})
    removed = db['timeline_events'].delete_many({'import_id': doc['import_id']}).deleted_count
    p = Path(doc.get('path') or '')
    if p.is_file() and imports_dir() in p.resolve().parents:
        p.unlink()
    db['timeline_imports'].delete_one({'_id': doc['_id']})
    return removed
