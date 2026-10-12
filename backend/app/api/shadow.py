"""Volume Shadow Copies of a case: the snapshots, what changed since each, browsing a snapshot, reading a file in
it (hex, preview, render), and recovering the old version (with its hash and a custody record)."""
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..core.config import settings
from ..database import get_db
from ..forensic.disk_formats import ensure_space
from ..forensic.filesystem import INODE_RE
from ..forensic.hashing import sha256_file
from ..forensic.source import BlobRef, TskImageSource, parse_volume
from ..forensic.vss import CHANGES
from ..repositories.cases import get_case
from ..security import current_user, require_permission, require_write
from ..services.audit import log
from ..websocket.manager import manager
from .forensics import _page, _preview, _raw, auth_evidence, serial, tsk_image

r = APIRouter(prefix='/forensics/shadow-copies', tags=['shadow copies'])


def _case_evidence(case_id: str, u, evidence_id: str | None = None) -> list[dict]:
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id, **({'evidence_id': evidence_id} if evidence_id else {})}
    return list(get_db()['evidence'].find(q, {'evidence_id': 1, 'filename': 1}))


@r.get('/stores')
def stores(case_id: str, u=Depends(current_user)):
    """Every shadow copy of every evidence item of the case: volume, number, identifiers, when it was made, and how
    many files were deleted, changed and added since."""
    evidence = {e['evidence_id']: e for e in _case_evidence(case_id, u)}
    out = []
    for f in get_db()['analysis_facts'].find({'evidence_id': {'$in': list(evidence)}}, {'evidence_id': 1, 'shadow_copies': 1}):
        for s in (f.get('shadow_copies') or {}).get('stores') or []:
            out.append(dict(s, evidence_id=f['evidence_id'], filename=evidence[f['evidence_id']].get('filename')))
    out.sort(key=lambda s: (s['evidence_id'], s['parent_volume_id'], s['store']))
    return {'data': serial(out)}


@r.get('')
def files(case_id: str, evidence_id: str | None = None, volume_id: str | None = None, change: str | None = None,
          search: str | None = None, files_only: bool = False, skip: int = 0, limit: int = 100, u=Depends(current_user)):
    """Files and folders that differ between a shadow copy and the volume now: `change` DELETED_SINCE, CHANGED_SINCE or
    ADDED_SINCE; `volume_id` one shadow copy (p2048/vss1); `search` part of the path."""
    evidence = _case_evidence(case_id, u, evidence_id)
    q: dict = {'evidence_id': {'$in': [e['evidence_id'] for e in evidence]}}
    if volume_id:
        q['volume_id'] = volume_id
    if change:
        if change not in CHANGES:
            raise HTTPException(400, f'change must be one of {", ".join(CHANGES)}')
        q['change'] = change
    if files_only:
        q['is_dir'] = False
    if search and search.strip():
        if len(search) > 300:
            raise HTTPException(400, 'Search for at most 300 characters')
        q['path'] = {'$regex': re.escape(search.strip()), '$options': 'i'}
    col = get_db()['shadow_files']
    rows = [serial(dict(x, _id=str(x['_id']))) for x in col.find(q).sort([('evidence_id', 1), ('volume_id', 1), ('change', 1), ('path', 1)])
            .skip(max(0, skip)).limit(max(1, min(limit, 500)))]
    counts = {c['_id']: c['n'] for c in col.aggregate([{'$match': {k: v for k, v in q.items() if k != 'change'}},
                                                      {'$group': {'_id': '$change', 'n': {'$sum': 1}}}])}
    return {'data': rows, 'total': col.count_documents(q), 'counts': counts}


def _shadow(eid: str, volume_id: str, u):
    e = auth_evidence(eid, u)
    try:
        _, store = parse_volume(volume_id)
    except ValueError:
        store = None
    if store is None:
        raise HTTPException(400, 'volume_id must name a shadow copy, such as p2048/vss1')
    facts = get_db()['analysis_facts'].find_one({'evidence_id': e['evidence_id']}, {'shadow_copies': 1}) or {}
    info = next((s for s in (facts.get('shadow_copies') or {}).get('stores') or [] if s.get('volume_id') == volume_id), None)
    if not info:
        raise HTTPException(404, f'{e["evidence_id"]} has no shadow copy {volume_id} (run the analysis first)')
    return e, info, TskImageSource(tsk_image(e))


@r.get('/browse')
def browse(evidence_id: str, volume_id: str, path: str = '/', u=Depends(require_permission('EVIDENCE_READ'))):
    """One folder of a shadow copy as it was when the copy was made."""
    import pytsk3
    e, info, src = _shadow(evidence_id, volume_id, u)
    if len(path) > 4096 or not path.startswith('/'):
        raise HTTPException(400, 'path must start with /')
    try:
        directory = src._filesystem(volume_id).open_dir(path=path)
    except OSError:
        raise HTTPException(404, f'{path} is not a folder in shadow copy {info["store"]}')
    rows = []
    for entry in directory:
        name = entry.info.name.name
        name = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else str(name)
        meta = entry.info.meta
        if name in ('.', '..') or meta is None or meta.type in (pytsk3.TSK_FS_META_TYPE_VIRT, pytsk3.TSK_FS_META_TYPE_VIRT_DIR):
            continue  # Sleuth Kit's own entries ($OrphanFiles) are not in the file system
        rows.append({'name': name, 'path': (path.rstrip('/') + '/' + name), 'inode': str(meta.addr), 'size': int(meta.size or 0),
                     'is_dir': meta.type == pytsk3.TSK_FS_META_TYPE_DIR,
                     'deleted': bool(int(entry.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC)),
                     'mtime': datetime.fromtimestamp(meta.mtime, timezone.utc).isoformat() if meta.mtime else None})
    rows.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    return {'evidence_id': e['evidence_id'], 'volume_id': volume_id, 'store': serial(info), 'path': path, 'data': rows}


def _snapshot_file(evidence_id: str, volume_id: str, inode: str, u):
    if not INODE_RE.match(inode or ''):
        raise HTTPException(400, 'Invalid inode address')
    e, info, src = _shadow(evidence_id, volume_id, u)
    try:
        blob = src.open(BlobRef(e['evidence_id'], volume_id, inode=inode))
    except (OSError, ValueError):
        raise HTTPException(404, f'No file {inode} in shadow copy {info["store"]}')
    rec = get_db()['shadow_files'].find_one({'evidence_id': e['evidence_id'], 'volume_id': volume_id, 'inode': inode}, {'path': 1})
    path = (rec or {}).get('path') or f'inode {inode}'
    meta = {'evidence_id': e['evidence_id'], 'volume_id': volume_id, 'inode': inode, 'path': path, 'shadow_copy': info['store']}
    return e, f'{path} (shadow copy {info["store"]})', blob.size, blob.read, meta


@r.get('/content')
def content(evidence_id: str, volume_id: str, inode: str, start: int = 0, length: int = 4096,
            u=Depends(require_permission('EVIDENCE_READ'))):
    return _page(_snapshot_file(evidence_id, volume_id, inode, u), start, length, u, 'evidence')


@r.get('/preview')
def preview(evidence_id: str, volume_id: str, inode: str, u=Depends(require_permission('EVIDENCE_READ'))):
    return _preview(_snapshot_file(evidence_id, volume_id, inode, u), u, 'evidence')


@r.get('/raw')
def raw(evidence_id: str, volume_id: str, inode: str, u=Depends(require_permission('EVIDENCE_READ'))):
    return _raw(_snapshot_file(evidence_id, volume_id, inode, u), u, 'evidence')


class RecoverIn(BaseModel):
    evidence_id: str
    volume_id: str
    inode: str
    path: str | None = None


@r.post('/recover')
def recover(body: RecoverIn, u=Depends(require_write('ANALYSIS_RUN'))):
    """Copies a file out of a shadow copy, as it was when the copy was made, with its SHA-256 and a custody record."""
    e, title, size, read, meta = _snapshot_file(body.evidence_id, body.volume_id, body.inode, u)
    store = meta['shadow_copy']
    original = meta['path'] if not meta['path'].startswith('inode ') else (body.path or meta['path'])
    name = Path(original).name if '/' in original else f'inode-{body.inode}.bin'
    aid = str(uuid.uuid4())
    dest = Path(settings.storage_path).resolve() / 'analysis' / 'recovered' / e['evidence_id'] / aid / name
    try:
        ensure_space(dest.parent, size, 'the recovered file')
    except ValueError as exc:
        raise HTTPException(507, str(exc))
    with dest.open('wb') as out:
        for pos in range(0, size, 1 << 20):
            out.write(read(pos, min(1 << 20, size - pos)))
    digest = sha256_file(dest)
    dest.chmod(0o440)
    now = datetime.now(timezone.utc)
    facts = get_db()['analysis_facts'].find_one({'evidence_id': e['evidence_id']}, {'shadow_copies': 1}) or {}
    info = next(s for s in facts['shadow_copies']['stores'] if s.get('volume_id') == body.volume_id)
    doc = {'artifact_id': aid, 'case_id': e['case_id'], 'evidence_id': e['evidence_id'], 'type': 'RECOVERED_FILE', 'timestamp': now,
           'path': str(dest), 'filename': name, 'original_path': original, 'was_deleted': False, 'inode': body.inode,
           'volume_id': body.volume_id, 'offset': info.get('partition_offset'), 'size': size, 'sha256': digest, 'source': 'VSS',
           'shadow_copy': {'store': store, 'identifier': info.get('identifier'), 'created': info.get('created')}}
    db = get_db()
    db['forensic_artifacts'].insert_one(doc)
    log(u, 'FILE_RECOVERED', 'evidence', e['_id'], {'artifact_id': aid, 'inode': body.inode, 'volume_id': body.volume_id,
                                                     'original_path': original, 'sha256': digest})
    db['chain_of_custody'].insert_one({'evidence_id': e['evidence_id'], 'case_id': e['case_id'], 'timestamp': now, 'user_id': str(u['_id']),
                                       'user_name': u.get('name'), 'action': 'FILE_RECOVERED', 'artifact_id': aid, 'original_path': original,
                                       'inode': body.inode, 'volume_id': body.volume_id, 'sha256': digest,
                                       'detail': f'As it was in shadow copy {store} ({info.get("identifier")})'})
    manager.emit_sync('ARTIFACT_CREATED', {'artifact_id': aid, 'case_id': e['case_id'], 'type': 'RECOVERED_FILE', 'filename': name})
    return serial({'status': 'COMPLETED', 'artifact_id': aid, 'size': size, 'sha256': digest, 'filename': name, 'original_path': original,
                   'volume_id': body.volume_id, 'shadow_copy': store})
