"""Pictures and videos of a case: the gallery, cameras, the places pictures were taken, one item's details, and thumbnails.

Thumbnails and keyframes are served as JPEGs DFIP wrote itself (never the evidence's own bytes), with nosniff, attachment and a
sandbox CSP, and every one served is recorded in the audit log as a view of evidence content.
"""
import re

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from ..database import get_db
from ..forensic.modules.media import media_root
from ..repositories.cases import get_case
from ..security import current_user, require_permission
from ..services.audit import log

r = APIRouter(prefix='/forensics/media', tags=['pictures and videos'])
FIELDS = {'path': 1, 'name': 1, 'size': 1, 'deleted': 1, 'inode': 1, 'volume_id': 1, 'partition_offset': 1, 'evidence_id': 1,
          'case_id': 1, 'sha256': 1, 'mime': 1, 'hash_status': 1, 'container.kind': 1, 'container.parent': 1, 'media': 1,
          'ocr.chars': 1, 'ocr.pages': 1}
THUMB = re.compile(r'^[0-9a-f]{64}(-(scene|at)-\d{2})?\.jpg$')
SOURCES = {'disk': {'container': {'$exists': False}}, 'archive': {'container': {'$exists': True}, 'container.kind': {'$nin': ['email', 'capture']}},
           'email': {'container.kind': 'email'}, 'capture': {'container.kind': 'capture'}}


def _plain(doc):
    def conv(v):
        if hasattr(v, 'isoformat'):
            return v.isoformat()
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [conv(x) for x in v]
        return v
    out = conv({k: v for k, v in doc.items() if k != '_id'})
    out['_id'] = str(doc['_id'])
    return out


def _eids(case_id, u, evidence_id=None):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id}
    if evidence_id:
        q['evidence_id'] = evidence_id
    return [e['evidence_id'] for e in get_db()['evidence'].find(q, {'evidence_id': 1})]


@r.get('')
def gallery(case_id: str, evidence_id: str | None = None, kind: str | None = None, gps: bool | None = None, camera: str | None = None,
            deleted: bool | None = None, source: str | None = None, text: bool | None = None, search: str | None = None,
            skip: int = 0, limit: int = 60, u=Depends(current_user)):
    """Pictures and videos: kind picture or video, gps=true for those with a location, camera (as shown), deleted, source (disk,
    archive or email), search in the path. text=true lists the files with text read by OCR instead: pictures, and scanned PDFs
    (which have no `media`). Newest taken first."""
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}}
    if text:
        q['ocr.text'] = {'$exists': True}
    else:
        q['media'] = {'$exists': True}
        if text is False:
            q['ocr.text'] = {'$exists': False}
    if kind:
        if kind not in ('picture', 'video'):
            raise HTTPException(400, 'kind must be picture or video')
        q['media.kind'] = kind
    if gps is not None:
        q['media.gps'] = {'$exists': gps}
    if camera:
        q['media.camera'] = camera
    if deleted is not None:
        q['deleted'] = deleted
    if source:
        if source not in SOURCES:
            raise HTTPException(400, f'source must be one of {", ".join(SOURCES)}')
        q.update(SOURCES[source])
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        q['path'] = {'$regex': re.escape(search.strip()), '$options': 'i'}
    col = get_db()['fs_entries']
    data = [_plain(x) for x in col.find(q, FIELDS).sort([('media.taken', -1), ('path', 1)]).skip(max(0, skip)).limit(max(1, min(limit, 500)))]
    return {'data': data, 'total': col.count_documents(q)}


@r.get('/cameras')
def cameras(case_id: str, u=Depends(current_user)):
    """The cameras (make and model) of the pictures and videos, with how many each took and the first and last time."""
    rows = get_db()['fs_entries'].aggregate([
        {'$match': {'evidence_id': {'$in': _eids(case_id, u)}, 'media.camera': {'$ne': None, '$exists': True}}},
        {'$group': {'_id': '$media.camera', 'items': {'$sum': 1}, 'first': {'$min': '$media.taken'}, 'last': {'$max': '$media.taken'}}},
        {'$sort': {'items': -1}}, {'$limit': 500}])
    return {'data': [{'camera': x['_id'], 'items': x['items'], 'first': x['first'].isoformat() if x.get('first') else None,
                      'last': x['last'].isoformat() if x.get('last') else None} for x in rows]}


@r.get('/locations')
def locations(case_id: str, evidence_id: str | None = None, u=Depends(current_user)):
    """Every picture and video with a GPS location: where, when and with which camera."""
    q = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'media.gps': {'$exists': True}}
    out = []
    for x in get_db()['fs_entries'].find(q, {'path': 1, 'deleted': 1, 'evidence_id': 1, 'media.gps': 1, 'media.taken': 1, 'media.camera': 1,
                                             'media.kind': 1}).limit(10_000):
        m = x['media']
        out.append({'_id': str(x['_id']), 'evidence_id': x['evidence_id'], 'path': x['path'], 'deleted': bool(x.get('deleted')), 'kind': m.get('kind'),
                    'lat': m['gps']['lat'], 'lon': m['gps']['lon'], 'alt': m['gps'].get('alt'), 'camera': m.get('camera'),
                    'taken': m['taken'].isoformat() if m.get('taken') else None})
    return {'data': out}


def _entry(entry_id, u, projection=None):
    doc = get_db()['fs_entries'].find_one({'_id': ObjectId(entry_id)}, projection) if ObjectId.is_valid(entry_id) else None
    if not doc or not (doc.get('media') or doc.get('ocr')) or not get_case(doc['case_id'], u):
        raise HTTPException(404, 'Picture or video not found or access denied')
    return doc


@r.get('/{entry_id}')
def item(entry_id: str, u=Depends(current_user)):
    """One picture or video: all its metadata, keyframes and the full text OCR read in it."""
    return _plain(_entry(entry_id, u, {**{k: v for k, v in FIELDS.items() if not k.startswith('ocr.')}, 'ocr': 1}))


@r.get('/{entry_id}/thumb')
def thumb(entry_id: str, frame: int | None = None, u=Depends(require_permission('EVIDENCE_READ'))):
    """The thumbnail (or a video's keyframe number `frame`, from 0) as a JPEG."""
    doc = _entry(entry_id, u)
    m = doc.get('media') or {}
    if frame is None:
        name = m.get('thumb')
    else:
        frames = m.get('frames') or []
        if not 0 <= frame < len(frames):
            raise HTTPException(404, 'No such keyframe')
        name = frames[frame]['file']
    if not name or not THUMB.match(name):
        raise HTTPException(404, 'No thumbnail for this item')
    root = (media_root() / doc['evidence_id']).resolve()
    p = (root / name).resolve()
    if root not in p.parents or not p.is_file():
        raise HTTPException(410, 'The thumbnail is no longer stored; run Pictures and videos again')
    log(u, 'FILE_CONTENT_VIEWED', 'evidence', doc['evidence_id'], {'evidence_id': doc['evidence_id'], 'path': doc['path'],
                                                                    'view': 'thumbnail' if frame is None else f'keyframe {frame}'})
    return Response(content=p.read_bytes(), media_type='image/jpeg', headers={
        'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment', 'Content-Security-Policy': "sandbox; default-src 'none'",
        'Cache-Control': 'no-store'})
