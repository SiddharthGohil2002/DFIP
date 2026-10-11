"""NTFS internals of a case: files whose times look altered, alternate data streams and the USN change journal."""
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.ntfs import REASONS
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics/ntfs', tags=['ntfs'])
REASON_NAMES = [name for _, name in REASONS]


def _plain(doc):
    out = {k: v for k, v in doc.items() if k != '_id'}
    out['_id'] = str(doc['_id'])
    for k, v in list(out.items()):
        if hasattr(v, 'isoformat'):
            out[k] = v.isoformat()
    return out


def _eids(case_id, u, evidence_id=None):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id}
    if evidence_id:
        q['evidence_id'] = evidence_id
    return [e['evidence_id'] for e in get_db()['evidence'].find(q, {'evidence_id': 1})]


def _rx(search):
    if not search or not search.strip():
        return None
    if len(search) > 200:
        raise HTTPException(400, 'Search for at most 200 characters')
    return {'$regex': re.escape(search.strip()), '$options': 'i'}


def _page(col, q, sort, skip, limit):
    rows = [_plain(x) for x in get_db()[col].find(q).sort(sort).skip(max(0, skip)).limit(max(1, min(limit, 2000)))]
    return {'data': rows, 'total': get_db()[col].count_documents(q)}


@r.get('/volumes')
def volumes(case_id: str, u=Depends(current_user)):
    """The NTFS volumes read per evidence item: serial number, label, MFT entries and USN journal records."""
    out = []
    for f in get_db()['analysis_facts'].find({'evidence_id': {'$in': _eids(case_id, u)}}, {'evidence_id': 1, 'ntfs.volumes': 1}):
        out += [dict(v, evidence_id=f['evidence_id']) for v in (f.get('ntfs') or {}).get('volumes') or []]
    return {'data': out}


@r.get('/timestomp')
def timestomp(case_id: str, evidence_id: str | None = None, level: str | None = None, search: str | None = None,
              skip: int = 0, limit: int = 500, u=Depends(current_user)):
    """Files whose $STANDARD_INFORMATION times look altered: level strong (the pattern timestomping tools leave) or
    possible (an earlier, whole-second creation time in a user's folder)."""
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'type': 'TIMESTOMP_SUSPECT'}
    if level:
        if level not in ('strong', 'possible'):
            raise HTTPException(400, 'level must be strong or possible')
        q['level'] = level
    if (rx := _rx(search)):
        q['path'] = rx
    return _page('forensic_artifacts', q, [('level', -1), ('fn_created', -1)], skip, limit)


@r.get('/streams')
def streams(case_id: str, evidence_id: str | None = None, downloaded: bool | None = None, search: str | None = None,
            skip: int = 0, limit: int = 500, u=Depends(current_user)):
    """Alternate data streams; downloaded=true lists only Zone.Identifier streams (the Mark of the Web)."""
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'type': 'ALTERNATE_STREAM'}
    if downloaded is not None:
        q['zone'] = {'$exists': downloaded}
    if (rx := _rx(search)):
        q['$or'] = [{'path': rx}, {'zone.HostUrl': rx}, {'zone.ReferrerUrl': rx}, {'text': rx}]
    return _page('forensic_artifacts', q, [('path', 1)], skip, limit)


@r.get('/usn')
def usn(case_id: str, evidence_id: str | None = None, search: str | None = None, reason: str | None = None,
        entry: int | None = None, start: str | None = None, end: str | None = None, closing: bool = False,
        order: str = 'asc', skip: int = 0, limit: int = 500, u=Depends(current_user)):
    """USN change journal records, in journal order (order=desc for newest first). reason takes a reason name such as
    FILE_DELETE; closing=true lists only each change's closing record (the one that holds all of its reasons)."""
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}}
    if reason:
        if reason not in REASON_NAMES:
            raise HTTPException(400, f'reason must be one of {", ".join(REASON_NAMES)}')
        q['reasons'] = reason
    if closing:
        q.setdefault('$and', []).append({'reasons': 'CLOSE'})
    if entry is not None:
        q['entry'] = entry
    if (rx := _rx(search)):
        q['$or'] = [{'name': rx}, {'path': rx}]
    window = {}
    for key, value in (('$gte', start), ('$lte', end)):
        if value:
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(400, 'start and end must be ISO 8601 dates and times')
            window[key] = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if window:
        q['time'] = window
    if order not in ('asc', 'desc'):
        raise HTTPException(400, 'order must be asc or desc')
    d = 1 if order == 'asc' else -1
    return _page('usn_records', q, [('evidence_id', 1), ('volume_id', 1), ('usn', d)], skip, limit)
