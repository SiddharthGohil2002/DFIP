"""Jump Lists, the Windows Timeline, thumbnails, SRUM and the Windows Search index of a case."""
import re

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.modules.user_activity import TYPES
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics', tags=['user activity'])
_SEARCH = {
    'JUMPLIST_ENTRY': ('target', 'destlist_path', 'application', 'app_id', 'lnk.arguments', 'category'),
    'TIMELINE_ACTIVITY': ('app', 'app_display_name', 'display_text', 'description', 'content_uri', 'clipboard_text'),
    'THUMBNAIL': ('entry_hash', 'indexed_path', 'source_path'),
    'SRUM_NETWORK': ('app', 'user', 'sid'), 'SRUM_APP_USAGE': ('app', 'user', 'sid'), 'SRUM_CONNECTIVITY': ('app', 'user', 'sid'),
    'SEARCH_INDEX_ENTRY': ('path', 'name', 'owner', 'summary', 'kind'),
}
_SORT = {'JUMPLIST_ENTRY': [('last_used', -1), ('source_path', 1)], 'TIMELINE_ACTIVITY': [('start_time', -1)],
         'THUMBNAIL': [('source_path', 1), ('offset', 1)], 'SRUM_NETWORK': [('time', -1)], 'SRUM_APP_USAGE': [('time', -1)],
         'SRUM_CONNECTIVITY': [('time', -1)], 'SEARCH_INDEX_ENTRY': [('path', 1)]}
FILE_STATES = ('on disk', 'deleted', 'not on the disk')


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


@r.get('/user-activity')
def rows(case_id: str, type: str, search: str | None = None, user: str | None = None, evidence_id: str | None = None,
         file_state: str | None = None, skip: int = 0, limit: int = 500, u=Depends(current_user)):
    """Records of one kind: JUMPLIST_ENTRY, TIMELINE_ACTIVITY, THUMBNAIL, SRUM_NETWORK, SRUM_APP_USAGE, SRUM_CONNECTIVITY,
    SEARCH_INDEX_ENTRY. file_state (search index entries and thumbnails): on disk, deleted or not on the disk."""
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'type': type}
    if user:
        q['user'] = user
    if file_state:
        if file_state not in FILE_STATES:
            raise HTTPException(400, f'file_state must be one of {", ".join(FILE_STATES)}')
        q['indexed_file_state' if type == 'THUMBNAIL' else 'file_state'] = file_state
    if search and search.strip():
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q['$or'] = [{f: rx} for f in _SEARCH[type]]
    col = get_db()['forensic_artifacts']
    data = [_plain(x) for x in col.find(q, {'app_platforms': 0}).sort(_SORT[type]).skip(max(0, skip)).limit(max(1, min(limit, 2000)))]
    return {'data': data, 'total': col.count_documents(q)}


@r.get('/user-activity/network')
def network(case_id: str, evidence_id: str | None = None, u=Depends(current_user)):
    """SRUM network usage per application and user: bytes sent and received, the hours recorded, first and last."""
    q = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'type': 'SRUM_NETWORK'}
    rows_ = get_db()['forensic_artifacts'].aggregate([
        {'$match': q},
        {'$group': {'_id': {'evidence_id': '$evidence_id', 'app': '$app', 'user': '$user', 'sid': '$sid'},
                    'bytes_sent': {'$sum': '$bytes_sent'}, 'bytes_received': {'$sum': '$bytes_received'},
                    'records': {'$sum': 1}, 'first': {'$min': '$time'}, 'last': {'$max': '$time'},
                    'interfaces': {'$addToSet': '$interface_type'}}},
        {'$sort': {'bytes_sent': -1}}, {'$limit': 500}])
    out = []
    for x in rows_:
        out.append({**x['_id'], 'bytes_sent': x['bytes_sent'], 'bytes_received': x['bytes_received'], 'records': x['records'],
                    'first': x['first'].isoformat() if x.get('first') else None, 'last': x['last'].isoformat() if x.get('last') else None,
                    'interfaces': sorted(i for i in x['interfaces'] if i)})
    return {'data': out}


@r.get('/user-activity/files')
def files(case_id: str, u=Depends(current_user)):
    """The Jump List, Timeline, thumbnail cache, SRUM and search index files read, with their SHA-256."""
    eids = _eids(case_id, u)
    out = []
    for f in get_db()['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'evidence_id': 1, 'user_activity.files': 1}):
        out += [dict(x, evidence_id=f['evidence_id']) for x in (f.get('user_activity') or {}).get('files') or []]
    return {'data': out}
