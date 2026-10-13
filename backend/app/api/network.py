"""Network captures of a case (module `network`): the capture's span, conversations, DNS lookups, HTTP requests,
TLS server names, and the files HTTP carried."""
import re

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics/network', tags=['network captures'])
TYPES = {  # type: (sort, fields searched)
    'CAPTURE_INFO': ([('first', 1)], ('file_type',)),
    'NET_CONVERSATION': ([('bytes', -1), ('first', 1)], ('client', 'server', 'server_names', 'protocols')),
    'DNS_QUERY': ([('time', 1)], ('name', 'answers', 'client')),
    'HTTP_REQUEST': ([('time', 1)], ('host', 'url', 'uri', 'method', 'user_agent', 'client', 'files.name')),
    'TLS_HANDSHAKE': ([('time', 1)], ('server_name', 'server', 'client')),
}


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _search(q: dict, search: str | None, fields):
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q.setdefault('$and', []).append({'$or': [{f: rx} for f in fields]})


@r.get('')
def records(case_id: str, type: str, evidence_id: str | None = None, search: str | None = None, uploads: bool = False, host: str | None = None,
            skip: int = 0, limit: int = 200, u=Depends(current_user)):
    """Records of one type; `uploads=true` only HTTP requests that sent a file; `host` one host name or address."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    sort, fields = TYPES[type]
    q: dict = {'case_id': case_id, 'type': type, **({'evidence_id': evidence_id} if evidence_id else {})}
    if uploads:
        q['files'] = {'$elemMatch': {'direction': 'request', 'part': True}}
    if host:
        h = host.strip()[:300]
        q['$or'] = [{'host': h}, {'name': h}, {'server_name': h}, {'server': h}, {'client': h}, {'server_names': h}, {'answers': h}]
    _search(q, search, fields)
    col = get_db()['forensic_artifacts']
    rows = [dict(_plain(x), _id=str(x['_id'])) for x in col.find(q).sort(sort).skip(max(0, skip)).limit(max(1, min(limit, 1000)))]
    return {'data': rows, 'total': col.count_documents(q)}


@r.get('/files')
def files(case_id: str, evidence_id: str | None = None, search: str | None = None, skip: int = 0, limit: int = 200, u=Depends(current_user)):
    """The files HTTP carried in the case's captures (bodies and the files of multipart uploads), with their hashes and types."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    eids = [e['evidence_id'] for e in db['evidence'].find({'case_id': case_id, **({'evidence_id': evidence_id} if evidence_id else {})}, {'evidence_id': 1})]
    q: dict = {'evidence_id': {'$in': eids}, 'container.kind': 'capture'}
    _search(q, search, ('path', 'name', 'sha256', 'mime', 'magic'))
    proj = {'path': 1, 'name': 1, 'size': 1, 'mtime': 1, 'sha256': 1, 'md5': 1, 'mime': 1, 'magic': 1, 'file_category': 1, 'hash_status': 1, 'container': 1,
            'evidence_id': 1, 'volume_id': 1, 'inode': 1, 'encryption': 1, 'ext_mismatch': 1}
    col = db['fs_entries']
    rows = [dict(_plain(x), _id=str(x['_id'])) for x in col.find(q, proj).sort([('mtime', 1), ('path', 1)]).skip(max(0, skip)).limit(max(1, min(limit, 1000)))]
    return {'data': rows, 'total': col.count_documents(q)}
