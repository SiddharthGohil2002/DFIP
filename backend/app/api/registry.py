"""Registry activity of a case: user activity, execution traces, persistence and installed programs."""
import re

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.execution import merge
from ..forensic.modules.registry import TYPES
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics', tags=['registry'])
_SEARCH_FIELDS = ('program', 'path', 'value', 'command', 'name', 'server', 'remote_path', 'publisher', 'sha1', 'location')
_SORT = {'USERASSIST': ('last_run', -1), 'BAM_ENTRY': ('last_run', -1), 'SHELLBAG': ('key_path', 1),
         'AMCACHE_FILE': ('key_last_write', -1), 'SHIMCACHE_ENTRY': ('position', 1), 'INSTALLED_PROGRAM': ('name', 1),
         'PERSISTENCE': ('key_last_write', -1)}


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


@r.get('/registry')
def registry_rows(case_id: str, type: str, search: str | None = None, evidence_id: str | None = None, user: str | None = None,
                  flagged: bool = False, skip: int = 0, limit: int = 500, u=Depends(current_user)):
    """Registry records of one kind (USERASSIST, SHELLBAG, TYPED_PATH, TYPED_URL, EXPLORER_SEARCH, RECENT_DOC, RUN_MRU,
    PERSISTENCE, INSTALLED_PROGRAM, AMCACHE_FILE, SHIMCACHE_ENTRY, BAM_ENTRY, RDP_CONNECTION, NETWORK_DRIVE)."""
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    q = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'type': type}
    if user:
        q['user'] = user
    if flagged:
        q['flags.0'] = {'$exists': True}
    if search and search.strip():
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q['$or'] = [{f: rx} for f in _SEARCH_FIELDS]
    sort = _SORT.get(type, ('order', 1))
    col = get_db()['forensic_artifacts']
    rows = [_plain(x) for x in col.find(q).sort([('evidence_id', 1), ('user', 1), sort]).skip(max(0, skip)).limit(max(1, min(limit, 2000)))]
    return {'data': rows, 'total': col.count_documents(q)}


@r.get('/registry/hives')
def registry_hives(case_id: str, u=Depends(current_user)):
    """The hives each evidence item's registry analysis read: path, user, SHA-256, transaction logs and state."""
    eids = _eids(case_id, u)
    out = []
    for f in get_db()['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'evidence_id': 1, 'registry.hives': 1}):
        for h in (f.get('registry') or {}).get('hives') or []:
            out.append(dict({k: v for k, v in h.items() if k != 'local'}, evidence_id=f['evidence_id']))
    return {'data': out}


@r.get('/execution')
def execution(case_id: str, evidence_id: str | None = None, search: str | None = None, ran: bool | None = None, u=Depends(current_user)):
    """One row per program with every trace of it: Prefetch, UserAssist, BAM, Amcache and ShimCache."""
    eids = _eids(case_id, u, evidence_id)
    col = get_db()['forensic_artifacts']
    by_type = {t: list(col.find({'evidence_id': {'$in': eids}, 'type': t}, {'_id': 0}))
               for t in ('PROGRAM_RUN', 'USERASSIST', 'BAM_ENTRY', 'AMCACHE_FILE', 'SHIMCACHE_ENTRY')}
    for rows in by_type.values():
        for x in rows:
            for k, v in list(x.items()):
                if hasattr(v, 'isoformat'):
                    x[k] = v.isoformat()
    rows = merge(by_type['PROGRAM_RUN'], by_type['USERASSIST'], by_type['BAM_ENTRY'], by_type['AMCACHE_FILE'], by_type['SHIMCACHE_ENTRY'])
    if search and search.strip():
        s = search.strip().lower()
        rows = [x for x in rows if s in x['program'].lower() or any(s in p.lower() for p in x['paths']) or s == (x.get('sha1') or '')]
    if ran is not None:
        rows = [x for x in rows if x['ran'] == ran]
    return {'data': rows, 'total': len(rows)}
