"""Content search (inside files) and found data (identifiers recognised in file contents).

Both need the Full analysis profile (modules `content` and `found_data`). Every content search is recorded in
the audit log; card and Aadhaar numbers are listed masked, and showing one in full is recorded too.
"""
import re
import time
from pathlib import Path

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.found_data import KINDS, LABELS
from ..forensic.source import offset_of
from ..forensic.text_index import SEARCH_SECONDS, QueryError, index_path, search, unallocated_index_path
from ..repositories.cases import get_case
from ..security import current_user
from ..services.audit import log

r = APIRouter(prefix='/forensics', tags=['content'])
MODES = ('text', 'regex')


def _case_evidence(case_id: str, u, evidence_id: str | None = None) -> list[dict]:
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    q = {'case_id': case_id}
    if evidence_id:
        q['evidence_id'] = evidence_id
    return list(get_db()['evidence'].find(q, {'evidence_id': 1, 'filename': 1, 'modules': 1}).sort('created_at', 1))


def _offset(volume_id):
    try:
        return offset_of(volume_id or 'p0')
    except ValueError:
        return None


@r.get('/content-search')
def content_search(case_id: str, q: str, mode: str = 'text', evidence_id: str | None = None, skip: int = 0, limit: int = 50,
                   u=Depends(current_user)):
    """Files whose text contains `q` (mode=text: case-insensitive, at least 3 characters) or matches the RE2 regular
    expression `q` (mode=regex), with their first matches, snippets and byte offsets."""
    evidence = _case_evidence(case_id, u, evidence_id)
    if mode not in MODES:
        raise HTTPException(400, 'mode must be text or regex')
    term = q.strip() if mode == 'text' else q
    if mode == 'text' and not 3 <= len(term) <= 500:
        raise HTTPException(400, 'Give 3 to 500 characters to search for (content search matches parts of words)')
    db = get_db()
    t0 = time.monotonic()
    deadline = t0 + SEARCH_SECONDS
    hits, complete, not_indexed = [], True, []
    for e in evidence:
        mods = e.get('modules') or {}
        # The files' index, and the unallocated space's when it was read.
        indexes = [p for name, p in (('content', index_path(e['evidence_id'])), ('unallocated', unallocated_index_path(e['evidence_id'])))
                   if (mods.get(name) or {}).get('status') == 'COMPLETED' and Path(p).is_file()]
        if not any(str(p) == str(index_path(e['evidence_id'])) for p in indexes):
            not_indexed.append({'evidence_id': e['evidence_id'], 'filename': e.get('filename')})
        for path in indexes:
            try:
                found, done = search(path, term, mode, deadline)
            except QueryError as exc:
                raise HTTPException(400, str(exc))
            complete &= done
            for h in found:
                h['evidence_id'] = e['evidence_id']
                h['partition_offset'] = _offset(h.get('volume_id'))
                h['unallocated'] = h.get('method') == 'unallocated'
                hits.append(h)
        if time.monotonic() > deadline:
            complete = False
            break
    page = hits[max(0, skip):max(0, skip) + max(1, min(limit, 200))]
    for h in page:  # the current file-index record (file or archive member), for details, tags and the viewer
        entry = None if h['unallocated'] else db['fs_entries'].find_one(
            {'evidence_id': h['evidence_id'], 'volume_id': h['volume_id'], 'inode': h['inode'], 'path': h['path']}, {'_id': 1})
        h['entry_id'] = str(entry['_id']) if entry else None
    result = {'query': term, 'mode': mode, 'total_files': len(hits), 'total_matches': sum(h['match_count'] for h in hits),
              'complete': complete, 'files': page, 'not_indexed': not_indexed, 'elapsed_ms': int((time.monotonic() - t0) * 1000),
              'skip': skip, 'limit': limit}
    log(u, 'CONTENT_SEARCHED', 'case', case_id, {'query': term[:200], 'mode': mode, 'files': len(hits), 'complete': complete})
    return result


def _public(doc: dict, occurrences: bool = False) -> dict:
    out = {k: v for k, v in doc.items() if k not in ('_id', 'occurrences', 'pipeline', 'pipeline_module', 'module_run_id',
                                                     'analysis_job_id')}
    out['_id'] = str(doc['_id'])
    out['label'] = LABELS.get(doc.get('kind'))
    if doc.get('sensitive'):
        out.pop('value', None)
    occ = doc.get('occurrences') or []
    out['first'] = occ[0]['path'] if occ else None
    if occurrences:
        out['occurrences'] = []
        for o in occ:
            o = dict(o, partition_offset=_offset(o.get('volume_id')))
            if o.get('member'):  # an archive member is viewed by its file-index record
                entry = get_db()['fs_entries'].find_one({'evidence_id': doc['evidence_id'], 'path': o['path']}, {'_id': 1})
                o['entry_id'] = str(entry['_id']) if entry else None
            out['occurrences'].append(o)
    return out


@r.get('/entities')
def entities(case_id: str, kind: str | None = None, q: str | None = None, evidence_id: str | None = None, skip: int = 0,
             limit: int = 100, u=Depends(current_user)):
    """Found data of the case: one row per value per evidence item, most frequent first, and the count per kind."""
    evidence = _case_evidence(case_id, u, evidence_id)
    eids = [e['evidence_id'] for e in evidence]
    if kind and kind not in KINDS:
        raise HTTPException(400, f'kind must be one of {", ".join(KINDS)}')
    col = get_db()['entities']
    base = {'evidence_id': {'$in': eids}}
    query = dict(base)
    if kind:
        query['kind'] = kind
    if q and q.strip():
        rx = {'$regex': re.escape(q.strip()), '$options': 'i'}
        # Masked values are searched by what is shown (for example the last four digits), never the full number.
        query['$or'] = [{'display': rx}, {'value': rx, 'sensitive': False}]
    kinds = {k['_id']: k['n'] for k in col.aggregate([{'$match': base}, {'$group': {'_id': '$kind', 'n': {'$sum': 1}}}])}
    rows = [_public(d) for d in col.find(query).sort([('kind', 1), ('count', -1), ('value', 1)]).skip(max(0, skip))
            .limit(max(1, min(limit, 500)))]
    indexed = [e['evidence_id'] for e in evidence if ((e.get('modules') or {}).get('found_data') or {}).get('status') == 'COMPLETED']
    return {'data': rows, 'total': col.count_documents(query), 'kinds': {k: kinds.get(k, 0) for k in KINDS},
            'labels': LABELS, 'analysed': indexed, 'not_analysed': [e for e in eids if e not in indexed]}


def _entity(entity_id: str, u) -> dict:
    doc = get_db()['entities'].find_one({'_id': ObjectId(entity_id)}) if ObjectId.is_valid(entity_id) else None
    if not doc or not get_case(doc['case_id'], u):
        raise HTTPException(404, 'Not found or access denied')
    return doc


@r.get('/entities/{entity_id}')
def entity(entity_id: str, u=Depends(current_user)):
    """One found value with where it occurs (file, byte offset when the text is stored in the file as such)."""
    return _public(_entity(entity_id, u), occurrences=True)


@r.post('/entities/{entity_id}/reveal')
def reveal(entity_id: str, u=Depends(current_user)):
    """The full value of a masked card or Aadhaar number; recorded in the audit log."""
    doc = _entity(entity_id, u)
    if doc.get('sensitive'):
        log(u, 'SENSITIVE_VALUE_REVEALED', 'entity', entity_id, {'case_id': doc['case_id'], 'evidence_id': doc['evidence_id'],
                                                                   'kind': doc['kind'], 'display': doc.get('display')})
    return {'value': doc['value'], 'kind': doc['kind']}
