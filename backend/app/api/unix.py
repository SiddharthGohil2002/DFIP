"""Linux and macOS records of a case (module `unix`): shell commands, logins and log events, scheduled jobs and
services, recently used files, Wi-Fi networks and quarantined downloads."""
import re

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics/unix', tags=['linux and macos'])
TYPES = {  # type: (sort, fields searched)
    'SHELL_COMMAND': ([('evidence_id', 1), ('user', 1), ('order', 1)], ('command', 'user')),
    'UNIX_EVENT': ([('time', -1)], ('label', 'user', 'ip', 'text', 'summary', 'host')),
    'SCHEDULED_JOB': ([('notable', -1), ('mechanism', 1), ('name', 1)], ('name', 'command', 'user', 'source_path')),
    'RECENT_DOCUMENT': ([('visited', -1)], ('path', 'application', 'user')),
    'WIFI_NETWORK': ([('last_joined', -1)], ('ssid',)),
    'QUARANTINE_EVENT': ([('time', -1)], ('url', 'origin_url', 'agent', 'sender')),
}


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


@r.get('')
def records(case_id: str, type: str, evidence_id: str | None = None, search: str | None = None, flagged: bool = False,
            kind: str | None = None, skip: int = 0, limit: int = 200, u=Depends(current_user)):
    """Records of one type; `flagged=true` only those that stand out (flagged commands and jobs, notable log events);
    `kind` a log event kind (ssh_login, sudo, usb_connected ...)."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    sort, fields = TYPES[type]
    q: dict = {'case_id': case_id, 'type': type, **({'evidence_id': evidence_id} if evidence_id else {})}
    if flagged:
        q['$or'] = [{'flags.severity': {'$in': ['high', 'medium']}}, {'notable': True}] if type != 'SHELL_COMMAND' else [{'flags.0': {'$exists': True}}]
    if kind:
        q['kind'] = kind
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q.setdefault('$and', []).append({'$or': [{f: rx} for f in fields]})
    col = get_db()['forensic_artifacts']
    rows = [dict(_plain(x), _id=str(x['_id'])) for x in col.find(q).sort(sort).skip(max(0, skip)).limit(max(1, min(limit, 1000)))]
    kinds = {}
    if type == 'UNIX_EVENT':
        kinds = {k['_id']: k['n'] for k in col.aggregate([{'$match': {'case_id': case_id, 'type': type, **({'evidence_id': evidence_id} if evidence_id else {})}},
                                                         {'$group': {'_id': '$kind', 'n': {'$sum': 1}}}])}
    return {'data': rows, 'total': col.count_documents(q), 'kinds': kinds}
