"""Phones of a case (module `phone`): the devices, messages (SMS, MMS, iMessage, WhatsApp), calls, contacts, installed
apps and saved Wi-Fi networks."""
import re

from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics/phones', tags=['phones'])
TYPES = {  # type: (sort, fields searched)
    'PHONE_DEVICE': ([('platform', 1), ('model', 1)], ('model', 'name', 'manufacturer', 'os_version')),
    'PHONE_MESSAGE': ([('time', 1), ('id', 1)], ('text', 'party', 'party_name', 'chat_name', 'sender', 'sender_name', 'attachments.name')),
    'PHONE_CALL': ([('time', 1)], ('party', 'party_name', 'kind', 'app')),
    'PHONE_CONTACT': ([('name', 1)], ('name', 'numbers', 'emails', 'organization')),
    'PHONE_APP': ([('notable', -1), ('installed', -1), ('app_id', 1)], ('app_id', 'name', 'category', 'installer')),
    'PHONE_WIFI': ([('last_joined', -1), ('ssid', 1)], ('ssid', 'security', 'router_mac')),
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
def records(case_id: str, type: str, evidence_id: str | None = None, search: str | None = None, whatsapp: bool | None = None,
            app: str | None = None, party: str | None = None, notable: bool = False, skip: int = 0, limit: int = 200, u=Depends(current_user)):
    """Records of one type. Messages: `whatsapp=true` only WhatsApp, `false` all other apps; `app` one app (SMS, MMS,
    iMessage ...); `party` one conversation (the number, address or WhatsApp id). Apps: `notable=true` only those that
    matter to an investigation (encrypted messaging, VPN, cleaners ...)."""
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    if type not in TYPES:
        raise HTTPException(400, f'type must be one of {", ".join(TYPES)}')
    sort, fields = TYPES[type]
    base: dict = {'case_id': case_id, 'type': type, **({'evidence_id': evidence_id} if evidence_id else {})}
    q = dict(base)
    if type == 'PHONE_MESSAGE':
        if whatsapp is not None:
            base['app'] = q['app'] = 'WhatsApp' if whatsapp else {'$ne': 'WhatsApp'}
        if app:
            q['app'] = app[:50]
        if party:
            q['party'] = party[:300]
    if notable:
        q['notable'] = True
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        rx = {'$regex': re.escape(search.strip()), '$options': 'i'}
        q.setdefault('$and', []).append({'$or': [{f: rx} for f in fields]})
    col = get_db()['forensic_artifacts']
    rows = [dict(_plain(x), _id=str(x['_id'])) for x in col.find(q).sort(sort).skip(max(0, skip)).limit(max(1, min(limit, 1000)))]
    out = {'data': rows, 'total': col.count_documents(q)}
    if type == 'PHONE_MESSAGE':  # the apps and the conversations, for the filters
        out['apps'] = {a['_id']: a['n'] for a in col.aggregate([{'$match': base}, {'$group': {'_id': '$app', 'n': {'$sum': 1}}}])}
        out['conversations'] = [{'party': c['_id'], 'name': c['name'], 'app': c['app'], 'messages': c['n'], 'last': _plain(c['last'])}
                                for c in col.aggregate([{'$match': base}, {'$group': {'_id': '$party', 'n': {'$sum': 1}, 'last': {'$max': '$time'},
                                                                                       'name': {'$first': {'$ifNull': ['$chat_name', '$party_name']}},
                                                                                       'app': {'$first': '$app'}}},
                                                        {'$sort': {'last': -1}}, {'$limit': 500}])]
    return out
