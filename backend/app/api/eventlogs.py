"""Windows event logs of a case: the logs read, their records (notable or all, filtered), one record with its XML,
and the detections of the curated Sigma rules."""
import re
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from ..database import get_db
from ..forensic.event_catalog import CATEGORY_LABELS
from ..repositories.cases import get_case
from ..security import current_user

r = APIRouter(prefix='/forensics/eventlogs', tags=['eventlogs'])
_LIST_FIELDS = {'xml': 0, 'text': 0}
LEVELS = {'critical': 1, 'error': 2, 'warning': 3}


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


def _time(value: str | None, name: str):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise HTTPException(400, f'{name} must be an ISO 8601 date and time')
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@r.get('/logs')
def logs(case_id: str, evidence_id: str | None = None, u=Depends(current_user)):
    """The event logs each evidence item's analysis read: path, channel, record counts, time span, SHA-256 and state."""
    eids = _eids(case_id, u, evidence_id)
    out = []
    for f in get_db()['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'evidence_id': 1, 'eventlogs.logs': 1}):
        for log in (f.get('eventlogs') or {}).get('logs') or []:
            out.append(dict(log, evidence_id=f['evidence_id']))
    out.sort(key=lambda x: (x['evidence_id'], -(x.get('records') or 0), x.get('name') or ''))
    return {'data': out}


@r.get('/events')
def events(case_id: str, evidence_id: str | None = None, notable: bool | None = None, channel: str | None = None,
           event_id: str | None = None, category: str | None = None, level: str | None = None, user: str | None = None,
           search: str | None = None, start: str | None = None, end: str | None = None, detection: str | None = None,
           recovered: bool | None = None, order: str = 'asc', skip: int = 0, limit: int = 200, u=Depends(current_user)):
    """Event records, oldest first (order=desc for newest first). event_id takes one ID or a comma-separated list;
    level is critical, error or warning; search matches the description and every data value."""
    q: dict = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}}
    if notable is not None:
        q['notable'] = notable
    if channel:
        q['channel'] = channel
    if event_id:
        try:
            ids = [int(x) for x in event_id.split(',') if x.strip()]
        except ValueError:
            raise HTTPException(400, 'event_id must be a number or a comma-separated list of numbers')
        if len(ids) > 50:
            raise HTTPException(400, 'Give at most 50 event IDs')
        q['event_id'] = ids[0] if len(ids) == 1 else {'$in': ids}
    if category:
        if category not in CATEGORY_LABELS:
            raise HTTPException(400, f'category must be one of {", ".join(CATEGORY_LABELS)}')
        q['category'] = category
    if level:
        if level not in LEVELS:
            raise HTTPException(400, 'level must be critical, error or warning')
        q['level'] = {'$in': [v for v in LEVELS.values() if v <= LEVELS[level]]}
    if user:
        q['user'] = {'$regex': f'^{re.escape(user.strip())}$', '$options': 'i'}
    if detection:
        q['detections'] = detection
    if recovered is not None:
        q['recovered'] = recovered
    if search and search.strip():
        if len(search) > 200:
            raise HTTPException(400, 'Search for at most 200 characters')
        q['text'] = {'$regex': re.escape(search.strip()), '$options': 'i'}
    window = {k: v for k, v in (('$gte', _time(start, 'start')), ('$lte', _time(end, 'end'))) if v}
    if window:
        q['time'] = window
    if order not in ('asc', 'desc'):
        raise HTTPException(400, 'order must be asc or desc')
    col = get_db()['event_records']
    direction = 1 if order == 'asc' else -1
    rows = col.find(q, _LIST_FIELDS).sort([('time', direction), ('record_id', direction)]).skip(max(0, skip)).limit(max(1, min(limit, 1000)))
    return {'data': [_plain(x) for x in rows], 'total': col.count_documents(q)}


@r.get('/events/{record_id}')
def event(record_id: str, case_id: str, u=Depends(current_user)):
    """One event record with all of its data and the XML libevtx rendered for it."""
    eids = _eids(case_id, u)
    doc = get_db()['event_records'].find_one({'_id': ObjectId(record_id), 'evidence_id': {'$in': eids}}, {'text': 0}) \
        if ObjectId.is_valid(record_id) else None
    if not doc:
        raise HTTPException(404, 'Event record not found')
    return _plain(doc)


@r.get('/detections')
def detections(case_id: str, evidence_id: str | None = None, u=Depends(current_user)):
    """What the detection rules found: one row per rule (or per group, for counting rules), most severe first."""
    q = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}, 'type': 'EVENTLOG_DETECTION'}
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
    rows = [_plain(x) for x in get_db()['forensic_artifacts'].find(q)]
    rows.sort(key=lambda d: (order.get(d.get('level'), 9), d.get('first') or ''))
    return {'data': rows}


@r.get('/facets')
def facets(case_id: str, evidence_id: str | None = None, u=Depends(current_user)):
    """Channels, categories and the most frequent event IDs with their record counts, for the filters."""
    q = {'evidence_id': {'$in': _eids(case_id, u, evidence_id)}}
    col = get_db()['event_records']

    def group(field, limit, extra=None):
        pipeline = [{'$match': dict(q, **(extra or {}))}, {'$group': {'_id': f'${field}', 'n': {'$sum': 1}}}, {'$sort': {'n': -1, '_id': 1}},
                    {'$limit': limit}]
        return [{'value': x['_id'], 'count': x['n']} for x in col.aggregate(pipeline) if x['_id'] is not None]

    return {'channels': group('channel', 200), 'categories': [dict(c, label=CATEGORY_LABELS.get(c['value'], c['value']))
                                                              for c in group('category', 50)],
            'event_ids': group('event_id', 100), 'users': group('user', 100)}
