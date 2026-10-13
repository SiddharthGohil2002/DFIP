"""Retention: when a case is closed (COMPLETED or ARCHIVED) it gets a date by which its data is due for deletion, from
the policy an administrator sets. A daily check (Celery beat, or run by an administrator) finds the cases that are due
and notifies the administrators; nothing is deleted automatically, and a case under legal hold is never due."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone

from ..database import get_db

CLOSED = {'COMPLETED', 'ARCHIVED'}
DEFAULT_DAYS = 7 * 365   # seven years
MIN_DAYS, MAX_DAYS = 1, 100 * 365


def policy() -> dict:
    p = get_db()['settings'].find_one({'_id': 'retention'}) or {}
    return {'enabled': bool(p.get('enabled', True)), 'days': int(p.get('days') or DEFAULT_DAYS), 'set_by_name': p.get('set_by_name'),
            'set_at': p.get('set_at')}


def set_policy(enabled: bool, days: int, user: dict) -> dict:
    now = datetime.now(timezone.utc)
    get_db()['settings'].update_one({'_id': 'retention'}, {'$set': {'enabled': enabled, 'days': days, 'set_by': str(user['_id']),
                                                                    'set_by_name': user.get('name'), 'set_at': now}}, upsert=True)
    return policy()


def on_status_change(old: str | None, new: str, now: datetime) -> tuple[dict, dict]:
    """($set, $unset) for a case whose status changes: closing it starts the retention period, reopening it ends it."""
    if new in CLOSED and old not in CLOSED:
        p = policy()
        retention = {'days': p['days'], 'due_at': now + timedelta(days=p['days']), 'set_at': now} if p['enabled'] else None
        return {'closed_at': now, **({'retention': retention} if retention else {})}, {}
    if new not in CLOSED and old in CLOSED:
        return {}, {'closed_at': '', 'retention': ''}
    return {}, {}


def due_cases(now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    return list(get_db()['cases'].find({'retention.due_at': {'$lte': now}, 'status': {'$in': sorted(CLOSED)}, 'deleted': {'$ne': True}},
                                       {'case_id': 1, 'name': 1, 'status': 1, 'closed_at': 1, 'retention': 1, 'legal_hold': 1}).sort('retention.due_at', 1))


def run_check(now: datetime | None = None) -> dict:
    """Notifies every active administrator of the cases due for deletion (at most once a day per case); cases under legal
    hold are listed as held, not due."""
    from .notifications import create_sync as notify
    now = now or datetime.now(timezone.utc)
    db = get_db()
    due, held, notified = [], [], []
    for c in due_cases(now):
        if (c.get('legal_hold') or {}).get('active'):
            held.append(c['case_id'])
            continue
        due.append(c['case_id'])
        last = (c.get('retention') or {}).get('notified_at')
        if last and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last and now - last < timedelta(hours=20):
            continue
        notified.append(c['case_id'])
        db['cases'].update_one({'_id': c['_id']}, {'$set': {'retention.notified_at': now}})
    if notified:
        for admin in db['users'].find({'role': 'ADMIN', 'status': 'ACTIVE'}, {'_id': 1}):
            notify(str(admin['_id']), 'Cases due for deletion',
                   f'{len(notified)} closed case(s) reached the end of their retention period: {", ".join(notified)}. '
                   'Review them under Administration > Retention.', 'WARNING')
    db['retention_runs'].insert_one({'at': now, 'due': due, 'held': held, 'notified': notified})
    return {'at': now.isoformat(), 'due': due, 'held': held, 'notified': notified}
