"""The people of a case: who can see it, what their role lets them do, and who an @mention in a comment names."""
from __future__ import annotations
import re

from bson import ObjectId

from ..database import get_db

# An @mention is the person's email address: @alice@example.org (the comment box offers the case's people).
MENTION = re.compile(r'(?<![\w.@])@([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)')


def has_permission(user: dict, permission: str) -> bool:
    if user.get('role') == 'ADMIN':
        return True
    role = get_db()['roles'].find_one({'name': user.get('role')}, {'permissions': 1}) or {}
    return permission in (role.get('permissions') or [])


def user_by_id(uid: str | None) -> dict | None:
    if not uid or not ObjectId.is_valid(str(uid)):
        return None
    return get_db()['users'].find_one({'_id': ObjectId(str(uid))})


def name_of(uid: str | None) -> str | None:
    u = user_by_id(uid)
    return u.get('name') if u else None


def member_ids(case: dict) -> set[str]:
    """The users a case is shared with (administrators see every case besides)."""
    return {x for x in (case.get('investigator_id'), case.get('created_by'), *(case.get('member_ids') or [])) if x}


def can_see(user: dict, case: dict) -> bool:
    return user.get('status') == 'ACTIVE' and (user.get('role') == 'ADMIN' or str(user['_id']) in member_ids(case))


def case_people(case: dict) -> list[dict]:
    """Active users who can see the case: its investigator, creator and members, and the administrators."""
    ids = [ObjectId(x) for x in member_ids(case) if ObjectId.is_valid(x)]
    q = {'status': 'ACTIVE', '$or': [{'_id': {'$in': ids}}, {'role': 'ADMIN'}]}
    out = []
    for u in get_db()['users'].find(q, {'name': 1, 'email': 1, 'role': 1}).sort('name', 1):
        uid = str(u['_id'])
        out.append({'user_id': uid, 'name': u.get('name'), 'email': u.get('email'), 'role': u.get('role'),
                    'investigator': uid == case.get('investigator_id'), 'member': uid in (case.get('member_ids') or []),
                    'can_review': has_permission(u, 'FINDING_REVIEW')})
    return out


def mentions(text: str, case: dict) -> tuple[list[dict], list[str]]:
    """The people a text @mentions who can see the case, and the addresses that name nobody who can (never
    notified, so a mention cannot tell anyone about a case they are not on)."""
    found, unknown = [], []
    for email in dict.fromkeys(m.lower() for m in MENTION.findall(text or '')):
        u = get_db()['users'].find_one({'email': {'$regex': f'^{re.escape(email)}$', '$options': 'i'}})
        if u and can_see(u, case):
            found.append({'user_id': str(u['_id']), 'name': u.get('name'), 'email': u.get('email')})
        else:
            unknown.append(email)
    return found, unknown
