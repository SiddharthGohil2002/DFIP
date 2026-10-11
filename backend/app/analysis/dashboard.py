"""Activity dashboard for a case: when the computer was used (day of week x hour, and per day), which websites
were visited, which file types the disks hold, and when USB devices were connected.

Grouping by hour and day happens in MongoDB in the requested time zone (an IANA name such as Asia/Kolkata, a
fixed offset such as +05:30, or UTC), so daylight-saving time is applied per event.
"""
from __future__ import annotations
import re
from urllib.parse import urlsplit

# User activity: what a person did, as opposed to filesystem times, which also change for system reasons
# (and on FAT carry only a date for "accessed", which would pile up at midnight).
ACTIVITY_TYPES = ['BROWSER_VISIT', 'BROWSER_DOWNLOAD', 'USB_ACTIVITY', 'PROGRAM_RUN', 'RECENT_FILE_OPENED', 'FILE_DELETED_TO_RECYCLE_BIN',
                  'PROGRAM_RUN_USERASSIST', 'PROGRAM_RUN_BAM', 'FOLDER_BROWSED', 'EXPLORER_SEARCH', 'TYPED_PATH', 'RECENT_DOC_OPENED',
                  'RUN_DIALOG', 'RDP_CONNECTION', 'LOGON', 'LOGOFF', 'JUMPLIST_OPENED', 'TIMELINE_ACTIVITY',
                  'FILE_DOWNLOADED', 'BROWSER_SEARCH', 'EMAIL_SENT', 'CHAT_CALL', 'CHAT_FILE_TRANSFER']
GROUPS = {'BROWSER_VISIT': 'web', 'BROWSER_DOWNLOAD': 'web', 'USB_ACTIVITY': 'usb', 'PROGRAM_RUN': 'windows',
          'RECENT_FILE_OPENED': 'windows', 'FILE_DELETED_TO_RECYCLE_BIN': 'windows', 'FILE_MACB': 'files',
          'PROGRAM_RUN_USERASSIST': 'windows', 'PROGRAM_RUN_BAM': 'windows', 'FOLDER_BROWSED': 'windows', 'EXPLORER_SEARCH': 'windows',
          'TYPED_PATH': 'windows', 'RECENT_DOC_OPENED': 'windows', 'RUN_DIALOG': 'windows', 'RDP_CONNECTION': 'windows',
          'LOGON': 'logon', 'LOGOFF': 'logon', 'JUMPLIST_OPENED': 'windows', 'TIMELINE_ACTIVITY': 'windows',
          'FILE_DOWNLOADED': 'web', 'BROWSER_SEARCH': 'web', 'EMAIL_SENT': 'comms', 'CHAT_CALL': 'comms', 'CHAT_FILE_TRANSFER': 'comms'}
TZ_RE = re.compile(r'^(UTC|[+-]\d{2}:\d{2}|[A-Za-z]+(?:[/_+-][A-Za-z0-9_+-]+)*)$')
USB_TIMES = ('setupapi_first_install', 'first_install', 'last_install', 'last_arrival', 'last_removal',
             'eventlog_first_connected', 'eventlog_last_connected', 'eventlog_last_removed')
EXTENSION = r'\.([A-Za-z0-9]{1,10})$'


def valid_tz(tz: str) -> bool:
    return bool(tz) and len(tz) <= 64 and bool(TZ_RE.match(tz))


def event_query(case_id: str, types: list[str] | None, evidence_id: str | None) -> dict:
    q = {'case_id': case_id}
    if types:
        q['type'] = {'$in': types}
    if evidence_id:
        q['evidence_id'] = evidence_id
    return q


def heatmap(db, q: dict, tz: str) -> dict:
    """Events per ISO weekday (1 = Monday) and hour of day."""
    rows = db['timeline_events'].aggregate([
        {'$match': q},
        {'$group': {'_id': {'d': {'$isoDayOfWeek': {'date': '$timestamp', 'timezone': tz}},
                            'h': {'$hour': {'date': '$timestamp', 'timezone': tz}}}, 'n': {'$sum': 1}}},
    ])
    cells = sorted([r['_id']['d'], r['_id']['h'], r['n']] for r in rows)
    return {'cells': cells, 'max': max((c[2] for c in cells), default=0), 'total': sum(c[2] for c in cells)}


def per_day(db, q: dict, tz: str) -> list[dict]:
    rows = db['timeline_events'].aggregate([
        {'$match': q},
        {'$group': {'_id': {'day': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp', 'timezone': tz}}, 'type': '$type'},
                    'n': {'$sum': 1}}},
    ])
    days: dict[str, dict] = {}
    for r in rows:
        day = days.setdefault(r['_id']['day'], {'date': r['_id']['day'], 'total': 0, 'by_group': {}})
        group = GROUPS.get(r['_id']['type'], 'other')
        day['total'] += r['n']
        day['by_group'][group] = day['by_group'].get(group, 0) + r['n']
    return [days[d] for d in sorted(days)]


def host_of(url: str | None) -> str:
    try:
        host = urlsplit(url or '').hostname
    except ValueError:
        host = None
    if not host:
        return '(local or invalid URL)'
    return host[4:] if host.startswith('www.') else host


def top_domains(db, case_id: str, evidence_id: str | None, limit: int = 10) -> dict:
    """Websites by number of visits (the browsers' visit counts) and pages recorded."""
    q = {'case_id': case_id, 'type': 'BROWSER_HISTORY'}
    if evidence_id:
        q['evidence_id'] = evidence_id
    hosts: dict[str, dict] = {}
    for r in db['forensic_artifacts'].find(q, {'url': 1, 'visit_count': 1}).limit(200_000):
        h = hosts.setdefault(host_of(r.get('url')), {'host': host_of(r.get('url')), 'visits': 0, 'pages': 0})
        h['pages'] += 1
        h['visits'] += r.get('visit_count') or 0
    ranked = sorted(hosts.values(), key=lambda h: (-h['visits'], -h['pages'], h['host']))
    return {'data': ranked[:limit], 'total_hosts': len(ranked), 'other_visits': sum(h['visits'] for h in ranked[limit:])}


def file_types(db, evidence_ids: list[str], limit: int = 12) -> dict:
    """Files by extension (lower case; '' for none), with total size and how many are deleted."""
    rows = list(db['fs_entries'].aggregate([
        {'$match': {'evidence_id': {'$in': evidence_ids}, 'is_virtual': False, 'is_dir': False, 'container': {'$exists': False}}},
        {'$project': {'size': 1, 'deleted': 1, 'ext': {'$toLower': {'$ifNull': [
            {'$arrayElemAt': [{'$getField': {'field': 'captures', 'input': {'$regexFind': {'input': '$name', 'regex': EXTENSION}}}}, 0]}, '']}}}},
        {'$group': {'_id': '$ext', 'count': {'$sum': 1}, 'size': {'$sum': {'$ifNull': ['$size', 0]}},
                    'deleted': {'$sum': {'$cond': ['$deleted', 1, 0]}}}},
        {'$sort': {'count': -1, '_id': 1}},
    ]))
    data = [{'extension': r['_id'] or '(none)', 'count': r['count'], 'size': r['size'], 'deleted': r['deleted']} for r in rows]
    rest = data[limit:]
    return {'data': data[:limit], 'other': {'count': sum(r['count'] for r in rest), 'size': sum(r['size'] for r in rest),
                                             'deleted': sum(r['deleted'] for r in rest), 'extensions': len(rest)}}


def usb_spans(db, case_id: str, evidence_id: str | None) -> list[dict]:
    q = {'case_id': case_id}
    if evidence_id:
        q['evidence_id'] = evidence_id
    out = []
    for d in db['usb_artifacts'].find(q):
        points = [{'kind': k, 't': d[k]} for k in USB_TIMES if d.get(k)]
        points.sort(key=lambda p: p['t'])
        out.append({'serial': d.get('serial'), 'label': d.get('friendly_name') or f'{d.get("vendor") or ""} {d.get("product") or ""}'.strip(),
                    'drive_letters': d.get('drive_letters') or [], 'first': points[0]['t'] if points else None,
                    'last': points[-1]['t'] if points else None, 'points': points})
    out.sort(key=lambda s: s['first'] or '')
    return out
