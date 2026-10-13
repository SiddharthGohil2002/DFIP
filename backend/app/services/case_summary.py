"""A case summary built from the stored records alone: numbered facts (F1, F2 ...) in sections, each citing the records
it rests on, and paragraphs that join them. The same records always give the same summary; nothing is inferred beyond
what the records state. The facts are also what the optional Claude mode may be given (only those the investigator
selects)."""
from __future__ import annotations
from datetime import datetime, timezone

from ..database import get_db

SECTIONS = [('evidence', 'Evidence'), ('devices', 'Computers, phones and users'), ('usb', 'USB devices'), ('files', 'Files of interest'),
            ('transfers', 'Data leaving the computer'), ('programs', 'Programs and malware indicators'), ('activity', 'When the computer was used'),
            ('findings', 'Findings and tags')]
PER_SECTION = 12


def _t(v) -> str:
    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            return v
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    return str(v) if v is not None else 'an unknown time'


def _ref(col: str, d: dict, kind: str | None = None) -> dict:
    return {'collection': col, 'id': str(d.get('_id')), 'type': kind or d.get('type'), 'evidence_id': d.get('evidence_id')}


class _Facts:
    def __init__(self):
        self.items: list[dict] = []
        self.more: dict[str, int] = {}

    def add(self, section: str, text: str, refs: list[dict]):
        if sum(1 for f in self.items if f['section'] == section) >= PER_SECTION:
            self.more[section] = self.more.get(section, 0) + 1
            return
        self.items.append({'section': section, 'text': text, 'refs': refs})


def facts(case_id: str) -> list[dict]:
    db = get_db()
    art = db['forensic_artifacts']
    F = _Facts()
    q = lambda t, extra=None, sort=None, limit=200: art.find({'case_id': case_id, 'type': t, **(extra or {})}).sort(sort or [('_id', 1)]).limit(limit)

    for e in db['evidence'].find({'case_id': case_id}).sort('evidence_id', 1):
        size = f'{(e.get("size") or 0) / (1 << 20):,.1f} MiB'
        F.add('evidence', f'{e["evidence_id"]} is {e.get("filename")} ({e.get("format")}, {size}, SHA-256 {str(e.get("sha256"))[:16]}…), '
                          f'integrity {str(e.get("verification_status") or "not checked").lower()}, analysis {str(e.get("analysis_status") or "not run").lower()}.',
              [_ref('evidence', e, 'EVIDENCE')])
    for c in q('COMPUTER_INFO', sort=[('evidence_id', 1)]):
        os_ = (c.get('os') or {}).get('product_name') if isinstance(c.get('os'), dict) else None
        tz = c.get('time_zone')
        tz = tz.get('zone') or tz.get('key_name') if isinstance(tz, dict) else tz
        bits = [f'runs {os_}' if os_ else None, f'time zone {tz}' if tz else None,
                f'last shut down {_t(c["last_shutdown"])}' if c.get('last_shutdown') else None]
        F.add('devices', f'{c["evidence_id"]} is the computer {c.get("computer_name") or c.get("hostname")}' + (f' ({c.get("os_family")})' if c.get('os_family') else '')
              + (': ' + ', '.join(b for b in bits if b) if any(bits) else '') + '.', [_ref('forensic_artifacts', c)])
    for p in q('PHONE_DEVICE', sort=[('evidence_id', 1)]):
        F.add('devices', f'{p["evidence_id"]} is a phone: {" ".join(x for x in (p.get("manufacturer"), p.get("model")) if x) or p.get("platform")}'
                         f'{" named " + p["name"] if p.get("name") else ""}, {p.get("platform")} {p.get("os_version") or ""}'.rstrip() + '.',
              [_ref('forensic_artifacts', p)])
    for a in q('USER_ACCOUNT', {'$or': [{'logon_count': {'$gt': 0}}, {'last_logon': {'$ne': None}}]}, sort=[('evidence_id', 1), ('username', 1)]):
        if a.get('disabled'):
            continue
        F.add('devices', f'User account {a.get("username")} on {a["evidence_id"]}' + (f' last logged on {_t(a["last_logon"])}' if a.get('last_logon') else '')
              + (f' ({a["logon_count"]} logons)' if a.get('logon_count') else '') + '.', [_ref('forensic_artifacts', a)])

    for u in db['usb_artifacts'].find({'case_id': case_id}).sort([('serial', 1)]).limit(100):
        name = u.get('friendly_name') or ' '.join(x for x in (u.get('vendor'), u.get('product')) if x) or 'A USB storage device'
        times = [f'first installed {_t(u.get("setupapi_first_install") or u.get("first_install"))}' if (u.get('setupapi_first_install') or u.get('first_install')) else None,
                 f'connected {_t(u["eventlog_last_connected"])}' if u.get('eventlog_last_connected') else None,
                 f'removed {_t(u["eventlog_last_removed"])}' if u.get('eventlog_last_removed') else None]
        F.add('usb', f'{name} (serial {u.get("serial")}) was used on {u["evidence_id"]}' + ('; ' + ', '.join(x for x in times if x) if any(times) else '')
              + (f'; drive {", ".join(u["drive_letters"])}' if u.get('drive_letters') else '') + '.',
              [{'collection': 'usb_artifacts', 'id': str(u['_id']), 'type': 'USB', 'evidence_id': u['evidence_id']}])

    for d in q('RECYCLE_BIN_ITEM', sort=[('deleted_time', 1)]):
        F.add('files', f'{d.get("original_path")} was moved to the Recycle Bin at {_t(d.get("deleted_time"))}'
                       + (' and its content is still there' if d.get('data_present') else '') + '.', [_ref('forensic_artifacts', d)])
    for d in q('RECENT_FILE', {'drive_type': 'Removable'}, sort=[('target_accessed', 1)]):
        F.add('files', f'{d.get("target_path")} on a removable volume ({d.get("volume_label") or "no label"}, serial {d.get("drive_serial")}) was opened '
                       f'(shortcut written {_t(d.get("lnk_modified"))}).', [_ref('forensic_artifacts', d)])
    deleted = db['fs_entries'].count_documents({'evidence_id': {'$in': [e['evidence_id'] for e in db['evidence'].find({'case_id': case_id}, {'evidence_id': 1})]},
                                                'deleted': True, 'is_dir': False})
    if deleted:
        F.add('files', f'{deleted:,} deleted files are listed in the file systems.', [])
    for h in art.find({'case_id': case_id, 'type': 'HASH_SET_MATCH'}).sort('_id', 1).limit(50):
        kind = str(h.get('kind') or '')
        names = ', '.join(s.get('name') for s in h.get('sets') or [] if isinstance(s, dict) and s.get('kind') == kind and s.get('name'))
        F.add('files', f'{h.get("original_path")} is in the {kind.replace("_", "-").lower()} hash set {names}.'.replace(' .', '.'),
              [_ref('forensic_artifacts', h)])

    for m in db['email_messages'].find({'case_id': case_id, 'direction': 'sent', 'attachment_count': {'$gt': 0}}).sort('time', 1).limit(50):
        names = ', '.join(a['name'] for a in m.get('attachments') or [] if a.get('name') and not a.get('content_id'))
        to = ', '.join(r.get('address') for r in m.get('to') or [] if r.get('address'))
        F.add('transfers', f'{m.get("from_address")} emailed {to} "{m.get("subject")}" at {_t(m.get("time"))} with {names}.',
              [{'collection': 'email_messages', 'id': str(m['_id']), 'type': 'EMAIL', 'evidence_id': m['evidence_id']}])
    for d in art.find({'case_id': case_id, 'type': 'HTTP_REQUEST', 'files': {'$elemMatch': {'direction': 'request', 'part': True}}}).sort('time', 1).limit(50):
        names = ', '.join(f['name'] for f in d['files'] if f.get('part') and f['direction'] == 'request')
        F.add('transfers', f'{d.get("client")} uploaded {names} to {d.get("url") or d.get("host")} at {_t(d.get("time"))} (network capture {d["evidence_id"]}).',
              [_ref('forensic_artifacts', d)])
    for d in art.find({'case_id': case_id, 'type': 'CLOUD_FILE', 'is_folder': {'$ne': True}}).sort('path', 1).limit(50):
        F.add('transfers', f'{d.get("provider")} ({d.get("account")}) synced {d.get("path")}' + (f', changed {_t(d["modified"])}' if d.get('modified') else '') + '.',
              [_ref('forensic_artifacts', d)])
    for d in q('CHAT_FILE_TRANSFER', sort=[('started', 1)]):
        F.add('transfers', f'{d.get("app")}: {d.get("file_name")} was {d.get("direction")} {"from" if d.get("direction") == "received" else "to"} '
                           f'{d.get("partner_name") or d.get("partner")} at {_t(d.get("started"))}.', [_ref('forensic_artifacts', d)])

    for x in art.find({'case_id': case_id, 'type': 'EXECUTABLE', 'score': {'$gte': 3}}).sort([('score', -1), ('path', 1)]).limit(50):
        why = '; '.join(f.get('label') for f in x.get('flags') or [] if f.get('label'))
        F.add('programs', f'{x.get("path")} stands out: {why or "flagged"}.', [_ref('forensic_artifacts', x)])
    for x in art.find({'case_id': case_id, 'type': 'MEMORY_PROCESS', 'notable': True}).sort([('score', -1), ('pid', 1)]).limit(50):
        why = '; '.join(f.get('label') for f in x.get('flags') or [] if f.get('severity') in ('high', 'medium'))
        F.add('programs', f'{x.get("name")} (PID {x.get("pid")}) in the memory image {x.get("evidence_id")} stands out: {why}.', [_ref('forensic_artifacts', x)])
    for x in art.find({'case_id': case_id, 'type': 'MALWARE_INDICATOR'}).sort('_id', 1).limit(50):
        F.add('programs', f'{x.get("original_path") or x.get("path")} matches {x.get("engine") or "YARA"} signature {x.get("rule") or x.get("signature")}.',
              [_ref('forensic_artifacts', x)])
    for x in q('PROGRAM_RUN', sort=[('last_run', 1)]):
        F.add('programs', f'{x.get("executable")} ran {x.get("run_count")} time(s), last at {_t(x.get("last_run"))} (Prefetch).', [_ref('forensic_artifacts', x)])

    from ..analysis.dashboard import ACTIVITY_TYPES
    ev = db['timeline_events']
    span = list(ev.aggregate([{'$match': {'case_id': case_id, 'type': {'$in': ACTIVITY_TYPES}}},
                              {'$group': {'_id': None, 'first': {'$min': '$timestamp'}, 'last': {'$max': '$timestamp'}, 'n': {'$sum': 1}}}]))
    if span and span[0]['n']:
        first = ev.find_one({'case_id': case_id, 'type': {'$in': ACTIVITY_TYPES}}, sort=[('timestamp', 1)])
        last = ev.find_one({'case_id': case_id, 'type': {'$in': ACTIVITY_TYPES}}, sort=[('timestamp', -1)])
        F.add('activity', f'{span[0]["n"]:,} user-activity events run from {_t(span[0]["first"])} to {_t(span[0]["last"])}.',
              [{'collection': 'timeline_events', 'id': str(first['_id']), 'type': first.get('type'), 'evidence_id': first.get('evidence_id')},
               {'collection': 'timeline_events', 'id': str(last['_id']), 'type': last.get('type'), 'evidence_id': last.get('evidence_id')}])
        for e in ev.find({'case_id': case_id, 'type': {'$in': ['USB_ACTIVITY', 'FILE_DELETED_TO_RECYCLE_BIN', 'EMAIL_SENT', 'HTTP_REQUEST']}}).sort('timestamp', 1).limit(8):
            F.add('activity', f'{_t(e.get("timestamp"))}: {e.get("description")}', [{'collection': 'timeline_events', 'id': str(e['_id']), 'type': e.get('type'),
                                                                                    'evidence_id': e.get('evidence_id')}])

    for f in db['findings'].find({'case_id': case_id}).sort('created_at', 1):
        status = (f.get('status') or 'DRAFT').replace('_', ' ').lower()
        F.add('findings', f'Finding ({status}{", approved by " + f["reviewed_by_name"] if f.get("status") == "APPROVED" and f.get("reviewed_by_name") else ""}, '
                          f'{str(f.get("severity")).lower()}): {f.get("title")}.', [{'collection': 'findings', 'id': str(f['_id']), 'type': 'FINDING'}])
    labels = {t['_id']: t['n'] for t in db['tags'].aggregate([{'$match': {'case_id': case_id}}, {'$group': {'_id': '$label', 'n': {'$sum': 1}}}])}
    if labels:
        F.add('findings', 'Tagged: ' + ', '.join(f'{n} {k.replace("_", " ").lower()}' for k, n in sorted(labels.items())) + '.', [])

    order = {s: i for i, (s, _) in enumerate(SECTIONS)}
    out = sorted(F.items, key=lambda f: order[f['section']])
    for i, f in enumerate(out, 1):
        f['id'] = f'F{i}'
    for s, n in F.more.items():
        out.append({'id': None, 'section': s, 'text': f'and {n} more of this kind (see the case pages).', 'refs': []})
    return out


def summary(case_id: str) -> dict:
    fs = facts(case_id)
    paragraphs = []
    for key, title in SECTIONS:
        items = [f for f in fs if f['section'] == key]
        if items:
            paragraphs.append({'section': key, 'title': title,
                               'text': ' '.join(f'{f["text"]}' + (f' [{f["id"]}]' if f['id'] else '') for f in items)})
    return {'case_id': case_id, 'generated_at': datetime.now(timezone.utc).isoformat(), 'facts': [f for f in fs if f['id']],
            'paragraphs': paragraphs, 'sections': [{'section': k, 'title': t} for k, t in SECTIONS]}
