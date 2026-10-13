"""The link graph of a case: people, devices, files, programs, internet hosts and accounts, joined by what the records
say they did (ran, opened, stored on, connected, visited, downloaded, emailed, messaged, called, synced, uploaded,
logged in). Every edge exists because a record states it, and keeps up to three of those records so it can be cited and
opened. Nodes are merged by name across evidence items (the same user on the laptop's disk and its collection is one
person); each type is capped to its busiest nodes, unless the graph is focused on one node and its neighbours.
"""
from __future__ import annotations
import re
from collections import defaultdict
from urllib.parse import urlsplit

from ..database import get_db

TYPES = {  # type: (category, label)
    'person': ('people', 'Person'), 'contact': ('people', 'Contact'),
    'computer': ('devices', 'Computer'), 'phone': ('devices', 'Phone'), 'usb': ('devices', 'USB device'), 'volume': ('devices', 'Removable volume'),
    'file': ('files', 'File'), 'program': ('programs', 'Program'),
    'domain': ('internet', 'Internet host'), 'ip': ('internet', 'IP address'),
    'account': ('accounts', 'Account'),
}
CAPS = {'person': 40, 'contact': 60, 'computer': 20, 'phone': 20, 'usb': 30, 'volume': 30, 'file': 80, 'program': 50, 'domain': 50, 'ip': 40,
        'account': 30}
FOCUS_MAX = 250
SCAN = 20000           # records read per kind at most
SYSTEM_ACCOUNTS = {'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount', 'root', 'daemon', 'nobody'}
_USER_PATH = re.compile(r'^/(?:Users|Documents and Settings|home)/([^/]+)/', re.I)


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, type_: str, key: str, label: str, detail: str | None = None, evidence_id: str | None = None) -> str | None:
        if not key or not label:
            return None
        nid = f'{type_}:{key}'
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {'id': nid, 'type': type_, 'category': TYPES[type_][0], 'label': str(label)[:120], 'detail': detail,
                                   'evidence_ids': [], 'weight': 0}
        elif detail and not n['detail']:
            n['detail'] = detail
        if evidence_id and evidence_id not in n['evidence_ids']:
            n['evidence_ids'].append(evidence_id)
        return nid

    def edge(self, a: str | None, b: str | None, kind: str, ref: dict, when=None):
        if not a or not b or a == b:
            return
        e = self.edges.get((a, b, kind))
        if e is None:
            e = self.edges[(a, b, kind)] = {'source': a, 'target': b, 'kind': kind, 'count': 0, 'refs': [], 'first': None, 'last': None}
        e['count'] += 1
        if len(e['refs']) < 3:
            e['refs'].append(ref)
        if when is not None:
            w = when.isoformat() if hasattr(when, 'isoformat') else str(when)
            e['first'] = w if not e['first'] or w < e['first'] else e['first']
            e['last'] = w if not e['last'] or w > e['last'] else e['last']


def _ref(col: str, doc: dict) -> dict:
    return {'collection': col, 'id': str(doc['_id']), 'type': doc.get('type'), 'evidence_id': doc.get('evidence_id')}


def _host(url: str | None) -> str | None:
    try:
        h = urlsplit(url or '').hostname
    except ValueError:
        return None
    return h.lower() if h else None


def _path(p: str | None) -> str | None:
    """A file path as the computer wrote it (Firefox records downloads as file:/// addresses)."""
    if p and p.lower().startswith('file:///'):
        from urllib.parse import unquote
        p = unquote(p[8:])
        if re.match(r'^[A-Za-z]:/', p):
            p = p.replace('/', '\\')
        else:
            p = '/' + p
    return p


def _base(path: str | None) -> str | None:
    if not path:
        return None
    return re.split(r'[\\/]', str(path).rstrip('\\/'))[-1] or None


def _user_of(doc: dict) -> str | None:
    if doc.get('user'):
        return str(doc['user'])
    m = _USER_PATH.match(doc.get('source_path') or doc.get('source_file') or '')
    return m.group(1) if m else None


def build(case_id: str) -> Graph:
    db = get_db()
    g = Graph()
    art = db['forensic_artifacts']
    evidence = {e['evidence_id']: e for e in db['evidence'].find({'case_id': case_id}, {'evidence_id': 1, 'filename': 1, 'format': 1})}
    find = lambda t, proj=None: art.find({'case_id': case_id, 'type': t}, proj).limit(SCAN)

    # Devices of each evidence item: the computer (or phone) it is.
    device = {}
    for c in find('COMPUTER_INFO'):
        name = c.get('computer_name') or c.get('hostname')
        if name:
            device[c['evidence_id']] = g.node('computer', name.lower(), name, (c.get('os') or {}).get('product_name') if isinstance(c.get('os'), dict) else None,
                                              c['evidence_id'])
    for p in find('PHONE_DEVICE'):
        label = ' '.join(x for x in (p.get('manufacturer'), p.get('model')) if x) or p.get('platform') or 'Phone'
        device[p['evidence_id']] = g.node('phone', p['evidence_id'], p.get('name') or label, f'{label}, {p.get("platform")} {p.get("os_version") or ""}'.strip(),
                                          p['evidence_id'])
    dev = lambda eid: device.get(eid)

    # People: accounts with activity; SIDs name the user of the Recycle Bin.
    sids, people = {}, {}

    def person(name, eid):
        if not name:
            return None
        key = str(name).split('\\')[-1].lower()
        nid = g.node('person', key, str(name).split('\\')[-1], None, eid)
        people[nid] = True
        return nid
    for a in find('USER_ACCOUNT', {'username': 1, 'sid': 1, 'evidence_id': 1, 'full_name': 1}):
        if a.get('sid'):
            sids[a['sid']] = a.get('username')

    # Programs run.
    for d in find('USERASSIST'):
        p = _base(d.get('program'))
        if p and p.lower().endswith('.exe'):
            g.edge(person(_user_of(d), d['evidence_id']), g.node('program', p.lower(), p, d.get('program'), d['evidence_id']), 'ran', _ref('forensic_artifacts', d),
                   d.get('last_run'))
    for d in find('PROGRAM_RUN'):
        p = d.get('executable')
        if p:
            g.edge(dev(d['evidence_id']), g.node('program', p.lower(), p, d.get('executable_path'), d['evidence_id']), 'ran', _ref('forensic_artifacts', d),
                   d.get('last_run'))
    for d in art.find({'case_id': case_id, 'type': 'EXECUTABLE', 'score': {'$gte': 3}}).limit(SCAN):
        nid = g.node('program', (d.get('name') or '').lower(), d.get('name'), d.get('path'), d['evidence_id'])
        g.edge(dev(d['evidence_id']), nid, 'stored', _ref('forensic_artifacts', d))

    # Files opened, where they were, deleted, downloaded.
    for d in find('RECENT_FILE'):
        path = d.get('target_path') or d.get('local_path')
        if int(d.get('file_attributes') or 0) & 0x10:  # a shortcut to a folder
            continue
        f = g.node('file', (path or '').lower(), _base(path), path, d['evidence_id'])
        g.edge(person(_user_of(d), d['evidence_id']) or dev(d['evidence_id']), f, 'opened', _ref('forensic_artifacts', d), d.get('target_accessed') or d.get('lnk_modified'))
        if (d.get('drive_type') or '').lower() == 'removable' and d.get('drive_serial'):
            v = g.node('volume', d['drive_serial'].lower(), f'{d.get("volume_label") or "Removable"} ({d["drive_serial"]})',
                       f'Removable volume {d.get("volume_label") or ""}, serial {d["drive_serial"]}'.replace('  ', ' '), d['evidence_id'])
            g.edge(f, v, 'stored on', _ref('forensic_artifacts', d))
    for d in find('JUMPLIST_ENTRY'):
        path = d.get('target')
        name = _base(path) or ''
        if not path or not re.match(r'^[A-Za-z]:\\', path) or '.' not in name:  # folders and shell items are left out
            continue
        if name.lower().endswith('.exe'):  # a task that starts a program
            g.edge(person(_user_of(d), d['evidence_id']), g.node('program', name.lower(), name, path, d['evidence_id']), 'ran',
                   _ref('forensic_artifacts', d), d.get('last_used'))
        else:
            g.edge(person(_user_of(d), d['evidence_id']), g.node('file', path.lower(), name, path, d['evidence_id']), 'opened',
                   _ref('forensic_artifacts', d), d.get('last_used'))
    for d in find('RECYCLE_BIN_ITEM'):
        path = d.get('original_path')
        g.edge(person(sids.get(d.get('sid')), d['evidence_id']) or dev(d['evidence_id']), g.node('file', (path or '').lower(), _base(path), path, d['evidence_id']),
               'deleted', _ref('forensic_artifacts', d), d.get('deleted_time'))
    for d in find('BROWSER_DOWNLOAD'):
        path = _path(d.get('target_path'))
        f = g.node('file', (path or '').lower(), _base(path), path, d['evidence_id'])
        g.edge(person(_user_of(d), d['evidence_id']) or dev(d['evidence_id']), f, 'downloaded', _ref('forensic_artifacts', d), d.get('start_time'))
        h = _host(d.get('tab_url') or d.get('url'))
        g.edge(f, h and g.node('domain', h, h, None, d['evidence_id']), 'downloaded from', _ref('forensic_artifacts', d), d.get('start_time'))

    # The internet.
    for d in find('BROWSER_HISTORY', {'url': 1, 'evidence_id': 1, 'user': 1, 'source_path': 1, 'source_file': 1, 'last_visit_time': 1, 'type': 1}):
        h = _host(d.get('url'))
        if h:
            g.edge(person(_user_of(d), d['evidence_id']) or dev(d['evidence_id']), g.node('domain', h, h, None, d['evidence_id']), 'visited',
                   _ref('forensic_artifacts', d), d.get('last_visit_time'))
    for d in find('RDP_CONNECTION'):
        s = (d.get('server') or '').lower()
        g.edge(person(_user_of(d), d['evidence_id']), s and g.node('domain', s, s, 'Remote desktop server', d['evidence_id']), 'remote desktop',
               _ref('forensic_artifacts', d), d.get('key_last_write'))
    for d in art.find({'case_id': case_id, 'type': 'UNIX_EVENT', 'ip': {'$nin': [None, '']}}).limit(SCAN):
        ip = g.node('ip', d['ip'], d['ip'], None, d['evidence_id'])
        g.edge(ip, dev(d['evidence_id']), 'logged in' if 'login' in (d.get('kind') or '') else (d.get('label') or 'connected').lower(),
               _ref('forensic_artifacts', d), d.get('time'))
        g.edge(ip, person(d.get('user'), d['evidence_id']), 'as user', _ref('forensic_artifacts', d), d.get('time'))
    for d in find('HTTP_REQUEST'):
        client = d.get('client') and g.node('ip', d['client'], d['client'], 'In a network capture', d['evidence_id'])
        host = (d.get('host') or '').split(':')[0].lower()
        h = host and g.node('domain', host, host, None, d['evidence_id'])
        g.edge(client, h, 'HTTP request', _ref('forensic_artifacts', d), d.get('time'))
        for f in d.get('files') or []:
            if f.get('part') and f.get('direction') == 'request':
                fn = g.node('file', f.get('sha256') or f['path'].lower(), f.get('name'), f.get('path'), d['evidence_id'])
                g.edge(client, fn, 'uploaded', _ref('forensic_artifacts', d), d.get('time'))
                g.edge(fn, h, 'uploaded to', _ref('forensic_artifacts', d), d.get('time'))

    # USB devices.
    for u in db['usb_artifacts'].find({'case_id': case_id}).limit(SCAN):
        label = u.get('friendly_name') or ' '.join(x for x in (u.get('vendor'), u.get('product')) if x) or u.get('serial')
        g.edge(dev(u['evidence_id']), g.node('usb', u.get('serial') or u.get('instance_id'), label, f'Serial {u.get("serial")}', u['evidence_id']), 'connected',
               {'collection': 'usb_artifacts', 'id': str(u['_id']), 'type': 'USB', 'evidence_id': u['evidence_id']},
               u.get('eventlog_last_connected') or u.get('last_arrival') or u.get('first_install'))

    # Email: who wrote to whom, and what was attached.
    for m in db['email_messages'].find({'case_id': case_id}, {'from_address': 1, 'from_name': 1, 'to': 1, 'cc': 1, 'attachments': 1, 'time': 1,
                                                              'evidence_id': 1, 'user': 1, 'direction': 1}).limit(SCAN):
        ref = {'collection': 'email_messages', 'id': str(m['_id']), 'type': 'EMAIL', 'evidence_id': m['evidence_id']}
        sender = m.get('from_address') and g.node('contact', m['from_address'].lower(), m.get('from_name') or m['from_address'], m['from_address'],
                                                  m['evidence_id'])
        if m.get('direction') == 'sent' and m.get('user'):
            g.edge(person(m['user'], m['evidence_id']), sender, 'uses', ref, m.get('time'))
        for r in (m.get('to') or []) + (m.get('cc') or []):
            if r.get('address'):
                g.edge(sender, g.node('contact', r['address'].lower(), r.get('name') or r['address'], r['address'], m['evidence_id']), 'emailed', ref, m.get('time'))
        for a in m.get('attachments') or []:
            if a.get('name') and not a.get('content_id'):
                g.edge(sender, g.node('file', a.get('sha256') or a['name'].lower(), a['name'], a.get('name'), m['evidence_id']), 'sent attachment', ref, m.get('time'))

    # Chat, cloud storage.
    for d in art.find({'case_id': case_id, 'type': {'$in': ['CHAT_MESSAGE', 'CHAT_CALL', 'CHAT_FILE_TRANSFER']}}).limit(SCAN):
        partner = d.get('partner') or d.get('host') or d.get('author')
        if not partner or partner == d.get('account'):
            continue
        c = g.node('contact', f'{(d.get("app") or "chat").lower()}:{partner.lower()}', d.get('partner_name') or d.get('author_name') or partner,
                   f'{d.get("app")} {partner}', d['evidence_id'])
        me = person(_user_of(d), d['evidence_id'])
        kind = {'CHAT_MESSAGE': 'messaged', 'CHAT_CALL': 'called', 'CHAT_FILE_TRANSFER': 'file transfer'}[d['type']]
        g.edge(me, c, kind, _ref('forensic_artifacts', d), d.get('time') or d.get('started'))
        if d['type'] == 'CHAT_FILE_TRANSFER' and d.get('file_name'):
            f = g.node('file', (d.get('file_path') or d['file_name']).lower(), d['file_name'], d.get('file_path'), d['evidence_id'])
            g.edge(c if d.get('direction') == 'received' else me, f, 'sent file', _ref('forensic_artifacts', d), d.get('started'))
    for d in find('CLOUD_ACCOUNT'):
        g.edge(person(_user_of(d), d['evidence_id']), g.node('account', f'{d.get("provider")}:{d.get("account")}'.lower(), f'{d.get("provider")} {d.get("account") or ""}'.strip(),
                                                              d.get('sync_folder'), d['evidence_id']), 'uses', _ref('forensic_artifacts', d))
    for d in art.find({'case_id': case_id, 'type': 'CLOUD_FILE', 'is_folder': {'$ne': True}}).limit(SCAN):
        acct = g.node('account', f'{d.get("provider")}:{d.get("account")}'.lower(), f'{d.get("provider")} {d.get("account") or ""}'.strip(), None, d['evidence_id'])
        g.edge(person(_user_of(d), d['evidence_id']), acct, 'uses', _ref('forensic_artifacts', d))
        g.edge(g.node('file', (d.get('local_path') or d.get('path') or '').lower(), d.get('name'), d.get('local_path') or d.get('path'), d['evidence_id']), acct,
               'synced to', _ref('forensic_artifacts', d), d.get('modified'))

    # Phones.
    from ..forensic.phones import party_key
    for d in art.find({'case_id': case_id, 'type': {'$in': ['PHONE_MESSAGE', 'PHONE_CALL']}}, {'party': 1, 'party_name': 1, 'chat_name': 1, 'app': 1, 'kind': 1,
                                                                                            'time': 1, 'evidence_id': 1, 'type': 1, 'group': 1}).limit(SCAN):
        k = party_key(d.get('party'))
        if not k:
            continue
        c = g.node('contact', f'party:{k}', d.get('chat_name') or d.get('party_name') or d['party'], d['party'], d['evidence_id'])
        kind = 'called' if d['type'] == 'PHONE_CALL' else ('WhatsApp' if d.get('app') == 'WhatsApp' else 'messaged')
        g.edge(dev(d['evidence_id']), c, kind, _ref('forensic_artifacts', d), d.get('time'))
    # A contact reached by email and by phone is the same person when the phone's contacts say so.
    for c in find('PHONE_CONTACT', {'name': 1, 'numbers': 1, 'emails': 1, 'evidence_id': 1, 'type': 1}):
        nums = [f'contact:party:{party_key(n)}' for n in c.get('numbers') or [] if party_key(n)]
        mails = [x for e in c.get('emails') or [] for x in (f'contact:party:{e.lower()}', f'contact:{e.lower()}')]
        present = [n for n in nums + mails if n in g.nodes]
        for a, b in zip(present, present[1:]):
            g.edge(a, b, 'same contact', _ref('forensic_artifacts', c))

    # Accounts on each computer (only people who did something appear).
    for a in find('USER_ACCOUNT', {'username': 1, 'evidence_id': 1, 'type': 1}):
        nid = f'person:{(a.get("username") or "").lower()}'
        if nid in g.nodes and dev(a['evidence_id']):
            g.edge(dev(a['evidence_id']), nid, 'account on', _ref('forensic_artifacts', a))
    for e in g.edges.values():
        g.nodes[e['source']]['weight'] += e['count']
        g.nodes[e['target']]['weight'] += e['count']
    return g


def view(case_id: str, types: set[str] | None = None, focus: str | None = None) -> dict:
    """The graph to draw: capped per type (or one node's neighbourhood when focused), with what was left out."""
    g = build(case_id)
    nodes = {nid: n for nid, n in g.nodes.items() if (not types or n['type'] in types) and n['weight'] > 0}
    if focus:
        if focus not in g.nodes:
            return {'nodes': [], 'edges': [], 'omitted': {}, 'focus': focus, 'types': _types()}
        near = {focus}
        for e in g.edges.values():
            if e['source'] == focus:
                near.add(e['target'])
            elif e['target'] == focus:
                near.add(e['source'])
        keep = sorted((nodes.get(n) or g.nodes[n] for n in near), key=lambda n: (n['id'] != focus, -n['weight']))[:FOCUS_MAX]
        keep_ids = {n['id'] for n in keep}
        omitted = {'neighbours': max(0, len(near) - len(keep_ids))}
    else:
        by_type = defaultdict(list)
        for n in nodes.values():
            by_type[n['type']].append(n)
        keep, omitted = [], {}
        for t, ns in by_type.items():
            ns.sort(key=lambda n: (-n['weight'], n['label']))
            keep += ns[:CAPS[t]]
            if len(ns) > CAPS[t]:
                omitted[t] = len(ns) - CAPS[t]
        keep_ids = {n['id'] for n in keep}
    edges = [e for e in g.edges.values() if e['source'] in keep_ids and e['target'] in keep_ids]
    linked = {e['source'] for e in edges} | {e['target'] for e in edges}
    keep = [n for n in keep if n['id'] in linked or n['id'] == focus]
    keep.sort(key=lambda n: (n['category'], n['type'], -n['weight'], n['label']))
    edges.sort(key=lambda e: (-e['count'], e['source'], e['target'], e['kind']))
    return {'nodes': keep, 'edges': edges, 'omitted': omitted, 'focus': focus, 'types': _types(),
            'totals': {'nodes': len(g.nodes), 'edges': len(g.edges)}}


def _types() -> list[dict]:
    return [{'type': t, 'category': c, 'label': label} for t, (c, label) in TYPES.items()]
