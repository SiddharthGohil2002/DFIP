"""More from browser profiles than history and downloads: what was searched for, cookies, bookmarks, form history
(autofill), the sites with saved logins (and their user names, never passwords), and deleted history rows still in
the database files.

Chromium-family browsers (Chrome, Edge, Brave, Opera, Vivaldi, Chromium) keep a profile folder with `History`,
`Cookies` (or `Network/Cookies`), `Web Data`, `Login Data` and `Bookmarks`; Firefox keeps `places.sqlite`,
`cookies.sqlite`, `formhistory.sqlite` and `logins.json`. Every database is opened as a copy (see
browser_artifacts._open_readonly_copy); a missing table or column leaves that part out with a note.

Passwords are never decrypted: Chromium encrypts them with the user's DPAPI key and Firefox with its NSS key
store, so a saved login shows the site, the user name (Chromium keeps it in clear; Firefox encrypts it too) and
when it was saved and last used.
"""
from __future__ import annotations
import json
import re
import shutil
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .browser_artifacts import _open_readonly_copy
from .sqlite_recover import recover

_WEBKIT = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_ROWS = 100_000

_USERS = r'^/(?:Users|Documents and Settings)/(?P<user>[^/]+)'
# (browser, family, profile folder pattern). The folder group is the profile's own folder.
PROFILES = [
    ('Chrome', 'CHROMIUM', _USERS + r'/AppData/Local/Google/Chrome/User Data/(?P<profile>[^/]+)'),
    ('Edge', 'CHROMIUM', _USERS + r'/AppData/Local/Microsoft/Edge/User Data/(?P<profile>[^/]+)'),
    ('Brave', 'CHROMIUM', _USERS + r'/AppData/Local/BraveSoftware/Brave-Browser/User Data/(?P<profile>[^/]+)'),
    ('Vivaldi', 'CHROMIUM', _USERS + r'/AppData/Local/Vivaldi/User Data/(?P<profile>[^/]+)'),
    ('Chromium', 'CHROMIUM', _USERS + r'/AppData/Local/Chromium/User Data/(?P<profile>[^/]+)'),
    ('Opera GX', 'CHROMIUM', _USERS + r'/AppData/Roaming/Opera Software/Opera GX Stable(?:/(?P<profile>Default|Profile [0-9]+))?'),
    ('Opera', 'CHROMIUM', _USERS + r'/AppData/Roaming/Opera Software/Opera Stable(?:/(?P<profile>Default|Profile [0-9]+))?'),
    ('Firefox', 'FIREFOX', _USERS + r'/AppData/Roaming/Mozilla/Firefox/Profiles/(?P<profile>[^/]+)'),
]
FILES = {
    'CHROMIUM': {'History': 'history', 'Cookies': 'cookies', 'Network/Cookies': 'cookies', 'Web Data': 'web_data',
                 'Login Data': 'logins', 'Bookmarks': 'bookmarks'},
    'FIREFOX': {'places.sqlite': 'places', 'cookies.sqlite': 'cookies', 'formhistory.sqlite': 'formhistory',
                'logins.json': 'logins_json'},
}
_FILE_RX = {fam: '|'.join(re.escape(n) for n in names) for fam, names in FILES.items()}
PATTERNS = [(b, fam, re.compile(rx + r'/(?P<file>' + _FILE_RX[fam] + r')$', re.I)) for b, fam, rx in PROFILES]
CANDIDATES = (r'/(History|Cookies|Web Data|Login Data|Bookmarks|places\.sqlite|cookies\.sqlite|formhistory\.sqlite|logins\.json)'
              r'(-wal|-journal)?$')

# Search engines: host (a suffix of the URL's host, or with a path prefix) -> the query parameter.
ENGINES = [
    ('Google', re.compile(r'(^|\.)google\.[a-z.]+$'), '/search', ('q',)),
    ('Bing', re.compile(r'(^|\.)bing\.com$'), '/search', ('q',)),
    ('DuckDuckGo', re.compile(r'(^|\.)duckduckgo\.com$'), '/', ('q',)),
    ('Yahoo', re.compile(r'(^|\.)search\.yahoo\.com$'), '/search', ('p',)),
    ('Yandex', re.compile(r'(^|\.)yandex\.[a-z.]+$'), '/search', ('text',)),
    ('Baidu', re.compile(r'(^|\.)baidu\.com$'), '/s', ('wd', 'word')),
    ('Ecosia', re.compile(r'(^|\.)ecosia\.org$'), '/search', ('q',)),
    ('Startpage', re.compile(r'(^|\.)startpage\.com$'), '/', ('query', 'q')),
    ('YouTube', re.compile(r'(^|\.)youtube\.com$'), '/results', ('search_query',)),
    ('Wikipedia', re.compile(r'(^|\.)wikipedia\.org$'), '/w/index.php', ('search',)),
    ('Amazon', re.compile(r'(^|\.)amazon\.[a-z.]+$'), '/s', ('k',)),
]


def classify(path: str) -> dict | None:
    """{browser, family, user, profile, profile_path, file, part} for a browser profile file, else None."""
    for browser, family, rx in PATTERNS:
        m = rx.match(path)
        if m:
            file = m.group('file')
            canon = next(n for n in FILES[family] if n.lower() == file.lower())
            return {'browser': browser, 'family': family, 'user': m.group('user'), 'profile': m.group('profile') or 'Default',
                    'profile_path': path[:m.start('file') - 1], 'file': canon, 'part': FILES[family][canon]}
    return None


def webkit(us):
    if not us or not isinstance(us, (int, float)) or us <= 0:
        return None
    try:
        return _WEBKIT + timedelta(microseconds=int(us))
    except (OverflowError, ValueError):
        return None


def unix_us(us):
    if not us or not isinstance(us, (int, float)) or us <= 0:
        return None
    try:
        return _UNIX + timedelta(microseconds=int(us))
    except (OverflowError, ValueError):
        return None


def unix_s(s):
    if not s or not isinstance(s, (int, float)) or s <= 0:
        return None
    try:
        return _UNIX + timedelta(seconds=s)
    except (OverflowError, ValueError):
        return None


def search_term(url: str | None) -> tuple[str, str] | None:
    """(engine, term) when the URL is a search on a known engine."""
    if not url or not url.lower().startswith(('http://', 'https://')):
        return None
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = (u.hostname or '').lower()
    for name, rx, path, params in ENGINES:
        if rx.search(host) and (u.path or '/').startswith(path):
            q = urllib.parse.parse_qs(u.query)
            for p in params:
                term = (q.get(p) or [''])[0].strip()
                if term:
                    return name, term[:500]
    return None


def _columns(con, table) -> set[str]:
    return {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}


class _Db:
    """A read-only copy of a profile database (with its -wal/-journal), closed and removed on exit."""

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        self.con, self.scratch = _open_readonly_copy(self.path)
        return self.con

    def __exit__(self, *exc):
        self.con.close()
        shutil.rmtree(self.scratch, ignore_errors=True)


# -- Chromium -----------------------------------------------------------------------------------------------------
def chromium_history(path: Path) -> dict:
    """Search terms (keyword_search_terms, and search URLs in urls) and deleted urls/keyword_search_terms rows."""
    out = {'searches': [], 'recovered': [], 'errors': [], 'free_pages': 0, 'wal_frames': 0}
    urls = {}
    with _Db(path) as con:
        try:
            for r in con.execute('SELECT id, url, title, last_visit_time, visit_count FROM urls LIMIT ?', (MAX_ROWS,)):
                urls[r['id']] = dict(r)
        except sqlite3.Error as exc:
            out['errors'].append(f'urls: {exc}')
        seen = set()
        try:
            for r in con.execute('SELECT keyword_id, url_id, term FROM keyword_search_terms LIMIT ?', (MAX_ROWS,)):
                u = urls.get(r['url_id']) or {}
                eng = search_term(u.get('url'))
                out['searches'].append({'term': r['term'], 'engine': eng[0] if eng else None, 'url': u.get('url'),
                                        'time': webkit(u.get('last_visit_time')), 'source_table': 'keyword_search_terms',
                                        'row_id': r['url_id'], 'keyword_id': r['keyword_id']})
                seen.add(r['url_id'])
        except sqlite3.Error as exc:
            out['errors'].append(f'keyword_search_terms: {exc}')
        for uid, u in urls.items():
            eng = search_term(u['url'])
            if eng and uid not in seen:
                out['searches'].append({'term': eng[1], 'engine': eng[0], 'url': u['url'], 'time': webkit(u['last_visit_time']),
                                        'source_table': 'urls', 'row_id': uid})
    _recovered(path, out, ['urls', 'keyword_search_terms'], 'CHROMIUM', urls)
    return out


def _recovered(path: Path, out: dict, tables, family, urls: dict):
    """Deleted history rows from free pages, free space and WAL frames (see sqlite_recover), on a fresh copy."""
    scratch = None
    try:
        con, scratch = _open_readonly_copy(path)
        con.close()
        res = recover(scratch / path.name, tables)
    except Exception as exc:
        out['errors'].append(f'deleted rows: {exc}')
        return
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    out['free_pages'], out['wal_frames'] = res['free_pages'], res['wal_frames']
    out['errors'] += res['errors']
    recovered_urls = {}
    for rec in res['records']:
        v = rec.values
        where = {'recovered_from': rec.source, 'page': rec.page, 'file_offset': rec.offset, 'file': rec.file, 'wal_frame': rec.frame,
                 'previous_version': rec.previous_version, 'source_table': rec.table, 'row_id': rec.rowid}
        if rec.table in ('urls', 'moz_places'):
            url = v.get('url')
            if not isinstance(url, str) or not re.match(r'^[a-z][a-z0-9+.-]*:', url):
                continue
            raw = v.get('last_visit_time') if family == 'CHROMIUM' else v.get('last_visit_date')
            when = webkit(raw) if family == 'CHROMIUM' else unix_us(raw)
            count = v.get('visit_count')
            # Carved bytes must make sense as a visit: a real date (or none) and a visit count, else they are a misreading.
            if (raw and not (when and 1995 <= when.year <= 2100)) or not (count is None or (isinstance(count, int) and 0 <= count < 10**7)):
                continue
            title = v.get('title') if isinstance(v.get('title'), str) else None
            row = {'url': url, 'title': title, 'visit_count': v.get('visit_count'), 'last_visit_time': when, **where}
            out['recovered'].append(row)
            if rec.rowid is not None:
                recovered_urls[rec.rowid] = row
            eng = search_term(url)
            if eng:
                out['searches'].append({'term': eng[1], 'engine': eng[0], 'url': url, 'time': when, 'source_table': rec.table,
                                        'row_id': rec.rowid, 'recovered': True, 'recovered_from': rec.source})
        elif rec.table == 'keyword_search_terms' and isinstance(v.get('term'), str):
            u = urls.get(v.get('url_id')) or recovered_urls.get(v.get('url_id')) or {}
            when = u.get('last_visit_time')
            when = webkit(when) if isinstance(when, int) else when
            if any(s.get('recovered') and s['term'] == v['term'] for s in out['searches']):
                continue
            out['searches'].append({'term': v['term'], 'engine': (search_term(u.get('url')) or (None,))[0], 'url': u.get('url'),
                                    'time': when, 'source_table': 'keyword_search_terms', 'row_id': v.get('url_id'),
                                    'recovered': True, 'recovered_from': rec.source})


def chromium_cookies(path: Path) -> dict:
    out = {'cookies': [], 'errors': []}
    with _Db(path) as con:
        try:
            cols = _columns(con, 'cookies')
            extra = [c for c in ('last_access_utc', 'is_persistent', 'samesite') if c in cols]
            enc = 'length(encrypted_value)' if 'encrypted_value' in cols else '0'
            for r in con.execute(f'SELECT host_key, name, value, path, creation_utc, expires_utc, is_secure, is_httponly, '
                                 f'{enc} AS enc_len{"".join(", " + c for c in extra)} FROM cookies LIMIT ?', (MAX_ROWS,)):
                r = dict(r)
                out['cookies'].append({
                    'host': r['host_key'], 'name': r['name'], 'path': r['path'],
                    'value': r['value'] or None, 'value_encrypted': bool(r['enc_len']) and not r['value'],
                    'created': webkit(r['creation_utc']), 'expires': webkit(r['expires_utc']),
                    'last_accessed': webkit(r.get('last_access_utc')), 'secure': bool(r['is_secure']),
                    'http_only': bool(r['is_httponly']), 'persistent': bool(r['is_persistent']) if 'is_persistent' in r else None})
        except sqlite3.Error as exc:
            out['errors'].append(f'cookies: {exc}')
    return out


def chromium_web_data(path: Path) -> dict:
    """Form history (autofill: what was typed into which field, how often) and saved cards (numbers stay encrypted)."""
    out = {'autofill': [], 'errors': []}
    with _Db(path) as con:
        try:
            for r in con.execute('SELECT name, value, date_created, date_last_used, count FROM autofill LIMIT ?', (MAX_ROWS,)):
                out['autofill'].append({'field': r['name'], 'value': r['value'], 'kind': 'form field', 'times_used': r['count'],
                                        'first_used': unix_s(r['date_created']), 'last_used': unix_s(r['date_last_used'])})
        except sqlite3.Error as exc:
            out['errors'].append(f'autofill: {exc}')
        try:
            cols = _columns(con, 'credit_cards')
            if cols:
                used = 'use_date' if 'use_date' in cols else 'date_modified'
                for r in con.execute(f'SELECT name_on_card, expiration_month, expiration_year, date_modified, {used} AS used '
                                     f'FROM credit_cards LIMIT ?', (MAX_ROWS,)):
                    out['autofill'].append({'field': 'saved card', 'value': f'{r["name_on_card"] or ""} (expires {r["expiration_month"]:02d}/'
                                            f'{r["expiration_year"]}; number encrypted)'.strip(), 'kind': 'saved card',
                                            'first_used': unix_s(r['date_modified']), 'last_used': unix_s(r['used'])})
        except (sqlite3.Error, TypeError, ValueError) as exc:
            out['errors'].append(f'credit_cards: {exc}')
    return out


def chromium_logins(path: Path) -> dict:
    out = {'logins': [], 'errors': []}
    with _Db(path) as con:
        try:
            cols = _columns(con, 'logins')
            last = 'date_last_used' if 'date_last_used' in cols else 'NULL'
            times = 'times_used' if 'times_used' in cols else 'NULL'
            for r in con.execute(f'SELECT origin_url, action_url, signon_realm, username_value, length(password_value) AS pw_len, '
                                 f'date_created, {last} AS last_used, {times} AS times_used, blacklisted_by_user FROM logins LIMIT ?',
                                 (MAX_ROWS,)):
                out['logins'].append({
                    'site': r['origin_url'] or r['signon_realm'], 'action_url': r['action_url'] or None,
                    'username': r['username_value'] or None, 'username_encrypted': False,
                    'password_saved': bool(r['pw_len']), 'never_save': bool(r['blacklisted_by_user']),
                    'created': webkit(r['date_created']), 'last_used': webkit(r['last_used']), 'times_used': r['times_used']})
        except sqlite3.Error as exc:
            out['errors'].append(f'logins: {exc}')
    return out


def chromium_bookmarks(path: Path) -> dict:
    out = {'bookmarks': [], 'errors': []}
    try:
        data = json.loads(path.read_bytes()[:64 << 20].decode('utf-8', 'replace'))
    except (ValueError, OSError) as exc:
        return {'bookmarks': [], 'errors': [f'Bookmarks: {exc}']}

    def walk(node, folder, depth):
        if depth > 64 or len(out['bookmarks']) >= MAX_ROWS or not isinstance(node, dict):
            return
        if node.get('type') == 'url':
            added = node.get('date_added')
            out['bookmarks'].append({'title': node.get('name'), 'url': node.get('url'), 'folder': folder,
                                     'added': webkit(int(added)) if str(added or '').isdigit() else None,
                                     'last_used': webkit(int(node['date_last_used'])) if str(node.get('date_last_used') or '').isdigit() else None})
        for child in node.get('children') or []:
            walk(child, f'{folder}/{node.get("name")}' if node.get('type') == 'folder' and depth else folder, depth + 1)

    names = {'bookmark_bar': 'Bookmarks bar', 'other': 'Other bookmarks', 'synced': 'Mobile bookmarks'}
    for key, root in ((data.get('roots') or {}).items() if isinstance(data, dict) else []):
        if isinstance(root, dict):
            walk(root, names.get(key, key), 0)
    return out


# -- Firefox --------------------------------------------------------------------------------------------------------
def firefox_places(path: Path) -> dict:
    """Bookmarks, search URLs and deleted moz_places rows (Firefox keeps places.sqlite in WAL mode)."""
    out = {'bookmarks': [], 'searches': [], 'recovered': [], 'errors': [], 'free_pages': 0, 'wal_frames': 0}
    places = {}
    with _Db(path) as con:
        try:
            for r in con.execute('SELECT id, url, title, last_visit_date FROM moz_places LIMIT ?', (MAX_ROWS,)):
                places[r['id']] = dict(r)
                eng = search_term(r['url'])
                if eng:
                    out['searches'].append({'term': eng[1], 'engine': eng[0], 'url': r['url'], 'time': unix_us(r['last_visit_date']),
                                            'source_table': 'moz_places', 'row_id': r['id']})
        except sqlite3.Error as exc:
            out['errors'].append(f'moz_places: {exc}')
        try:
            rows = {r['id']: dict(r) for r in con.execute('SELECT id, type, fk, parent, title, dateAdded, lastModified FROM moz_bookmarks')}
            roots = {'menu': 'Bookmarks menu', 'toolbar': 'Bookmarks toolbar', 'unfiled': 'Other bookmarks', 'mobile': 'Mobile bookmarks'}

            def folder(pid, depth=0):
                f = rows.get(pid)
                if not f or depth > 64 or f.get('parent') in (0, None) or f['id'] == f.get('parent'):
                    return ''
                name = roots.get(f.get('title') or '', f.get('title') or '')
                up = folder(f.get('parent'), depth + 1)
                return f'{up}/{name}' if up else name
            for b in rows.values():
                if b['type'] == 1 and b.get('fk') in places:
                    p = places[b['fk']]
                    out['bookmarks'].append({'title': b['title'] or p.get('title'), 'url': p['url'], 'folder': folder(b['parent']),
                                             'added': unix_us(b['dateAdded']), 'modified': unix_us(b['lastModified'])})
        except sqlite3.Error as exc:
            out['errors'].append(f'moz_bookmarks: {exc}')
    _recovered(path, out, ['moz_places'], 'FIREFOX', places)
    return out


def firefox_cookies(path: Path) -> dict:
    out = {'cookies': [], 'errors': []}
    with _Db(path) as con:
        try:
            cols = _columns(con, 'moz_cookies')
            last = 'lastAccessed' if 'lastAccessed' in cols else 'NULL'
            for r in con.execute(f'SELECT host, name, value, path, creationTime, expiry, isSecure, isHttpOnly, {last} AS last '
                                 f'FROM moz_cookies LIMIT ?', (MAX_ROWS,)):
                exp = r['expiry']
                out['cookies'].append({'host': r['host'], 'name': r['name'], 'value': r['value'], 'value_encrypted': False,
                                       'path': r['path'], 'created': unix_us(r['creationTime']),
                                       'expires': unix_s(exp / 1000 if exp and exp > 10**11 else exp),  # Firefox 106+: milliseconds
                                       'last_accessed': unix_us(r['last']), 'secure': bool(r['isSecure']),
                                       'http_only': bool(r['isHttpOnly'])})
        except sqlite3.Error as exc:
            out['errors'].append(f'moz_cookies: {exc}')
    return out


def firefox_formhistory(path: Path) -> dict:
    out = {'autofill': [], 'errors': []}
    with _Db(path) as con:
        try:
            for r in con.execute('SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory LIMIT ?', (MAX_ROWS,)):
                out['autofill'].append({'field': r['fieldname'], 'value': r['value'], 'times_used': r['timesUsed'],
                                        'kind': 'search bar' if r['fieldname'] == 'searchbar-history' else 'form field',
                                        'first_used': unix_us(r['firstUsed']), 'last_used': unix_us(r['lastUsed'])})
        except sqlite3.Error as exc:
            out['errors'].append(f'moz_formhistory: {exc}')
    return out


def firefox_logins(path: Path) -> dict:
    out = {'logins': [], 'errors': []}
    try:
        data = json.loads(path.read_bytes()[:16 << 20].decode('utf-8', 'replace'))
    except (ValueError, OSError) as exc:
        return {'logins': [], 'errors': [f'logins.json: {exc}']}
    for x in (data.get('logins') or [])[:MAX_ROWS] if isinstance(data, dict) else []:
        if not isinstance(x, dict):
            continue
        ms = lambda k: unix_s(x[k] / 1000) if isinstance(x.get(k), (int, float)) else None
        out['logins'].append({'site': x.get('hostname'), 'action_url': x.get('formSubmitURL') or None, 'username': None,
                              'username_encrypted': bool(x.get('encryptedUsername')), 'password_saved': bool(x.get('encryptedPassword')),
                              'never_save': False, 'created': ms('timeCreated'), 'last_used': ms('timeLastUsed'),
                              'password_changed': ms('timePasswordChanged'), 'times_used': x.get('timesUsed')})
    for site in (data.get('disabledHosts') or []) if isinstance(data, dict) else []:
        out['logins'].append({'site': site, 'never_save': True, 'password_saved': False, 'username': None, 'username_encrypted': False})
    return out


PARSERS = {
    ('CHROMIUM', 'history'): chromium_history, ('CHROMIUM', 'cookies'): chromium_cookies,
    ('CHROMIUM', 'web_data'): chromium_web_data, ('CHROMIUM', 'logins'): chromium_logins,
    ('CHROMIUM', 'bookmarks'): chromium_bookmarks,
    ('FIREFOX', 'places'): firefox_places, ('FIREFOX', 'cookies'): firefox_cookies,
    ('FIREFOX', 'formhistory'): firefox_formhistory, ('FIREFOX', 'logins_json'): firefox_logins,
}
