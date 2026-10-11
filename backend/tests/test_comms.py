"""Email, chat, cloud storage and browser depth: deleted SQLite rows (free space, free pages, WAL frames), the browser profile
parsers, MBOX/EML/MSG messages, Skype, OneDrive, Google Drive and Dropbox, and how the new records are tagged."""
import email.utils
import hashlib
import json
import shutil
import sqlite3
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'fixtures'))
import winfmt  # noqa: E402

from app.forensic import browser_depth as bd  # noqa: E402
from app.forensic import chat_cloud as cc  # noqa: E402
from app.forensic import mail  # noqa: E402
from app.forensic.artifact_locator import classify as locate  # noqa: E402
from app.forensic.modules import PROFILES, REGISTRY, plan  # noqa: E402
from app.forensic.modules.email_stores import kind_of  # noqa: E402
from app.forensic.sqlite_recover import recover, varint  # noqa: E402
from app.services.tags import natural_key, snapshot  # noqa: E402

T = lambda *a: datetime(*a, tzinfo=timezone.utc)
WEBKIT = lambda dt: int((dt.timestamp() + 11_644_473_600) * 1_000_000)
URLS = """CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,
          typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL)"""


def _store(saved):
    def save(data, name, mime):
        saved.append((name, data, mime))
        return {'sha256': hashlib.sha256(data).hexdigest(), 'store': f'mail/x/{name}'}
    return save


# --------------------------------------------------------------------------------- deleted SQLite rows
def test_varint():
    assert varint(bytes([0x05]), 0) == (5, 1)
    assert varint(bytes([0x81, 0x00]), 0) == (128, 2)
    assert varint(bytes([0x81]), 0) == (-1, 0)  # runs past the end
    assert varint(bytes([0xFF] * 8 + [0x01]), 0)[1] == 9


def _history(path, deleted, live=4):
    db = sqlite3.connect(path)
    db.execute('PRAGMA secure_delete=OFF')
    db.execute(URLS)
    for i in range(1, live + 1):
        db.execute('INSERT INTO urls VALUES (?,?,?,?,0,?,0)', (i, f'https://live{i}.example/', f'Live {i}', i, WEBKIT(T(2026, 9, 1, 9, i))))
    db.commit()
    for i, url, title in deleted:
        db.execute('INSERT INTO urls VALUES (?,?,?,1,0,?,0)', (i, url, title, WEBKIT(T(2026, 9, 1, 14, i))))
    db.commit()
    db.execute('DELETE FROM urls WHERE id > ?', (live,))
    db.commit()
    db.close()


def test_deleted_rows_in_free_space_are_recovered_and_live_rows_are_not(tmp_path):
    deleted = [(5, 'https://www.google.com/search?q=wipe+usb', 'wipe usb - Google Search'),
               (6, 'https://filetransfer.example.net/d/7Hq2xK', 'Your file is ready'),
               (7, 'https://www.google.com/search?q=clear+history', 'clear history - Google Search')]
    _history(tmp_path / 'History', deleted)
    res = recover(tmp_path / 'History', ['urls'])
    got = {r.values['url']: r for r in res['records']}
    assert set(got) == {u for _, u, _ in deleted}
    # The last row written sat at the start of the cell area and is whole (row ID kept); the others lost their first 4 bytes
    # to freeblock headers, and with them the row ID.
    assert got['https://www.google.com/search?q=clear+history'].rowid == 7
    assert {got[u].rowid for _, u, _ in deleted[:2]} == {None}
    for i, url, title in deleted:
        r = got[url]
        assert r.values['title'] == title and r.values['last_visit_time'] == WEBKIT(T(2026, 9, 1, 14, i)) and r.values['visit_count'] == 1
        assert r.source == 'free space' and r.file == 'database' and not r.previous_version
        data = (tmp_path / 'History').read_bytes()
        assert data.find(url.encode()) > r.offset - 64  # the reported offset is where the record is
    assert res['errors'] == []


def test_no_deletions_no_records_and_secure_delete_leaves_nothing(tmp_path):
    _history(tmp_path / 'clean', [])
    assert recover(tmp_path / 'clean', ['urls'])['records'] == []
    db = sqlite3.connect(tmp_path / 'secure')
    db.execute('PRAGMA secure_delete=ON')
    db.execute(URLS)
    db.execute("INSERT INTO urls VALUES (1,'https://a.example/','A',1,0,1,0)")
    db.execute("INSERT INTO urls VALUES (2,'https://gone.example/','Gone',1,0,2,0)")
    db.commit()
    db.execute('DELETE FROM urls WHERE id = 2')
    db.commit()
    db.close()
    assert b'gone.example' not in (tmp_path / 'secure').read_bytes()
    assert recover(tmp_path / 'secure', ['urls'])['records'] == []


def test_rows_on_freed_pages_keep_their_row_ids(tmp_path):
    long = [(i, f'https://www.google.com/search?q=deleted+{i}&x=' + 'y' * 300, f'deleted {i}') for i in range(5, 21)]
    _history(tmp_path / 'History', long)
    res = recover(tmp_path / 'History', ['urls'])
    data = (tmp_path / 'History').read_bytes()
    present = {u for _, u, _ in long if u.encode() in data}  # balancing rewrote some pages: only what is still there can be found
    got = {r.values['url']: r for r in res['records']}
    assert present <= set(got) and len(present) >= 8 and res['free_pages'] >= 1
    assert any(r.source == 'freelist page' and r.rowid is not None for r in got.values())
    for i, url, title in long:
        if url in got:
            assert got[url].values['title'] == title and got[url].rowid in (i, None)
    # A cell whose end was overwritten can still be misread as a shorter record; the history parser drops what does not
    # make sense as a visit (here a "time" thousands of years away), so only the real rows are reported.
    (tmp_path / 'p').mkdir()
    shutil.copy(tmp_path / 'History', tmp_path / 'p' / 'History')
    assert {r['url'] for r in bd.chromium_history(tmp_path / 'p' / 'History')['recovered']} == present


def test_wal_frames_hold_deleted_rows_and_older_versions(tmp_path):
    work = tmp_path / 'live'
    work.mkdir()
    db = sqlite3.connect(work / 'places.sqlite')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0, '
               'last_visit_date INTEGER)')
    db.execute("INSERT INTO moz_places VALUES (1, 'https://pastebin.example.com/raw/x9f2', 'Paste', 1, 1)")
    db.commit()
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    db.execute("INSERT INTO moz_places VALUES (3, 'https://www.bing.com/search?q=wipe', 'wipe - Search', 1, 1788264000000000)")
    db.commit()
    db.execute('DELETE FROM moz_places WHERE id = 3')
    db.commit()
    db.execute("UPDATE moz_places SET title = 'Paste (edited)' WHERE id = 1")
    db.commit()
    copy = tmp_path / 'copy'
    copy.mkdir()
    shutil.copy(work / 'places.sqlite', copy / 'places.sqlite')
    shutil.copy(work / 'places.sqlite-wal', copy / 'places.sqlite-wal')
    db.close()
    res = recover(copy / 'places.sqlite', ['moz_places'])
    assert res['wal_frames'] >= 3
    by = {(r.values['url'], r.values['title']): r for r in res['records']}
    gone = by[('https://www.bing.com/search?q=wipe', 'wipe - Search')]
    assert gone.source == 'WAL frame' and gone.file == 'wal' and gone.rowid == 3 and gone.frame and not gone.previous_version
    old = by[('https://pastebin.example.com/raw/x9f2', 'Paste')]  # the title before the edit
    assert old.previous_version and old.rowid == 1
    assert ('https://pastebin.example.com/raw/x9f2', 'Paste (edited)') not in by  # the live row is not "recovered"
    # Text extraction reads the -wal row by row: values on their own lines (raw strings would glue the address to its title).
    from app.forensic.sqlite_recover import wal_text
    from app.forensic.textextract import extract, method_for
    text = wal_text((copy / 'places.sqlite-wal').read_bytes())
    lines = text.split('\n')
    assert 'https://www.bing.com/search?q=wipe' in lines and 'wipe - Search' in lines and 'Paste (edited)' in lines
    assert len(lines) == len(set(lines)) and not any('wipewipe' in x for x in lines)
    assert wal_text(b'not a wal' * 10) is None
    assert method_for({'size': 10, 'mime': 'application/octet-stream', 'file_category': 'other',
                       'magic': 'SQLite Write-Ahead Log, version 3007000'}) == 'sqlite-wal'
    assert extract('sqlite-wal', (copy / 'places.sqlite-wal').read_bytes()).method == 'sqlite-wal'


# --------------------------------------------------------------------------------- browser profiles
def test_search_terms_from_urls():
    assert bd.search_term('https://www.google.com/search?q=how+to+wipe+usb+drive&oq=x') == ('Google', 'how to wipe usb drive')
    assert bd.search_term('https://www.google.co.uk/search?q=a%26b') == ('Google', 'a&b')
    assert bd.search_term('https://www.bing.com/search?q=securedelete') == ('Bing', 'securedelete')
    assert bd.search_term('https://duckduckgo.com/?q=tor+browser&ia=web') == ('DuckDuckGo', 'tor browser')
    assert bd.search_term('https://search.yahoo.com/search?p=usb') == ('Yahoo', 'usb')
    assert bd.search_term('https://www.youtube.com/results?search_query=wipe') == ('YouTube', 'wipe')
    assert bd.search_term('https://www.google.com/maps?q=x') is None
    assert bd.search_term('https://notgoogle.example/search?q=x') is None
    assert bd.search_term('file:///C:/x?q=1') is None


def test_profile_paths():
    c = bd.classify('/Users/alice/AppData/Local/Google/Chrome/User Data/Profile 2/Network/Cookies')
    assert (c['browser'], c['profile'], c['part'], c['user']) == ('Chrome', 'Profile 2', 'cookies', 'alice')
    assert bd.classify('/Users/bob/AppData/Roaming/Opera Software/Opera Stable/Login Data')['browser'] == 'Opera'
    assert bd.classify('/Users/bob/AppData/Roaming/Opera Software/Opera GX Stable/Default/Bookmarks')['browser'] == 'Opera GX'
    assert bd.classify('/Users/bob/AppData/Local/Vivaldi/User Data/Default/Web Data')['part'] == 'web_data'
    assert bd.classify('/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/logins.json')['part'] == 'logins_json'
    assert bd.classify('/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Preferences') is None
    # History of Opera and Vivaldi is read with the other Chromium browsers'.
    assert locate('/Users/bob/AppData/Roaming/Opera Software/Opera Stable/History') == ('CHROMIUM_HISTORY', {'browser': 'Opera'})
    assert locate('/Users/bob/AppData/Roaming/Opera Software/Opera GX Stable/Default/History')[1] == {'browser': 'Opera GX'}
    assert locate('/Users/bob/AppData/Local/Vivaldi/User Data/Default/History')[1] == {'browser': 'Vivaldi'}
    assert locate('/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History')[1] == {'browser': 'Chrome'}


def test_chromium_history_searches_and_recovered_rows(tmp_path):
    p = tmp_path / 'History'
    db = sqlite3.connect(p)
    db.execute('PRAGMA secure_delete=OFF')
    db.execute(URLS)
    db.execute('CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,lower_term LONGVARCHAR NOT NULL,'
               'term LONGVARCHAR NOT NULL)')
    db.execute("INSERT INTO urls VALUES (9, 'https://www.google.com/search?q=wipe+usb', 'wipe usb', 2, 0, ?, 0)", (WEBKIT(T(2026, 9, 1, 10, 2)),))
    db.execute("INSERT INTO keyword_search_terms VALUES (2, 9, 'wipe usb', 'Wipe USB')")
    db.execute("INSERT INTO urls VALUES (10, 'https://www.bing.com/search?q=tor', 'tor - Bing', 1, 0, ?, 0)", (WEBKIT(T(2026, 9, 1, 10, 3)),))
    db.execute("INSERT INTO urls VALUES (11, 'https://www.google.com/search?q=how+to+permanently+delete+files', "
               "'how to permanently delete files - Google Search', 1, 0, ?, 0)", (WEBKIT(T(2026, 9, 1, 14, 5)),))
    db.commit()
    db.execute('DELETE FROM urls WHERE id = 11')
    db.commit()
    db.close()
    out = bd.chromium_history(p)
    terms = {(s['term'], s['source_table'], bool(s.get('recovered'))) for s in out['searches']}
    assert terms == {('Wipe USB', 'keyword_search_terms', False), ('tor', 'urls', False),
                     ('how to permanently delete files', 'urls', True)}
    wipe = next(s for s in out['searches'] if s['term'] == 'Wipe USB')
    assert wipe['time'] == T(2026, 9, 1, 10, 2) and wipe['engine'] == 'Google'
    assert [r['url'] for r in out['recovered']] == ['https://www.google.com/search?q=how+to+permanently+delete+files']
    assert out['recovered'][0]['last_visit_time'] == T(2026, 9, 1, 14, 5) and out['recovered'][0]['recovered_from'] == 'free space'


def test_chromium_web_data_logins_bookmarks_and_cookies(tmp_path):
    db = sqlite3.connect(tmp_path / 'Web Data')
    db.execute('CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, '
               'date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value))')
    db.execute("INSERT INTO autofill VALUES ('email', 'a@x.example', 'a@x.example', ?, ?, 3)",
               (int(T(2026, 8, 20).timestamp()), int(T(2026, 9, 1, 14).timestamp())))
    db.commit()
    db.close()
    a = bd.chromium_web_data(tmp_path / 'Web Data')
    assert a['autofill'] == [{'field': 'email', 'value': 'a@x.example', 'kind': 'form field', 'times_used': 3,
                              'first_used': T(2026, 8, 20), 'last_used': T(2026, 9, 1, 14)}]
    assert 'credit_cards' not in ' '.join(a['errors'])  # an absent table is not an error

    db = sqlite3.connect(tmp_path / 'Login Data')
    db.execute('CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_value VARCHAR, password_value BLOB, '
               'signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, times_used INTEGER)')
    db.execute("INSERT INTO logins VALUES ('https://ft.example/login', '', 'alice', ?, 'https://ft.example/', ?, 0, 1)",
               (b'v10' + bytes(16), WEBKIT(T(2026, 9, 1, 14, 19, 5))))
    db.commit()
    db.close()
    lg = bd.chromium_logins(tmp_path / 'Login Data')['logins'][0]
    assert lg['site'] == 'https://ft.example/login' and lg['username'] == 'alice' and lg['password_saved'] and lg['last_used'] is None
    assert lg['created'] == T(2026, 9, 1, 14, 19, 5) and 'password' not in lg and not any(isinstance(v, bytes) for v in lg.values())

    (tmp_path / 'Bookmarks').write_text(json.dumps({'roots': {
        'bookmark_bar': {'type': 'folder', 'name': 'Bookmarks bar', 'children': [
            {'type': 'folder', 'name': 'tools', 'children': [
                {'type': 'url', 'name': 'SecureDelete', 'url': 'https://tools.example.org/', 'date_added': str(WEBKIT(T(2026, 9, 1, 10, 4)))}]}]},
        'other': {'type': 'folder', 'name': 'Other bookmarks', 'children': [{'type': 'url', 'name': 'X', 'url': 'https://x.example/'}]}}}))
    bm = bd.chromium_bookmarks(tmp_path / 'Bookmarks')['bookmarks']
    assert [(b['folder'], b['title'], b['added']) for b in bm] == [('Bookmarks bar/tools', 'SecureDelete', T(2026, 9, 1, 10, 4)),
                                                                     ('Other bookmarks', 'X', None)]
    (tmp_path / 'Bad').write_text('{not json')
    assert bd.chromium_bookmarks(tmp_path / 'Bad')['errors']

    db = sqlite3.connect(tmp_path / 'Cookies')
    db.execute('CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, '
               'path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, '
               'last_access_utc INTEGER NOT NULL, encrypted_value BLOB)')
    db.execute("INSERT INTO cookies VALUES (?, '.ft.example', 'sid', '', '/', 0, 1, 1, 0, ?)", (WEBKIT(T(2026, 9, 1, 14, 19)), b'v10abc'))
    db.execute("INSERT INTO cookies VALUES (?, 'old.example', 'k', 'plain', '/', 0, 0, 0, 0, '')", (WEBKIT(T(2018, 1, 1)),))
    db.commit()
    db.close()
    ck = {c['host']: c for c in bd.chromium_cookies(tmp_path / 'Cookies')['cookies']}
    assert ck['.ft.example']['value_encrypted'] and ck['.ft.example']['value'] is None and ck['.ft.example']['created'] == T(2026, 9, 1, 14, 19)
    assert ck['old.example']['value'] == 'plain' and not ck['old.example']['value_encrypted'] and ck['old.example']['expires'] is None


def test_firefox_bookmarks_formhistory_and_logins(tmp_path):
    db = sqlite3.connect(tmp_path / 'places.sqlite')
    db.execute('CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, last_visit_date INTEGER)')
    db.execute('CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title LONGVARCHAR, '
               'dateAdded INTEGER, lastModified INTEGER)')
    db.execute("INSERT INTO moz_places VALUES (1, 'https://pastebin.example.com/raw/x9f2', 'Paste', 1)")
    db.execute("INSERT INTO moz_places VALUES (2, 'https://duckduckgo.com/?q=paste+site', 'paste site', ?)", (int(T(2026, 9, 1).timestamp() * 1e6),))
    for row in [(1, 2, None, 0, '', 0, 0), (3, 2, None, 1, 'toolbar', 0, 0), (7, 2, None, 3, 'leaks', 0, 0),
                (8, 1, 1, 7, None, int(T(2026, 9, 1, 14, 31, 40).timestamp() * 1e6), 0)]:
        db.execute('INSERT INTO moz_bookmarks VALUES (?,?,?,?,?,?,?)', row)
    db.commit()
    db.close()
    out = bd.firefox_places(tmp_path / 'places.sqlite')
    assert out['bookmarks'] == [{'title': 'Paste', 'url': 'https://pastebin.example.com/raw/x9f2', 'folder': 'Bookmarks toolbar/leaks',
                                 'added': T(2026, 9, 1, 14, 31, 40), 'modified': None}]
    assert [(s['engine'], s['term'], s['time']) for s in out['searches']] == [('DuckDuckGo', 'paste site', T(2026, 9, 1))]

    db = sqlite3.connect(tmp_path / 'formhistory.sqlite')
    db.execute('CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER)')
    db.execute("INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', 'wipe free space', 2, 1, ?)", (int(T(2026, 9, 1, 14, 17).timestamp() * 1e6),))
    db.commit()
    db.close()
    f = bd.firefox_formhistory(tmp_path / 'formhistory.sqlite')['autofill'][0]
    assert (f['kind'], f['value'], f['times_used'], f['last_used']) == ('search bar', 'wipe free space', 2, T(2026, 9, 1, 14, 17))

    ms = int(T(2026, 9, 1, 14, 31, 30).timestamp() * 1000)
    (tmp_path / 'logins.json').write_text(json.dumps({'logins': [{'hostname': 'https://pastebin.example.com', 'formSubmitURL': '',
        'encryptedUsername': 'MDoE', 'encryptedPassword': 'MEIE', 'timeCreated': ms, 'timeLastUsed': ms, 'timesUsed': 1}],
        'disabledHosts': ['https://bank.example']}))
    lg = bd.firefox_logins(tmp_path / 'logins.json')['logins']
    assert lg[0]['site'] == 'https://pastebin.example.com' and lg[0]['username'] is None and lg[0]['username_encrypted']
    assert lg[0]['created'] == T(2026, 9, 1, 14, 31, 30) and lg[0]['password_saved']
    assert lg[1] == {'site': 'https://bank.example', 'never_save': True, 'password_saved': False, 'username': None, 'username_encrypted': False}


# --------------------------------------------------------------------------------- email
PNG = bytes.fromhex('89504e470d0a1a0a') + b'fake'


def _rfc822(status='0001'):
    return (f'X-Mozilla-Status: {status}\r\nMessage-ID: <m1@corp.example>\r\nDate: Tue, 01 Sep 2026 10:20:31 -0400\r\n'
            'Received: from mx (mx [10.0.0.1]) by imap; Tue, 01 Sep 2026 14:20:40 +0000\r\n'
            'From: Alice Example <alice@corp.example>\r\nTo: "Me" <alice.private@mailbox.example>, bob@x.example\r\nCc: carol@x.example\r\n'
            'Subject: =?utf-8?q?backup_=E2=9C=93?=\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="m"\r\n\r\n'
            '--m\r\nContent-Type: multipart/alternative; boundary="a"\r\n\r\n'
            '--a\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nfor home\r\n'
            '--a\r\nContent-Type: multipart/related; boundary="r"\r\n\r\n'
            '--r\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>for <b>home</b><img src="cid:logo@x"></p>\r\n'
            '--r\r\nContent-Type: image/png\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            + __import__('base64').b64encode(PNG).decode() + '\r\n--r--\r\n--a--\r\n'
            '--m\r\nContent-Type: text/csv\r\nContent-Disposition: attachment; filename="payroll-export.csv"\r\n\r\nemployee,iban\r\n--m--\r\n').encode()


def test_rfc822_message_fields_bodies_and_attachments():
    saved = []
    m = mail.from_rfc822(_rfc822(), 'Sent', _store(saved), 0)
    assert m['subject'] == 'backup ✓' and m['from_address'] == 'alice@corp.example' and m['from_name'] == 'Alice Example'
    assert [x['address'] for x in m['to']] == ['alice.private@mailbox.example', 'bob@x.example'] and m['cc'][0]['address'] == 'carol@x.example'
    assert m['sent'] == T(2026, 9, 1, 14, 20, 31) and m['received'] == T(2026, 9, 1, 14, 20, 40)
    assert m['body_text'].strip() == 'for home' and '<b>home</b>' in m['body_html'] and m['has_html']
    assert m['direction'] == 'sent' and not m['deleted'] and m['flags'] == ['read'] and m['message_id'] == '<m1@corp.example>'
    atts = {a['name']: a for a in m['attachments']}
    assert atts['payroll-export.csv']['inline'] is False and atts['payroll-export.csv']['size'] == len(b'employee,iban')
    logo = next(a for a in m['attachments'] if a['content_id'] == 'logo@x')
    assert logo['inline'] and logo['sha256'] == hashlib.sha256(PNG).hexdigest()
    assert m['attachment_count'] == 1 and len(saved) == 2
    assert 'Received: from mx' in m['headers'] and 'for home' not in m['headers']


def test_thunderbird_deleted_flag_html_only_body_and_mbox(tmp_path):
    m = mail.from_rfc822(_rfc822('0009'), 'INBOX', _store([]), 3)
    assert m['deleted'] and m['flags'] == ['read', 'deleted'] and m['direction'] == 'received'
    html_only = mail.from_rfc822(b'From: a@x\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n<html><style>p{}</style><p>Hello&amp;bye</p>'
                                 b'<script>x()</script><br>line two</html>', 'INBOX', _store([]), 0)
    assert html_only['body_text'] == 'Hello&bye\n\nline two' and html_only['snippet'] == 'Hello&bye line two'
    box = tmp_path / 'Sent'
    box.write_bytes(b'From - Tue Sep  1 14:20:31 2026\r\n' + _rfc822() + b'\r\nFrom - Tue Sep  1 14:41:07 2026\r\n'
                    + b'From: a@x\r\nSubject: second\r\nX-Mozilla-Status: 0009\r\n\r\nbody\r\n')
    assert mail.looks_like_mbox(box)
    got = list(mail.parse_mbox(box, 'Sent', _store([])))
    assert [(x['index'], x['subject'], x['deleted']) for x in got] == [(0, 'backup ✓', False), (1, 'second', True)]


def test_outlook_msg(tmp_path):
    def u(s):
        return s.encode('utf-16-le')
    ft = winfmt.filetime(T(2026, 9, 1, 14, 20, 31))
    props = bytes(32) + struct.pack('<HHIQ', 0x0040, 0x0039, 6, ft) + struct.pack('<HHIQ', 0x0040, 0x0E06, 6, ft + 90_000_000)
    streams = {
        '__substg1.0_0037001F': u('quarterly numbers'), '__substg1.0_0C1A001F': u('Alice Example'),
        '__substg1.0_5D01001F': u('alice@corp.example'), '__substg1.0_1000001F': u('see attached'),
        '__substg1.0_007D001F': u('X-Originating-IP: [198.51.100.7]\r\nSubject: quarterly numbers\r\n'),
        '__substg1.0_1035001F': u('<msg1@corp.example>'), '__properties_version1.0': props,
        '__recip_version1.0_#00000000/__substg1.0_3001001F': u('Bob'),
        '__recip_version1.0_#00000000/__substg1.0_3003001F': u('bob@x.example'),
        '__recip_version1.0_#00000000/__properties_version1.0': bytes(8) + struct.pack('<HHIQ', 0x0003, 0x0C15, 6, 2),
        '__attach_version1.0_#00000000/__substg1.0_3707001F': u('numbers.csv'),
        '__attach_version1.0_#00000000/__substg1.0_370E001F': u('text/csv'),
        '__attach_version1.0_#00000000/__substg1.0_37010102': b'a,b\n1,2\n',
        '__attach_version1.0_#00000000/__properties_version1.0': bytes(8) + struct.pack('<HHIQ', 0x0003, 0x3705, 6, 1),
    }
    p = tmp_path / 'numbers.msg'
    p.write_bytes(winfmt.compound_file(streams))
    saved = []
    m = mail.parse_msg(p, 'Desktop', _store(saved))
    assert (m['subject'], m['from_name'], m['from_address'], m['body_text']) == ('quarterly numbers', 'Alice Example', 'alice@corp.example', 'see attached')
    assert m['sent'] == T(2026, 9, 1, 14, 20, 31) and m['received'] == T(2026, 9, 1, 14, 20, 40)
    assert m['cc'] == [{'name': 'Bob', 'address': 'bob@x.example'}] and m['to'] == []
    assert m['originating_ip'] == '[198.51.100.7]' and m['message_id'] == '<msg1@corp.example>'
    assert [(a['name'], a['size'], a['mime']) for a in m['attachments']] == [('numbers.csv', 8, 'text/csv')] and saved[0][1] == b'a,b\n1,2\n'


def test_mailbox_kinds():
    assert kind_of('/Users/a/Documents/Outlook Files/a@x.pst') == ('PST', '')
    assert kind_of('/Users/a/AppData/Local/Microsoft/Outlook/a@x.ost') == ('OST', '')
    tb = '/Users/a/AppData/Roaming/Thunderbird/Profiles/p.default/'
    assert kind_of(tb + 'ImapMail/imap.corp.example/INBOX') == ('THUNDERBIRD', 'imap.corp.example/INBOX')
    assert kind_of(tb + 'Mail/Local Folders/Inbox.sbd/Work') == ('THUNDERBIRD', 'Local Folders/Inbox/Work')
    assert kind_of(tb + 'ImapMail/imap.corp.example/INBOX.msf') is None
    assert kind_of(tb + 'ImapMail/imap.corp.example/msgFilterRules.dat') is None
    assert kind_of('/Users/a/Desktop/invoice.eml') == ('EML', 'Desktop')


# --------------------------------------------------------------------------------- chat and cloud
def test_skype_text_and_app_detection():
    assert cc.skype_text('Don&apos;t <ss type="wink">;)</ss> <a href="https://x.example">https://x.example</a>') == "Don't ;) https://x.example"
    assert cc.skype_text(None) is None
    app = cc.app_of('/Users/alice/AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalState/sessions/x/session.db')
    assert app[:2] == ('WhatsApp', 'alice') and 'encrypted' in app[2]
    assert app[3] == '/Users/alice/AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm'
    assert cc.app_of('/Users/bob/AppData/Roaming/Telegram Desktop/tdata/key_datas')[0] == 'Telegram Desktop'
    assert cc.app_of('/Users/bob/Documents/Telegram Desktop/notes.txt') is None
    assert cc.classify('/Users/a/AppData/Roaming/Skype/alice.example/main.db') == ('SKYPE', {'user': 'a', 'account': 'alice.example'})
    assert cc.classify('/Users/a/AppData/Local/Microsoft/OneDrive/settings/Business1/SyncEngineDatabase.db')[1]['account'] == 'Business1'


def test_onedrive_paths_hashes_and_drivefs(tmp_path):
    sha1 = hashlib.sha1(b'payroll').hexdigest().upper()
    db = sqlite3.connect(tmp_path / 'SyncEngineDatabase.db')
    db.execute('CREATE TABLE od_ClientFolder_Records (parentResourceID TEXT, resourceID TEXT, folderName TEXT, folderStatus INTEGER)')
    db.execute('CREATE TABLE od_ClientFile_Records (parentResourceID TEXT, resourceID TEXT, fileName TEXT, size INTEGER, lastChange INTEGER, '
               'localHashDigest TEXT, sharedItem INTEGER)')
    db.execute("INSERT INTO od_ClientFolder_Records VALUES ('root', 'f1', 'Backup', 2)")
    db.execute("INSERT INTO od_ClientFolder_Records VALUES ('f1', 'f2', 'old', 2)")
    db.execute("INSERT INTO od_ClientFile_Records VALUES ('f2', 'a', 'payroll.csv', 7, ?, ?, 1)", (int(T(2026, 9, 1, 14, 26, 10).timestamp()), sha1))
    db.execute("INSERT INTO od_ClientFile_Records VALUES ('f1', 'b', 'x.bin', 3, 0, 'AAECAwQFBgcICQoLDA0ODxAREhM=', 0)")
    db.commit()
    db.close()
    files = {f['path']: f for f in cc.parse_onedrive(tmp_path / 'SyncEngineDatabase.db')['files']}
    assert set(files) == {'/Backup', '/Backup/old', '/Backup/old/payroll.csv', '/Backup/x.bin'}
    p = files['/Backup/old/payroll.csv']
    assert (p['hash_algorithm'], p['hash'], p['size'], p['modified'], p['shared']) == ('SHA-1', sha1.lower(), 7, T(2026, 9, 1, 14, 26, 10), True)
    assert files['/Backup/x.bin']['hash_algorithm'] == 'QuickXorHash' and files['/Backup/x.bin']['hash'] == bytes(range(20)).hex()
    assert files['/Backup/x.bin']['modified'] is None

    db = sqlite3.connect(tmp_path / 'metadata_sqlite_db')
    db.execute('CREATE TABLE items (stable_id INTEGER PRIMARY KEY, id TEXT, trashed INTEGER, is_folder INTEGER, is_owner INTEGER, '
               'local_title TEXT, file_size INTEGER, modified_date INTEGER, viewed_by_me_date INTEGER, shared_with_me_date INTEGER, mime_type TEXT)')
    db.execute('CREATE TABLE stable_parents (item_stable_id INTEGER, parent_stable_id INTEGER)')
    db.execute("INSERT INTO items VALUES (1, 'root', 0, 1, 1, 'My Drive', NULL, NULL, NULL, NULL, 'application/vnd.google-apps.folder')")
    db.execute("INSERT INTO items VALUES (2, 'abc', 1, 0, 1, 'payroll.csv', 7, ?, NULL, NULL, 'text/csv')", (int(T(2026, 9, 1, 14).timestamp() * 1000),))
    db.execute('INSERT INTO stable_parents VALUES (2, 1)')
    db.commit()
    db.close()
    g = {f['path']: f for f in cc.parse_drivefs(tmp_path / 'metadata_sqlite_db')['files']}
    assert g['/My Drive/payroll.csv']['trashed'] and g['/My Drive/payroll.csv']['modified'] == T(2026, 9, 1, 14) and g['/My Drive']['is_folder']

    (tmp_path / 'info.json').write_text(json.dumps({'personal': {'path': 'C:\\Users\\a\\Dropbox', 'is_team': False, 'subscription_type': 'Basic'},
                                                    'business': {'path': 'D:\\Dropbox (Corp)', 'is_team': True}}))
    acc = cc.parse_dropbox_info(tmp_path / 'info.json')['accounts']
    assert [(a['account_type'], a['sync_folder'], a['team']) for a in acc] == [('personal', 'C:\\Users\\a\\Dropbox', False),
                                                                              ('business', 'D:\\Dropbox (Corp)', True)]


def test_skype_database(tmp_path):
    db = sqlite3.connect(tmp_path / 'main.db')
    db.executescript("""
        CREATE TABLE Accounts (id INTEGER PRIMARY KEY, skypename TEXT, fullname TEXT, emails TEXT);
        CREATE TABLE Conversations (id INTEGER PRIMARY KEY, identity TEXT, displayname TEXT);
        CREATE TABLE Messages (id INTEGER PRIMARY KEY, convo_id INTEGER, chatname TEXT, author TEXT, from_dispname TEXT, dialog_partner TEXT,
                               timestamp INTEGER, type INTEGER, body_xml TEXT, edited_timestamp INTEGER);
        CREATE TABLE Transfers (id INTEGER PRIMARY KEY, type INTEGER, partner_handle TEXT, partner_dispname TEXT, status INTEGER,
                                starttime INTEGER, finishtime INTEGER, filepath TEXT, filename TEXT, filesize TEXT);
    """)
    db.execute("INSERT INTO Accounts VALUES (1, 'alice.example', 'Alice', 'a@x')")
    db.execute("INSERT INTO Conversations VALUES (1, 'dmitri', 'Dmitri K')")
    db.execute("INSERT INTO Messages VALUES (1, 1, '#c', 'dmitri', 'Dmitri K', NULL, ?, 61, 'hi &amp; bye', NULL)", (int(T(2025, 3, 12, 18).timestamp()),))
    db.execute("INSERT INTO Transfers VALUES (1, 2, 'dmitri', 'Dmitri K', 8, ?, ?, 'C:\\\\x\\\\list.csv', 'list.csv', '42')",
               (int(T(2025, 3, 12, 18, 5).timestamp()), int(T(2025, 3, 12, 18, 6).timestamp())))
    db.commit()
    db.close()
    s = cc.parse_skype(tmp_path / 'main.db')
    assert s['accounts'][0]['handle'] == 'alice.example' and s['calls'] == [] and s['contacts'] == []  # absent tables are empty, not errors
    m = s['messages'][0]
    assert (m['time'], m['conversation'], m['text'], m['kind']) == (T(2025, 3, 12, 18), 'Dmitri K', 'hi & bye', 'message')
    t = s['transfers'][0]
    assert (t['direction'], t['status'], t['size'], t['finished']) == ('sent', 'completed', 42, T(2025, 3, 12, 18, 6))


# --------------------------------------------------------------------------------- modules and tags
def test_modules_profiles_and_follows():
    for name in ('browser_depth', 'email', 'chat_cloud'):
        assert name in PROFILES['standard'] and name in PROFILES['full'] and name not in PROFILES['quick']
    assert 'email' in REGISTRY['hash_match'].follows and 'email' in REGISTRY['yara'].follows and 'email' in REGISTRY['content'].follows
    assert plan(['email'], {}) == ['tz_probe', 'fs_index', 'email']
    done = {m: {'status': 'COMPLETED', 'version': REGISTRY[m].version} for m in PROFILES['standard']}
    assert {'hash_match', 'yara', 'chat_cloud'} <= set(plan(['email'], done))  # attachments are re-matched and re-linked


def test_tag_keys_and_snapshots():
    s = {'evidence_id': 'E1', 'type': 'BROWSER_SEARCH', 'nk': 'abc', 'term': 'wipe usb', 'browser': 'Chrome', 'url': 'https://g/?q=x',
         'time': T(2026, 9, 1, 10, 2)}
    assert natural_key('BROWSER', s) == {'evidence_id': 'E1', 'type': 'BROWSER_SEARCH', 'nk': 'abc'}
    assert snapshot('BROWSER', s)['title'] == 'wipe usb' and snapshot('BROWSER', s)['detail'].startswith('Chrome search')
    old = {'evidence_id': 'E1', 'type': 'BROWSER_HISTORY', 'source_path': '/H', 'row_id': 3}
    assert natural_key('BROWSER', old) == {'evidence_id': 'E1', 'type': 'BROWSER_HISTORY', 'source_path': '/H', 'row_id': 3}
    m = {'evidence_id': 'E1', 'nk': 'm1', 'subject': 'backup', 'direction': 'sent', 'from_address': 'a@x', 'to': [{'address': 'b@y'}],
         'folder': 'Sent', 'time': T(2026, 9, 1, 14, 20, 31), 'store_path': '/S'}
    assert natural_key('EMAIL', m) == {'evidence_id': 'E1', 'nk': 'm1'}
    assert snapshot('EMAIL', m) == {'title': 'backup', 'detail': 'Email sent · from a@x to b@y · Sent', 'timestamp': '2026-09-01T14:20:31+00:00',
                                    'source': '/S'}
    c = {'evidence_id': 'E1', 'type': 'CLOUD_FILE', 'nk': 'c1', 'path': '/Backup/payroll.csv', 'provider': 'OneDrive', 'user': 'alice',
         'modified': T(2026, 9, 1, 14, 26, 10), 'source_path': '/db'}
    assert natural_key('CHAT_CLOUD', c) == {'evidence_id': 'E1', 'type': 'CLOUD_FILE', 'nk': 'c1'}
    assert snapshot('CHAT_CLOUD', c)['detail'] == 'Cloud storage file (OneDrive) · alice'


def test_email_dates():
    assert mail._date('Tue, 01 Sep 2026 10:20:31 -0400') == T(2026, 9, 1, 14, 20, 31)
    assert mail._date('not a date') is None and mail._date(None) is None
    assert email.utils.format_datetime(T(2026, 9, 1)) and mail._utc(datetime(2026, 9, 1)) == T(2026, 9, 1)
