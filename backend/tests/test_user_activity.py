"""Jump Lists, the Windows Timeline, thumbnail caches, SRUM and Windows Search: the writers read back by the parsers, the
format details the real samples showed, and how search index entries are matched with the disk and the thumbnails."""
import base64
import json
import os
import sqlite3
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'fixtures'))
import winfmt  # noqa: E402

from app.forensic import activities as act  # noqa: E402
from app.forensic import jumplists as jl  # noqa: E402
from app.forensic import srum as sr  # noqa: E402
from app.forensic import thumbcache as tc  # noqa: E402
from app.forensic import winsearch as ws  # noqa: E402
from app.forensic.modules.user_activity import UserActivityModule, fs_path  # noqa: E402

T = lambda *a: datetime(*a, tzinfo=timezone.utc)
MAC = 0x00155D01A2B3


def _lnk(path, **kw):
    return winfmt.shell_link(path, size=kw.pop('size', 10), created=T(2026, 9, 1, 9), modified=T(2026, 9, 1, 9, 30),
                             accessed=T(2026, 9, 1, 14), **kw)


# --------------------------------------------------------------------------------- Jump Lists
def test_automatic_destinations_read_back(tmp_path):
    entries = [
        dict(number=3, path='E:\\payroll-export.csv', last_used=T(2026, 9, 1, 14, 14, 6), access_count=1, hostname='laptop-07',
             droid_volume=winfmt.droid_uuid(100, MAC), droid_file=winfmt.droid_uuid(3, MAC),
             lnk=_lnk('E:\\payroll-export.csv', drive_type=winfmt.DRIVE_REMOVABLE, volume_label='CRUZER', drive_serial=0x6A3C91F2)),
        dict(number=10, path='C:\\Users\\alice\\cleanup.ps1', last_used=T(2026, 9, 1, 10, 6, 45), access_count=2, pin=0,
             lnk=_lnk('C:\\Users\\alice\\cleanup.ps1')),
    ]
    p = tmp_path / '9b9cdc69c1c24e2b.automaticDestinations-ms'
    p.write_bytes(winfmt.automatic_destinations(entries))
    r = jl.parse_automatic(p)
    assert r['status'] == 'COMPLETED' and r['version'] == 4 and r['pinned'] == 1 and r['errors'] == []
    a, b = r['entries']
    assert (a['entry_number'], a['path'], a['last_used'], a['pinned'], a['access_count'], a['hostname']) == \
        (3, 'E:\\payroll-export.csv', T(2026, 9, 1, 14, 14, 6), False, 1, 'laptop-07')
    assert a['mac_address'] == '00:15:5d:01:a2:b3' and a['droid_file_id'].endswith('-00155d01a2b3')
    assert a['lnk']['target_path'] == 'E:\\payroll-export.csv' and a['lnk']['drive_type'] == 'Removable' and a['lnk']['volume_label'] == 'CRUZER'
    assert (b['entry_number'], b['pinned'], b['pin_position'], b['access_count'], b['hostname'], b['mac_address']) == (10, True, 0, 2, None, None)
    assert b['lnk']['target_path'] == 'C:\\Users\\alice\\cleanup.ps1'  # stream "a" (entry 10 in hexadecimal)


def test_automatic_destinations_without_destlist_and_damaged(tmp_path):
    p = tmp_path / 'x.automaticDestinations-ms'
    p.write_bytes(winfmt.compound_file({'1': _lnk('C:\\a.txt')}))
    r = jl.parse_automatic(p)
    assert r['errors'] == ['no DestList stream'] and r['entries'][0]['lnk']['target_path'] == 'C:\\a.txt'
    assert r['entries'][0]['note'] == 'stream without a DestList entry'
    p.write_bytes(b'not a compound file')
    assert jl.parse_automatic(p)['status'] == 'FAILED'


def test_custom_destinations_categories(tmp_path):
    chrome = lambda args, name: _lnk('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', arguments=args, description=name)
    data = winfmt.custom_destinations([
        ('custom', 'Recently closed', [chrome('https://filetransfer.example.net/upload', 'Anonymous File Upload')]),
        ('known', 1),
        ('tasks', [chrome('--new-window', 'New window'), chrome('--incognito', 'New Incognito window')]),
        ('known', 2),
    ])
    p = tmp_path / 'c.customDestinations-ms'
    p.write_bytes(data)
    r = jl.parse_custom(p)
    assert r['errors'] == [] and [(c['name'], c['kind']) for c in r['categories']] == \
        [('Recently closed', 'custom'), ('Frequent', 'known'), ('Tasks', 'tasks'), ('Recent', 'known')]
    assert [(e['category'], e['lnk']['arguments'], e['lnk']['description']) for e in r['entries']] == [
        ('Recently closed', 'https://filetransfer.example.net/upload', 'Anonymous File Upload'),
        ('Tasks', '--new-window', 'New window'), ('Tasks', '--incognito', 'New Incognito window')]
    # A damaged header: the links are still found by their own header.
    p.write_bytes(data[:12] + b'\x07\x00\x00\x00' + data[16:])
    r = jl.parse_custom(p)
    assert r['errors'] and sorted(e['lnk']['arguments'] for e in r['entries']) == \
        ['--incognito', '--new-window', 'https://filetransfer.example.net/upload']
    p.write_bytes(b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')  # an empty list (Plaso's c98dce577f884ef8 sample is like this)
    assert jl.parse_custom(p) == {'status': 'COMPLETED', 'categories': [], 'entries': [], 'errors': [], 'version': 2}


@pytest.mark.parametrize('kw', [{}, {'arguments': '-x', 'working_dir': 'C:\\'}, {'description': 'd', 'arguments': 'a' * 300}])
def test_lnk_size_is_the_link_length(kw):
    data = _lnk('C:\\Windows\\notepad.exe', **kw)
    assert jl.lnk_size(data + b'trailing bytes') == len(data)
    assert jl.lnk_size(b'\0' * 100) is None and jl.lnk_size(data[:60]) is None


def test_app_names():
    assert jl.app_name('9B9CDC69C1C24E2B') == 'Notepad (64-bit)' and jl.app_name('1b4dd67f29cb1962') == 'Windows Explorer (Windows 7)'
    assert jl.app_name('0123456789abcdef') is None


# --------------------------------------------------------------------------------- Windows Timeline
def _activities_db(path, rows, operations=()):
    con = sqlite3.connect(path)
    cols = ('Id BLOB, AppId TEXT, ActivityType INT, Payload BLOB, StartTime INT, EndTime INT, LastModifiedTime INT, '
            'ExpirationTime INT, ClipboardPayload BLOB, PlatformDeviceId TEXT')
    con.execute(f'CREATE TABLE Activity ({cols})')
    con.execute(f'CREATE TABLE ActivityOperation (OperationOrder INTEGER PRIMARY KEY, OperationType INT, CreatedTime INT, {cols})')
    for r in rows:
        con.execute('INSERT INTO Activity (Id, AppId, ActivityType, Payload, StartTime, EndTime, ClipboardPayload) VALUES (?,?,?,?,?,?,?)', r)
    for r in operations:
        con.execute('INSERT INTO ActivityOperation (OperationType, CreatedTime, Id, AppId, ActivityType, Payload, StartTime) VALUES (?,?,?,?,?,?,?)', r)
    con.commit()
    con.close()


def test_activities_cache(tmp_path):
    notepad = json.dumps([{'application': '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe', 'platform': 'windows_win32'},
                          {'application': '', 'platform': 'alternateId'}])
    store = json.dumps([{'application': 'Microsoft.SkyDrive.Desktop', 'platform': 'packageId'}])
    clip = json.dumps([{'content': base64.b64encode(b'E:\\payroll-export.csv').decode(), 'formatName': 'Text'}])
    start = int(T(2026, 9, 1, 14, 14, 6).timestamp())
    _activities_db(tmp_path / 'a.db', [
        (b'\x01' * 16, notepad, 5, json.dumps({'displayText': 'payroll-export.csv', 'description': 'E:\\payroll-export.csv',
                                                'appDisplayName': 'Notepad'}).encode(), start, 0, None),
        (b'\x02' * 16, notepad, 6, json.dumps({'type': 'UserEngaged', 'activeDurationSeconds': 95}).encode(), start, start + 95, None),
        (b'\x03' * 16, store, 10, b'{}', start - 36, 0, clip),
    ], operations=[(3, start + 400, b'\x04' * 16, store, 5, b'{"displayText": "x.png"}', start - 600)])
    r = act.parse_activities_cache(tmp_path / 'a.db')
    assert r['status'] == 'COMPLETED' and len(r['activities']) == 4
    assert [a['activity_type'] for a in r['activities']] == [10, 5, 6, 5]  # in order of start time, then the pending operations
    copied, opened, engaged, deleted = r['activities']
    assert opened['app'] == 'C:\\Windows\\System32\\notepad.exe'  # known folder resolved
    assert (opened['activity_label'], opened['display_text'], opened['start_time'], opened['end_time']) == \
        ('Opened', 'payroll-export.csv', T(2026, 9, 1, 14, 14, 6), None)
    assert engaged['duration_seconds'] == 95 and engaged['end_time'] == T(2026, 9, 1, 14, 15, 41)
    assert copied['clipboard_text'] == 'E:\\payroll-export.csv' and copied['app'] == 'Microsoft.SkyDrive.Desktop'
    assert (deleted['table'], deleted['operation_type'], deleted['operation_label']) == ('ActivityOperation', 3, 'deleted by the user')


def test_activities_cache_read_only_folder_and_bad_files(tmp_path):
    db = tmp_path / 'ro' / 'a.db'
    db.parent.mkdir()
    _activities_db(db, [(b'\x01' * 16, '[]', 5, b'{}', 1, 0, None)])
    con = sqlite3.connect(db)
    con.execute('PRAGMA journal_mode=WAL')
    con.close()
    os.chmod(db.parent, 0o555)  # a WAL database in a folder that cannot be written: read as it is on disk
    try:
        r = act.parse_activities_cache(db)
        assert r['status'] == 'COMPLETED' and len(r['activities']) == 1
    finally:
        os.chmod(db.parent, 0o755)
    (tmp_path / 'x.db').write_bytes(b'junk')
    assert act.parse_activities_cache(tmp_path / 'x.db')['status'] == 'FAILED'
    sqlite3.connect(tmp_path / 'y.db').execute('CREATE TABLE t (a)').connection.close()
    assert act.parse_activities_cache(tmp_path / 'y.db')['errors'] == ['no Activity table (not an ActivitiesCache database)']


def test_activity_helpers():
    assert act._time(0) is None and act._time(None) is None and act._time(10 ** 12) is None
    assert act.clipboard_text(json.dumps([{'content': base64.b64encode('héllo'.encode()).decode(), 'formatName': 'Text'}])) == 'héllo'
    assert act.clipboard_text('not json') is None and act.clipboard_text(json.dumps([{'formatName': 'Bitmap', 'content': 'AA=='}])) is None
    assert act.application(json.dumps([{'application': 'a.exe', 'platform': 'other'}]))[0] == 'a.exe'


# --------------------------------------------------------------------------------- thumbnails
PNG = b'\x89PNG\r\n\x1a\n' + b'\0' * 40
JPEG = b'\xff\xd8\xff\xe0' + b'\0' * 30


def test_thumbcache_windows_10(tmp_path):
    p = tmp_path / 'thumbcache_256.db'
    p.write_bytes(winfmt.thumbcache([dict(hash=0x9F3A6C21E4D07B58, width=256, height=144, data=PNG), dict(hash=1),
                                     dict(hash=0x41C7D2E09B6F3A15, width=48, height=32, data=JPEG)]))
    r = tc.parse_thumbcache(p)
    assert (r['status'], r['version'], r['windows'], r['cache_type'], r['errors']) == ('COMPLETED', 0x20, 'Windows 10 or 11', 4, [])
    a, b = r['entries']  # the entry without a picture is skipped
    assert (a['hash'], a['identifier'], a['width'], a['height'], a['image_type']) == ('9f3a6c21e4d07b58', '9f3a6c21e4d07b58', 256, 144, 'png')
    assert tc.read_data(p, a) == PNG and tc.read_data(p, b) == JPEG and b['image_type'] == 'jpeg'


def test_thumbcache_windows_7_and_bad_files(tmp_path):
    ident = 'abcd'.encode('utf-16-le')
    entry = b'CMMM' + struct.pack('<IQIIIIQQ', 48 + len(ident) + len(JPEG), 0x1234, len(ident), 0, len(JPEG), 0, 0, 0) + ident + JPEG
    p = tmp_path / 't7.db'
    p.write_bytes(b'CMMM' + struct.pack('<IIIII', 0x15, 2, 24, 24 + len(entry), 1) + entry)
    r = tc.parse_thumbcache(p)
    assert r['windows'] == 'Windows 7' and [(e['hash'], e['width'], e['image_type']) for e in r['entries']] == [('0000000000001234', None, 'jpeg')]
    p.write_bytes(b'XXXX' + b'\0' * 40)
    assert tc.parse_thumbcache(p)['status'] == 'FAILED'
    p.write_bytes(b'CMMM' + struct.pack('<IIIII', 0x20, 4, 0, 24, 100) + b'CMMM' + struct.pack('<I', 999999) + b'\0' * 60)
    assert 'impossible size' in tc.parse_thumbcache(p)['errors'][0]


# --------------------------------------------------------------------------------- SRUM and Windows Search
def test_srum_helpers(tmp_path):
    assert sr.sid_string(bytes.fromhex('010100000000000512000000')) == 'S-1-5-18'
    assert sr.sid_string(bytes.fromhex('010500000000000515000000') + struct.pack('<IIII', 1, 2, 3, 1001)) == 'S-1-5-21-1-2-3-1001'
    assert sr.sid_string(b'\x01') is None
    assert sr.app_path('\\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe') == '\\Windows\\System32\\svchost.exe'
    (tmp_path / 'SRUDB.dat').write_bytes(b'\0' * 8192)
    assert sr.parse_srum(tmp_path / 'SRUDB.dat')['status'] == 'FAILED'


def test_windows_search_decoding():
    text = b'\x01Choose which programs you want Windows to use'
    assert ws.ws_decode(ws.ws_decode(text)) == text
    assert ws.summary_text(ws.ws_decode(text)) == 'Choose which programs you want Windows to use'
    assert ws.summary_text(ws.ws_decode(b'\x00' + 'Résumé'.encode('utf-16-le'))) == 'Résumé'
    assert ws._number(bytes.fromhex('0000000000000502')) == 1282 and ws._number(b'*' * 8) is None
    assert ws._number((2191).to_bytes(8, 'little')) == 2191  # a little-endian value is read when big-endian makes no sense
    assert ws._filetime(bytes.fromhex('01ca04401cc35f15')) == T(2009, 7, 14, 5, 1, 14, 46440)
    assert ws._filetime(winfmt.filetime(T(2026, 9, 1, 9, 41, 2)).to_bytes(8, 'little')) == T(2026, 9, 1, 9, 41, 2)


def _windows_db(path, items):
    con = sqlite3.connect(path)
    con.execute('CREATE TABLE SystemIndex_1_PropertyStore_Metadata (Id INTEGER, UniqueKey TEXT)')
    con.execute('CREATE TABLE SystemIndex_1_PropertyStore (WorkId INTEGER, ColumnId INTEGER, Value BLOB)')
    keys = ['4447-System_ItemPathDisplay', '4631-System_Size', '15F-System_DateModified', '4703-System_ThumbnailCacheId',
            '4539-System_Search_AutoSummary', '4520-System_FileOwner', '9999-System_Unrelated']
    for i, k in enumerate(keys):
        con.execute('INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (?, ?)', (i, k.replace('15F', '4568')))
    for work_id, values in items.items():
        for i, k in enumerate(keys):
            if k.split('-', 1)[1] in values:
                con.execute('INSERT INTO SystemIndex_1_PropertyStore VALUES (?, ?, ?)', (work_id, i, values[k.split('-', 1)[1]]))
    con.commit()
    con.close()


def test_windows_db(tmp_path):
    _windows_db(tmp_path / 'Windows.db', {
        7: {'System_ItemPathDisplay': 'C:\\Users\\alice\\Pictures\\payroll-screenshot.png', 'System_Size': 48211,
            'System_DateModified': winfmt.filetime(T(2026, 9, 1, 13, 59, 12)).to_bytes(8, 'big'),
            'System_ThumbnailCacheId': (0x9F3A6C21E4D07B58).to_bytes(8, 'big'), 'System_FileOwner': 'LAPTOP-07\\alice'},
        8: {'System_ItemPathDisplay': 'C:\\Users\\alice\\Documents\\payroll-export.csv', 'System_Size': (2191).to_bytes(8, 'big'),
            'System_Search_AutoSummary': 'employee,iban,salary', 'System_Unrelated': 'x'},
    })
    r = ws.parse_windows_db(tmp_path / 'Windows.db')
    assert r['status'] == 'COMPLETED' and r['table'] == 'SystemIndex_1_PropertyStore' and len(r['entries']) == 2
    a, b = r['entries']
    assert (a['work_id'], a['name'], a['size'], a['modified'], a['thumbnail_cache_id'], a['owner']) == \
        (7, 'payroll-screenshot.png', 48211, T(2026, 9, 1, 13, 59, 12), '9f3a6c21e4d07b58', 'LAPTOP-07\\alice')
    assert (b['size'], b['summary'], b['folder']) == (2191, 'employee,iban,salary', None)
    sqlite3.connect(tmp_path / 'other.db').execute('CREATE TABLE t (a)').connection.close()
    assert ws.parse_windows_db(tmp_path / 'other.db')['status'] == 'FAILED'


# --------------------------------------------------------------------------------- the module: disk state and thumbnails
class _Cursor(list):
    pass


class _FS:
    def __init__(self, entries):
        self.entries = entries

    def find(self, q, projection=None):
        return _Cursor(e for e in self.entries if e['path'] in q['path']['$in'])


class _Ctx:
    def __init__(self, entries):
        self.db = {'fs_entries': _FS(entries)}
        self.eid, self.counts = 'EVID-1', {}

    def count(self, key, n=1):
        self.counts[key] = self.counts.get(key, 0) + n


def test_search_entries_are_matched_with_the_disk_and_the_thumbnails():
    m = UserActivityModule()
    m.ctx = _Ctx([{'path': '/Users/alice/notes.txt', 'deleted': False}, {'path': '/Users/alice/export.csv', 'deleted': True}])
    m.events = []
    base = {'case_id': 'C', 'evidence_id': 'EVID-1', 'source': 'WINDOWS_SEARCH', 'source_path': '/x/Windows.edb'}
    rows = [dict(base, path='C:\\Users\\alice\\notes.txt'), dict(base, path='C:\\Users\\alice\\export.csv', gather_time=T(2026, 9, 1)),
            dict(base, path='C:\\Users\\alice\\shot.png', thumbnail_cache_id='9f3a6c21e4d07b58', modified=T(2026, 9, 1, 13)),
            dict(base, path='E:\\Exports\\x.csv')]
    m.rows = rows + [{'type': 'THUMBNAIL', 'entry_hash': '9f3a6c21e4d07b58'}, {'type': 'THUMBNAIL', 'entry_hash': '0000000000000001'}]
    m._link_search(rows)
    assert [r['file_state'] for r in rows] == ['on disk', 'deleted', 'not on the disk', None]
    assert m.rows[-2]['indexed_path'] == 'C:\\Users\\alice\\shot.png' and m.rows[-2]['indexed_file_state'] == 'not on the disk'
    assert 'indexed_path' not in m.rows[-1]
    assert m.ctx.counts == {'search_entries_not_on_disk': 2}
    assert [(e['type'], e['timestamp']) for e in m.events] == [('SEARCH_INDEXED', T(2026, 9, 1)), ('SEARCH_INDEXED', T(2026, 9, 1, 13))]


def test_fs_path():
    assert fs_path('C:\\Users\\alice\\x.txt') == '/Users/alice/x.txt' and fs_path('c:\\a') == '/a'
    assert fs_path('E:\\x') is None and fs_path(None) is None and fs_path('\\\\server\\share\\x') is None
