import lzma
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.forensic import tools
from app.forensic.artifact_locator import ArtifactCollector, classify
from app.forensic.browser_artifacts import parse_chromium_history, parse_firefox_places
from app.forensic.filesystem import parse_bodyfile_line
from app.forensic.timeline import browser_events, macb_events, usb_events
from app.forensic.usb import filetime_to_datetime, merge_usb_sources, parse_setupapi, parse_system_hive, split_instance

FIXTURES = Path(__file__).parent / 'fixtures'


# --- Sleuth Kit output parsing ------------------------------------------------

def test_bodyfile_line_allocated_file():
    e = parse_bodyfile_line('0|/Users/alice/Documents/project-notes.txt|58|r/rrwxrwxrwx|0|0|1680|1787875200|1787933050|0|1787933050')
    assert e['path'] == '/Users/alice/Documents/project-notes.txt'
    assert e['name'] == 'project-notes.txt'
    assert e['inode'] == '58'
    assert e['size'] == 1680
    assert e['deleted'] is False and e['is_dir'] is False and e['is_virtual'] is False
    assert e['mtime'] == datetime.fromtimestamp(1787933050, tz=timezone.utc)
    assert e['ctime'] is None  # 0 = not recorded


def test_bodyfile_line_deleted_ntfs_entry_with_pipe_in_name():
    e = parse_bodyfile_line('0|/Users/bob/odd|name.txt (deleted)|64-128-2|r/rrwxrwxrwx|0|0|10|1|2|3|4')
    assert e['path'] == '/Users/bob/odd|name.txt'
    assert e['deleted'] is True and e['deleted_status'] == 'deleted'
    assert e['inode'] == '64-128-2'


def test_bodyfile_line_virtual_and_malformed():
    assert parse_bodyfile_line('0|/$FAT1|2032100|v/v---------|0|0|508416|0|0|0|0')['is_virtual'] is True
    assert parse_bodyfile_line('garbage') is None


def test_macb_events_groups_identical_timestamps():
    e = parse_bodyfile_line('0|/a.txt (deleted)|5|r/r---------|0|0|1|100|200|0|200')
    events = macb_events(e, 'CASE-1', 'EVID-1', 2048)
    assert [(ev['macb'], ev['timestamp'].timestamp()) for ev in events] == [('.a..', 100), ('m..b', 200)]
    assert all(ev['deleted'] and ev['description'].endswith('(deleted)') for ev in events)
    assert macb_events(parse_bodyfile_line('0|/$MBR|1|v/v---------|0|0|512|0|0|0|0'), 'C', 'E', 0) == []


MMLS_OUTPUT = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000131071   0000129024   Win95 FAT32 (0x0c)
"""


def test_parse_mmls(monkeypatch):
    monkeypatch.setattr(tools, 'run', lambda *a, **k: {'available': True, 'returncode': 0, 'stdout': MMLS_OUTPUT, 'stderr': ''})
    parts = tools.parse_mmls(Path('x.dd'))['partitions']
    assert len(parts) == 3
    fat = parts[2]
    assert (fat['start'], fat['end'], fat['length'], fat['description']) == (2048, 131071, 129024, 'Win95 FAT32 (0x0c)')
    assert parts[0]['is_meta'] and parts[1]['is_unallocated'] and not fat['is_meta'] and not fat['is_unallocated']


# --- Artifact location ----------------------------------------------------------

def test_classify_known_artifact_paths():
    assert classify('/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History') == ('CHROMIUM_HISTORY', {'browser': 'Chrome'})
    assert classify('/Users/a/AppData/Local/Microsoft/Edge/User Data/Profile 1/History')[1]['browser'] == 'Edge'
    assert classify('/Users/a/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite')[0] == 'FIREFOX_PLACES'
    assert classify('/Windows/System32/config/SYSTEM')[0] == 'SYSTEM_HIVE'
    assert classify('/WINDOWS/inf/setupapi.dev.log')[0] == 'SETUPAPI_LOG'
    assert classify('/Windows/System32/config/SYSTEM.LOG1') is None


def test_collector_ignores_deleted_and_attaches_sidecars():
    c = ArtifactCollector()
    base = '/Users/a/AppData/Local/Google/Chrome/User Data/Default/History'
    c.observe({'path': base + '-journal', 'inode': '9', 'deleted': False, 'is_dir': False, 'is_virtual': False}, 0)
    c.observe({'path': base, 'inode': '8', 'deleted': False, 'is_dir': False, 'is_virtual': False}, 0)
    c.observe({'path': '/Windows/System32/config/SYSTEM', 'inode': '7', 'deleted': True, 'is_dir': False, 'is_virtual': False}, 0)
    items = c.resolved()
    assert len(items) == 1
    assert items[0]['sidecars'] == [{'path': base + '-journal', 'inode': '9'}]


# --- USB -------------------------------------------------------------------------

@pytest.fixture(scope='module')
def system_hive(tmp_path_factory):
    path = tmp_path_factory.mktemp('hive') / 'SYSTEM'
    path.write_bytes(lzma.open(FIXTURES / 'SYSTEM.xz').read())
    return path


def test_filetime_and_instance_helpers():
    assert filetime_to_datetime('e01b2da028f0cb01').year == 2011
    assert filetime_to_datetime(b'\x00' * 8) is None
    assert split_instance('AA951D0000007252&0') == ('AA951D0000007252', True)
    assert split_instance('6&2ab01149&0') == ('6&2ab01149&0', False)


def test_parse_system_hive_usb_device(system_hive):
    r = parse_system_hive(system_hive)
    assert r['status'] == 'COMPLETED'
    assert r['current_control_set'] == 'ControlSet001'
    assert len(r['devices']) == 1  # same device in ControlSet001 and 002 is merged
    d = r['devices'][0]
    assert d['serial'] == 'AA951D0000007252' and d['serial_is_unique']
    assert (d['vendor'], d['product'], d['revision']) == ('HP', 'v100w', '1024')
    assert d['friendly_name'] == 'HP v100w USB Device'
    assert (d['vid'], d['pid']) == ('03F0', '3207')
    assert d['drive_letters'] == ['E:']
    assert d['first_install'].startswith('2011-04-0')
    assert set(d['control_sets']) == {'ControlSet001', 'ControlSet002'}


SETUPAPI = """>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_HP&Prod_v100w&Rev_1024\\AA951D0000007252&0]
>>>  Section start 2011/04/03 21:15:05.402
<<<  Section end 2011/04/03 21:15:07.960
>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\\4C530001230518109141&0]
>>>  Section start 2026/09/01 10:12:44.020
>>>  [Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_1234\\3&11583659&0&10]
>>>  Section start 2026/09/01 10:00:00.000
"""


def test_setupapi_and_merge(tmp_path, system_hive):
    log = tmp_path / 'setupapi.dev.log'
    log.write_text(SETUPAPI)
    parsed = parse_setupapi(log, bias_minutes=-60)  # UTC = local - 60 min
    assert [e['instance_id'] for e in parsed['entries']] == ['AA951D0000007252&0', '4C530001230518109141&0']
    assert parsed['entries'][0]['install_time'] == '2011-04-03T20:15:05+00:00'

    devices = merge_usb_sources(parse_system_hive(system_hive)['devices'], parsed['entries'])
    by_serial = {d['serial']: d for d in devices}
    assert by_serial['AA951D0000007252']['setupapi_first_install'] == '2011-04-03T20:15:05+00:00'
    sandisk = by_serial['4C530001230518109141']
    assert sandisk['source'] == 'SETUPAPI_LOG' and sandisk['vendor'] == 'SanDisk' and sandisk['first_install'] is None
    events = usb_events(devices, 'CASE-1', 'EVID-1')
    assert {e['usb_event'] for e in events} >= {'FIRST_INSTALL', 'SETUPAPI_FIRST_INSTALL'}


# --- Browsers --------------------------------------------------------------------

def _chrome_ts(dt):
    return int((dt.timestamp() + 11_644_473_600) * 1_000_000)


def test_chromium_history_and_timeline(tmp_path):
    db_path = tmp_path / 'History'
    db = sqlite3.connect(db_path)
    db.executescript('CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, last_visit_time INT);'
                     'CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, total_bytes INT, start_time INT, end_time INT, state INT);')
    visit = datetime(2026, 9, 1, 10, 2, tzinfo=timezone.utc)
    db.execute('INSERT INTO urls VALUES (1, ?, ?, 2, ?)', ('https://example.com/x', 'X', _chrome_ts(visit)))
    db.execute('INSERT INTO downloads VALUES (1, ?, ?, 5, ?, ?, 1)', (r'C:\tmp\a.exe', 'https://example.com/a', _chrome_ts(visit), _chrome_ts(visit)))
    db.commit()
    db.close()
    r = parse_chromium_history(db_path, 'CASE-1', 'EVID-1')
    assert r['status'] == 'COMPLETED'
    assert r['history'][0]['last_visit_time'] == visit.isoformat()
    rows = [dict(x, browser='Chrome') for x in r['history'] + r['downloads']]
    events = browser_events(rows)
    assert {e['type'] for e in events} == {'BROWSER_VISIT', 'BROWSER_DOWNLOAD'}
    assert all(e['timestamp'] == visit for e in events)
    # The source database must be untouched (parsers work on a copy).
    assert not (tmp_path / 'History-journal').exists()


def test_firefox_places_history_and_downloads(tmp_path):
    db_path = tmp_path / 'places.sqlite'
    db = sqlite3.connect(db_path)
    db.executescript('CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, last_visit_date INT);'
                     'CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);'
                     'CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INT, anno_attribute_id INT, content TEXT, dateAdded INT);')
    db.execute("INSERT INTO moz_places VALUES (1,'https://cdn.example.org/a.zip','a.zip',1,1788258780000000)")
    db.execute("INSERT INTO moz_anno_attributes VALUES (1,'downloads/destinationFileURI')")
    db.execute("INSERT INTO moz_annos VALUES (1,1,1,'file:///C:/Users/a/Downloads/a.zip',1788258785000000)")
    db.commit()
    db.close()
    r = parse_firefox_places(db_path, 'CASE-1', 'EVID-1')
    assert r['status'] == 'COMPLETED'
    assert len(r['history']) == 1
    assert r['downloads'][0]['target_path'] == 'file:///C:/Users/a/Downloads/a.zip'
    assert r['downloads'][0]['tab_url'] == 'https://cdn.example.org/a.zip'


def test_bodyfile_ntfs_file_name_attribute_lines():
    fn = parse_bodyfile_line('0|/Users/a/x.txt (deleted) ($FILE_NAME)|70-48-2|r/rrwxrwxrwx|0|0|82|1|2|3|4')
    assert fn['fn_attr'] is True and fn['deleted'] is True and fn['path'] == '/Users/a/x.txt'
    assert parse_bodyfile_line('0|/Users/a/x.txt|70-128-1|r/rrwxrwxrwx|0|0|5|1|2|3|4')['fn_attr'] is False


def test_pattern_rules_ignore_file_paths_and_count_devices():
    from app.analysis.services import PatternService
    files = [{'type': 'FILE_MACB', 'description': f'[m...] /logs/failed-{i}.txt'} for i in range(5)]
    one_stick = [{'type': 'USB_ACTIVITY', 'serial': 'S1', 'description': 'x'} for _ in range(4)]
    assert PatternService().run(files + one_stick) == []
    two_sticks = one_stick + [{'type': 'USB_ACTIVITY', 'serial': 'S2', 'description': 'y'}]
    assert [p['pattern'] for p in PatternService().run(two_sticks)] == ['Repeated removable-media activity']


def test_audit_metadata_is_hashed_as_stored():
    import json
    from app.services.audit import _canonical
    meta = {'updated_at': datetime(2026, 9, 1, 10, 0, 0, 123456, tzinfo=timezone.utc)}
    normalised = json.loads(_canonical(meta))
    # A datetime becomes its full string before hashing, so Mongo's millisecond truncation cannot change it.
    assert normalised == {'updated_at': '2026-09-01 10:00:00.123456+00:00'}
