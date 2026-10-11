"""Tags: the natural key that identifies an item across re-analysis, and the snapshot kept with the tag."""
from datetime import datetime, timedelta

from bson import ObjectId

from app.forensic.timeline import activity_events, event_nk
from app.services.tags import key_hash, natural_key, snapshot

TS = datetime(2026, 9, 1, 14, 14, 6)


def test_natural_keys_ignore_database_ids():
    a = {'_id': ObjectId(), 'evidence_id': 'EVID-001', 'partition_offset': 2048, 'inode': '23', 'path': '/a.csv', 'pipeline': True,
         'analysis_job_id': 'JOB-1'}
    b = dict(a, _id=ObjectId(), analysis_job_id='JOB-2')  # the same file after a re-run
    assert natural_key('FILE', a) == natural_key('FILE', b) == {'evidence_id': 'EVID-001', 'volume_id': 'p2048', 'inode': '23', 'path': '/a.csv'}
    assert natural_key('FILE', dict(a, volume_id='p2048')) == natural_key('FILE', a)  # new and legacy documents agree
    assert key_hash(natural_key('FILE', a)) == key_hash(natural_key('FILE', b))
    assert key_hash(natural_key('FILE', a)) != key_hash(natural_key('FILE', dict(a, inode='24')))


def test_natural_keys_per_item_type():
    ev = {'evidence_id': 'EVID-001'}
    assert natural_key('TIMELINE_EVENT', dict(ev, type='FILE_MACB', partition_offset=2048, inode='5', path='/x', macb='m...', timestamp=TS)) == \
        {'evidence_id': 'EVID-001', 'type': 'FILE_MACB', 'volume_id': 'p2048', 'inode': '5', 'path': '/x', 'macb': 'm...'}
    usb = dict(ev, type='USB_ACTIVITY', timestamp=TS, description='USB device x', serial='X', usb_event='LAST_ARRIVAL')
    assert natural_key('TIMELINE_EVENT', usb) == {'evidence_id': 'EVID-001', 'nk': event_nk(usb)}
    assert natural_key('BROWSER', dict(ev, type='BROWSER_HISTORY', source_path='/H', row_id=3, url='u')) == \
        {'evidence_id': 'EVID-001', 'type': 'BROWSER_HISTORY', 'source_path': '/H', 'row_id': 3}
    assert natural_key('USB', dict(ev, instance_id='X&0', serial='X')) == {'evidence_id': 'EVID-001', 'instance_id': 'X&0'}
    assert natural_key('ACTIVITY', dict(ev, type='RECENT_FILE', source_path='/r.lnk')) == {'evidence_id': 'EVID-001', 'type': 'RECENT_FILE', 'source_path': '/r.lnk'}
    assert natural_key('ARTIFACT', dict(ev, type='RECOVERED_FILE', artifact_id='abc')) == {'artifact_id': 'abc'}
    assert natural_key('ARTIFACT', dict(ev, type='MALWARE_INDICATOR', artifact_id='new-each-run', rule='R', original_path='/p')) == \
        {'evidence_id': 'EVID-001', 'type': 'MALWARE_INDICATOR', 'rule': 'R', 'original_path': '/p'}


def test_snapshots():
    f = snapshot('FILE', {'path': '/Users/alice/Documents/payroll-export.csv', 'inode': '23', 'size': 2191, 'deleted': True, 'mtime': TS})
    assert f == {'title': '/Users/alice/Documents/payroll-export.csv', 'detail': 'inode 23 · 2,191 bytes · deleted',
                 'timestamp': TS.isoformat(), 'source': None}
    v = snapshot('BROWSER', {'type': 'BROWSER_HISTORY', 'browser': 'Chrome', 'url': 'https://x', 'title': 'X', 'last_visit_time': '2026-09-01T10:20:00+00:00',
                             'source_path': '/History'})
    assert (v['title'], v['detail'], v['source']) == ('X', 'Chrome visit: https://x', '/History')
    r = snapshot('ACTIVITY', {'type': 'RECENT_FILE', 'target_path': r'E:\a.csv', 'drive_type': 'Removable', 'volume_label': 'CRUZER',
                              'lnk_modified': '2026-09-01T14:14:06+00:00'})
    assert (r['title'], r['detail']) == (r'E:\a.csv', 'File opened (Removable CRUZER drive)')
    u = snapshot('USB', {'friendly_name': None, 'vendor': 'SanDisk', 'product': 'Cruzer Blade', 'serial': '4C53'})
    assert (u['title'], u['detail']) == ('SanDisk Cruzer Blade', 'USB device, serial 4C53')


def test_keys_survive_time_corrections():
    """A time-zone correction moves file-system times; tag keys must not change with them."""
    macb = {'evidence_id': 'E', 'type': 'FILE_MACB', 'partition_offset': 2048, 'inode': '5', 'path': '/x', 'macb': 'm...', 'timestamp': TS}
    assert natural_key('TIMELINE_EVENT', macb) == natural_key('TIMELINE_EVENT', dict(macb, timestamp=TS + timedelta(hours=4)))
    row = {'case_id': 'C', 'evidence_id': 'E', 'type': 'RECENT_FILE', 'target_path': r'E:\a.csv', 'source': 'LNK',
           'source_path': '/Recent/a.lnk', 'lnk_created': '2026-09-01T14:13:10+00:00', 'lnk_modified': '2026-09-01T14:14:06+00:00'}
    shifted = dict(row, lnk_created='2026-09-01T18:13:10+00:00', lnk_modified='2026-09-01T18:14:06+00:00')
    before, after = activity_events([row]), activity_events([shifted])
    assert [e['nk'] for e in before] == [e['nk'] for e in after] and len({e['nk'] for e in before}) == 2  # first + last opened


def test_event_keys_are_derivable_from_legacy_documents():
    """Documents written before keys existed get the same key, so old tags migrate to it."""
    rows = [{'case_id': 'C', 'evidence_id': 'E', 'type': 'PROGRAM_RUN', 'executable': 'X.EXE', 'run_count': 2, 'source': 'PREFETCH',
             'source_path': '/Windows/Prefetch/X.EXE-1.pf', 'last_run_times': ['2026-09-01T14:18:30+00:00', '2026-09-01T10:06:02+00:00']}]
    for event in activity_events(rows):
        legacy = {k: v for k, v in event.items() if k != 'nk'}
        assert event_nk(legacy) == event['nk']
    assert len({e['nk'] for e in activity_events(rows)}) == 2  # each run its own key
