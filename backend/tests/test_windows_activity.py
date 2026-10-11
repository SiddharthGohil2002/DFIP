"""Windows activity: Recycle Bin $I, Recent-folder LNK and Prefetch parsing, locating and timeline events.

The test files are written by tests/fixtures/winfmt.py from the published formats; the LNK and Prefetch
files are read back with libyal's liblnk and libscca, independently of the writers.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'fixtures'))
import winfmt  # noqa: E402

from app.forensic.artifact_locator import ArtifactCollector, classify  # noqa: E402
from app.forensic.timeline import activity_events  # noqa: E402
from app.forensic.windows_activity import (parse_lnk, parse_prefetch, parse_recycle_index,  # noqa: E402
                                           parse_recycle_index_file)


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


@pytest.mark.parametrize('version', [1, 2])
def test_recycle_index_round_trip(version):
    data = winfmt.recycle_bin_index(r'C:\Users\alice\Documents\payroll-export.csv', 2191, utc(2026, 9, 1, 14, 15, 20), version)
    r = parse_recycle_index(data)
    assert r == {'format_version': version, 'original_path': r'C:\Users\alice\Documents\payroll-export.csv',
                 'original_size': 2191, 'deleted_time': '2026-09-01T14:15:20+00:00'}


def test_recycle_index_rejects_bad_records(tmp_path):
    good = winfmt.recycle_bin_index(r'C:\x.txt', 1, utc(2026, 1, 1))
    with pytest.raises(ValueError):
        parse_recycle_index(b'\3' + good[1:])          # unknown version
    with pytest.raises(ValueError):
        parse_recycle_index(good[:26])                  # path length missing
    with pytest.raises(ValueError):
        parse_recycle_index(good[:24] + b'\xff\xff\x00\x00' + good[28:])  # length beyond the record
    junk = tmp_path / '$IJUNK.txt'
    junk.write_bytes(b'not a recycle record')
    assert parse_recycle_index_file(junk)['status'] == 'FAILED'


def test_lnk_fields(tmp_path):
    p = tmp_path / 'payroll-export.csv.lnk'
    p.write_bytes(winfmt.shell_link(
        r'E:\payroll-export.csv', size=2191, created=utc(2026, 9, 1, 14, 13, 10), modified=utc(2026, 9, 1, 9, 41, 2),
        accessed=utc(2026, 9, 1, 14, 14, 5), drive_type=winfmt.DRIVE_REMOVABLE, drive_serial=0x6A3C91F2,
        volume_label='CRUZER', working_dir='E:\\', machine_id='laptop-07'))
    r = parse_lnk(p)
    assert r['status'] == 'COMPLETED'
    assert r['target_path'] == r'E:\payroll-export.csv' and r['target_size'] == 2191
    assert (r['drive_type'], r['drive_serial'], r['volume_label']) == ('Removable', '6A3C-91F2', 'CRUZER')
    assert r['target_created'] == '2026-09-01T14:13:10+00:00'
    assert r['target_modified'] == '2026-09-01T09:41:02+00:00'
    assert r['target_accessed'] == '2026-09-01T14:14:05+00:00'
    assert r['working_directory'] == 'E:\\' and r['machine_id'] == 'laptop-07'


def test_prefetch_fields(tmp_path):
    vol = r'\VOLUME{01dc1f2a3b4c5d6e-5e1f22c4}'
    exe = vol + r'\USERS\ALICE\DOWNLOADS\SECUREDELETE.EXE'
    p = tmp_path / 'SECUREDELETE.EXE-DDC0C4C3.pf'
    p.write_bytes(winfmt.prefetch_v30('SECUREDELETE.EXE', run_times=[utc(2026, 9, 1, 14, 18, 30), utc(2026, 9, 1, 10, 6, 2)],
                                      run_count=2, files=[vol + r'\WINDOWS\SYSTEM32\NTDLL.DLL', exe], volume_path=vol,
                                      volume_serial=0x5E1F22C4, volume_created=utc(2025, 11, 3, 8)))
    r = parse_prefetch(p)
    assert r['status'] == 'COMPLETED' and r['format_version'] == 30 and r['compressed'] is False
    assert (r['executable'], r['executable_path'], r['run_count']) == ('SECUREDELETE.EXE', exe, 2)
    assert r['last_run_times'] == ['2026-09-01T14:18:30+00:00', '2026-09-01T10:06:02+00:00']
    assert r['last_run'] == '2026-09-01T14:18:30+00:00'
    assert r['prefetch_hash'] == f'{winfmt.prefetch_hash(exe):08X}'
    assert r['volumes'] == [{'device_path': vol, 'serial': '5E1F-22C4', 'created': '2025-11-03T08:00:00+00:00'}]
    assert r['referenced_files_total'] == 2 and 'warning' not in r


@pytest.mark.parametrize('parser', [parse_lnk, parse_prefetch])
def test_garbage_files_fail_cleanly(tmp_path, parser):
    for data in (b'', b'garbage' * 50):
        f = tmp_path / 'bad.bin'
        f.write_bytes(data)
        assert parser(f)['status'] == 'FAILED'


def test_classify_windows_activity_paths():
    sid = 'S-1-5-21-3623811015-3361044348-30300820-1001'
    assert classify(f'/$Recycle.Bin/{sid}/$I3K9D2A.csv') == ('RECYCLE_BIN_INFO', {'sid': sid, 'suffix': '3K9D2A.csv'})
    assert classify('/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/report.docx.lnk')[0] == 'LNK_RECENT'
    assert classify('/Users/alice/AppData/Roaming/Microsoft/Office/Recent/report.docx.LNK')[0] == 'LNK_RECENT'
    assert classify('/Windows/Prefetch/CMD.EXE-0BD30981.pf')[0] == 'PREFETCH'
    assert classify(f'/$Recycle.Bin/{sid}/$R3K9D2A.csv') is None
    assert classify('/Users/alice/Desktop/shortcut.lnk') is None


def test_collector_pairs_index_with_content():
    sid = 'S-1-5-21-1-2-3-1001'
    c = ArtifactCollector()
    entry = lambda path, inode, **kw: {'path': path, 'inode': inode, 'size': 10, 'deleted': False, 'is_dir': False,
                                       'is_virtual': False, 'mtime': utc(2026, 9, 1, 14, 15, 20), 'crtime': None, **kw}
    c.observe(entry(f'/$Recycle.Bin/{sid}/$IAAAAAA.csv', '10'), 2048)
    c.observe(entry(f'/$Recycle.Bin/{sid}/$RAAAAAA.csv', '11'), 2048)
    c.observe(entry(f'/$Recycle.Bin/{sid}/$IBBBBBB', '12'), 2048)
    c.observe(entry(f'/$Recycle.Bin/{sid}/$RBBBBBB', '13', is_dir=True), 2048)     # a recycled folder
    c.observe(entry(f'/$Recycle.Bin/{sid}/$ICCCCCC.txt', '14'), 2048)
    c.observe(entry(f'/$Recycle.Bin/{sid}/$RCCCCCC.txt', '15', deleted=True), 2048)  # content already gone
    items = {i['suffix']: i for i in c.resolved()}
    assert items['AAAAAA.csv']['recycle_data'] == {'path': f'/$Recycle.Bin/{sid}/$RAAAAAA.csv', 'inode': '11', 'size': 10, 'is_dir': False}
    assert items['BBBBBB']['recycle_data']['is_dir'] is True
    assert items['CCCCCC.txt']['recycle_data'] is None
    assert items['AAAAAA.csv']['fs_mtime'] == utc(2026, 9, 1, 14, 15, 20)


def test_activity_events():
    base = {'case_id': 'C', 'evidence_id': 'E', 'source_path': '/x'}
    rows = [
        dict(base, type='PROGRAM_RUN', executable='A.EXE', executable_path=r'\VOLUME{x}\A.EXE', run_count=3,
             last_run_times=['2026-09-01T14:18:30+00:00', '2026-09-01T10:06:02+00:00']),
        dict(base, type='RECENT_FILE', target_path=r'E:\a.csv', drive_type='Removable', volume_label='CRUZER',
             lnk_created='2026-09-01T14:14:05+00:00', lnk_modified='2026-09-01T14:14:05+00:00'),
        dict(base, type='RECENT_FILE', target_path=r'C:\b.txt', lnk_created='2026-08-01T08:00:00+00:00',
             lnk_modified='2026-09-01T08:00:00+00:00'),
        dict(base, type='RECYCLE_BIN_ITEM', original_path=r'C:\a.csv', original_size=2191, deleted_time='2026-09-01T14:15:20+00:00'),
    ]
    ev = activity_events(rows)
    kinds = [(e['type'], e['timestamp'].isoformat()) for e in ev]
    assert kinds == [('PROGRAM_RUN', '2026-09-01T14:18:30+00:00'), ('PROGRAM_RUN', '2026-09-01T10:06:02+00:00'),
                     ('RECENT_FILE_OPENED', '2026-09-01T14:14:05+00:00'),
                     ('RECENT_FILE_OPENED', '2026-09-01T08:00:00+00:00'), ('RECENT_FILE_OPENED', '2026-08-01T08:00:00+00:00'),
                     ('FILE_DELETED_TO_RECYCLE_BIN', '2026-09-01T14:15:20+00:00')]
    assert 'removable drive "CRUZER"' in ev[2]['description']
    assert ev[5]['description'] == r'Deleted to Recycle Bin: C:\a.csv (2,191 bytes)'
