"""NTFS internals: USN journal records (versions 2 and 3), change reasons, Zone.Identifier streams, the timestomping
levels, and the volume-offset file object libfsntfs reads through. The volumes themselves are tested by the system
tests (an NTFS disk written with ntfs-3g, and Plaso's and dfVFS's real NTFS samples)."""
import struct
from datetime import datetime, timezone

import pytest

from app.forensic import ntfs

T = datetime(2026, 9, 1, 14, 18, 44, 100000, tzinfo=timezone.utc)
FT = ((T - ntfs.EPOCH_1601).days * 86400 + (T - ntfs.EPOCH_1601).seconds) * 10_000_000 + T.microsecond * 10


def v2(name='AAAAAAAA.AAA', reason=0x80000200, entry=71, seq=1, parent=68, usn=8960):
    n = name.encode('utf-16-le')
    return struct.pack('<IHHQQQQIIIIHH', 60 + len(n), 2, 0, entry | (seq << 48), parent | (5 << 48), usn, FT, reason, 0, 260, 0x20, len(n), 60) + n


def test_usn_v2_record():
    r = ntfs.parse_usn_record(v2())
    assert (r['version'], r['entry'], r['sequence'], r['parent_entry'], r['parent_sequence'], r['usn'], r['time'], r['name']) == \
        ('2.0', 71, 1, 68, 5, 8960, T, 'AAAAAAAA.AAA')
    assert r['reasons'] == ['FILE_DELETE', 'CLOSE'] and r['file_attributes'] == 0x20


def test_usn_v3_record_and_others():
    n = 'payroll-copy.csv'.encode('utf-16-le')
    data = (struct.pack('<IHH', 76 + len(n), 3, 0) + (71 | (1 << 48)).to_bytes(16, 'little') + (68 | (1 << 48)).to_bytes(16, 'little')
            + struct.pack('<QQIIIIHH', 4096, FT, 0x1000, 0, 0, 0x20, len(n), 76) + n)
    r = ntfs.parse_usn_record(data)
    assert (r['version'], r['entry'], r['sequence'], r['parent_entry'], r['usn'], r['reasons'], r['name']) == \
        ('3.0', 71, 1, 68, 4096, ['RENAME_OLD_NAME'], 'payroll-copy.csv')
    assert ntfs.parse_usn_record(struct.pack('<IHH', 80, 4, 0) + bytes(72)) is None  # version 4: byte ranges, no name
    assert ntfs.parse_usn_record(b'\x10\x00') is None


def test_reason_names():
    assert ntfs.reason_names(0x80000102) == ['DATA_EXTEND', 'FILE_CREATE', 'CLOSE']
    assert ntfs.reason_names(0x00208000) == ['BASIC_INFO_CHANGE', 'STREAM_CHANGE'] and ntfs.reason_names(0) == []


def test_zone_identifier():
    z = ntfs.zone_identifier('[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://tools.example.org/securedelete\r\n'
                             'HostUrl=https://tools.example.org/securedelete/SecureDelete.exe\r\n')
    assert z == {'ZoneId': '3', 'ReferrerUrl': 'https://tools.example.org/securedelete', 'ZoneName': 'Internet',
                 'HostUrl': 'https://tools.example.org/securedelete/SecureDelete.exe'}
    assert ntfs.zone_identifier('[ZoneTransfer]\nZoneId=7\n')['ZoneName'] == 'zone 7' and ntfs.zone_identifier('garbage') == {}


def _ft(*a, us=0):
    d = datetime(*a, tzinfo=timezone.utc) - ntfs.EPOCH_1601
    return (d.days * 86400 + d.seconds) * 10_000_000 + us * 10


STOMPED = _ft(2024, 3, 2, 9, 0, 0)
NAME = {'created_raw': _ft(2026, 9, 1, 14, 16, 4, us=49481)}


@pytest.mark.parametrize('si,path,level', [
    ({'created': STOMPED, 'modified': STOMPED, 'accessed': STOMPED, 'changed': _ft(2026, 9, 1, 14, 16, 40, us=49142)},
     '\\Users\\alice\\Documents\\budget-2025.txt', 'strong'),
    ({'created': STOMPED, 'modified': STOMPED, 'accessed': STOMPED, 'changed': STOMPED}, '\\Windows\\x.dll', 'strong'),
    # Earlier and whole-second, but the access time moved on: installers do this outside user folders...
    ({'created': STOMPED, 'modified': STOMPED, 'accessed': _ft(2026, 9, 1, 15, us=1), 'changed': STOMPED}, '\\Windows\\bootvid.dll', None),
    # ...in a user's folder it is worth a look.
    ({'created': STOMPED, 'modified': STOMPED, 'accessed': _ft(2026, 9, 1, 15, us=1), 'changed': STOMPED},
     '\\Users\\alice\\Desktop\\x.txt', 'possible'),
    ({'created': _ft(2024, 3, 2, 9, 0, 0, us=12345), 'modified': STOMPED, 'accessed': STOMPED, 'changed': STOMPED}, '\\Users\\a\\b', None),
    ({'created': NAME['created_raw'], 'modified': NAME['created_raw'], 'accessed': NAME['created_raw'], 'changed': NAME['created_raw']},
     '\\Users\\a\\b', None),  # a normal file
])
def test_timestomp_levels(si, path, level):
    got, reasons = ntfs.timestomp_reasons(si, NAME, path)
    assert got == level and (bool(reasons) if level else reasons == [])


def test_timestomp_needs_both_times():
    assert ntfs.timestomp_reasons({'created': None}, NAME) == (None, [])
    assert ntfs.timestomp_reasons({'created': STOMPED}, {'created_raw': None}) == (None, [])


def test_offset_file(tmp_path):
    p = tmp_path / 'disk.dd'
    p.write_bytes(b'M' * 1024 + bytes(range(256)) * 4)
    f = ntfs.OffsetFile(p, 1024)
    assert f.get_size() == 1024 and f.read(4) == bytes([0, 1, 2, 3]) and f.tell() == 4
    f.seek(-2, 2)
    assert f.read() == bytes([254, 255]) and f.read(10) == b''
    f.seek(250)
    f.seek(10, 1)
    assert f.read(1) == bytes([4])
    f.close()


def test_paths_and_times():
    assert ntfs.windows_path('\\Users\\alice\\x.txt') == '/Users/alice/x.txt' and ntfs.windows_path(None) is None
    assert ntfs.filetime(0) is None and ntfs.filetime(FT) == T
