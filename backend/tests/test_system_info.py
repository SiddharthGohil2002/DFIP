"""The computer and its users: SAM user records, the machine SID and joining accounts with profiles."""
import struct
from datetime import datetime, timezone

from app.forensic.system_info import accounts, machine_sid, parse_sam_f, parse_sam_v

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt):
    return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


def sam_f(rid, acb, logons, last_logon, password_set, failed=0):
    b = bytearray(0x50)
    struct.pack_into('<Q', b, 0x08, ft(last_logon))
    struct.pack_into('<Q', b, 0x18, ft(password_set))
    struct.pack_into('<Q', b, 0x20, 0x7FFFFFFFFFFFFFFF)
    struct.pack_into('<I', b, 0x30, rid)
    struct.pack_into('<H', b, 0x38, acb)
    struct.pack_into('<HH', b, 0x40, failed, logons)
    return bytes(b)


def sam_v(*strings):
    blobs = [b''] + [s.encode('utf-16-le') for s in strings]
    blobs += [b''] * (17 - len(blobs))
    header, data = bytearray(0xCC), bytearray()
    for i, blob in enumerate(blobs):
        struct.pack_into('<III', header, i * 12, len(data), len(blob), 0)
        data += blob + b'\0' * (-len(blob) % 4)
    return bytes(header + data)


def test_sam_f_record():
    f = parse_sam_f(sam_f(1001, 0x0210, 214, datetime(2026, 9, 1, 13, 28, 40, tzinfo=timezone.utc),
                          datetime(2026, 3, 2, 10, tzinfo=timezone.utc), failed=2))
    assert f == {'last_logon': '2026-09-01T13:28:40+00:00', 'password_last_set': '2026-03-02T10:00:00+00:00',
                 'account_expires': None, 'last_failed_logon': None, 'rid': 1001, 'flags': 0x0210, 'disabled': False,
                 'password_never_expires': True, 'failed_logon_count': 2, 'logon_count': 214}
    assert parse_sam_f(sam_f(500, 0x0211, 0, EPOCH_1601, EPOCH_1601))['disabled'] is True
    assert parse_sam_f(b'\x00' * 10) == {}  # truncated records are ignored, not misread


def test_sam_f_record_as_hex_string():
    raw = sam_f(1001, 0x0210, 5, datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert parse_sam_f(raw.hex())['logon_count'] == 5  # regipy returns binary values as hex


def test_sam_v_record():
    assert parse_sam_v(sam_v('alice', 'Alice Example', '')) == {'username': 'alice', 'full_name': 'Alice Example', 'comment': None}
    assert parse_sam_v(sam_v('Guest', '', 'Built-in account'))['comment'] == 'Built-in account'
    assert parse_sam_v(b'short') == {'username': None, 'full_name': None, 'comment': None}


def test_machine_sid_from_the_domain_v_record():
    v = bytes(0x40) + struct.pack('<BB', 1, 4) + (5).to_bytes(6, 'big') + struct.pack('<IIII', 21, 3623811015, 3361044348, 30300820)
    assert machine_sid(v) == 'S-1-5-21-3623811015-3361044348-30300820'


def test_accounts_join_sam_users_with_profiles():
    sam = {'users': [{'rid': 1001, 'username': 'alice', 'sid': 'S-1-5-21-1-2-3-1001'},
                     {'rid': 500, 'username': 'Administrator', 'sid': 'S-1-5-21-1-2-3-500'}]}
    software = {'profiles': [{'sid': 'S-1-5-21-1-2-3-1001', 'profile_path': 'C:\\Users\\alice', 'last_loaded': '2026-09-01T13:28:45+00:00'},
                             {'sid': 'S-1-5-18', 'profile_path': '%systemroot%', 'well_known': 'SYSTEM'},
                             {'sid': 'S-1-12-1-99', 'profile_path': 'C:\\Users\\bob.smith', 'last_loaded': None}]}
    out = {a['sid']: a for a in accounts(sam, software)}
    assert out['S-1-5-21-1-2-3-1001']['profile_path'] == 'C:\\Users\\alice' and out['S-1-5-21-1-2-3-1001']['source'] == 'SAM'
    assert out['S-1-5-21-1-2-3-500']['profile_path'] is None
    assert out['S-1-12-1-99'] == {'sid': 'S-1-12-1-99', 'username': 'bob.smith', 'profile_path': 'C:\\Users\\bob.smith',
                                  'profile_last_loaded': None, 'source': 'PROFILE_LIST'}   # e.g. an Azure AD account
    assert 'S-1-5-18' not in out                                                        # built-in service profiles are left out
