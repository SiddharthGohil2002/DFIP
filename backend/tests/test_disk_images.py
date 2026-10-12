"""Disk image formats and sets (formats from their bytes, EnCase segments and split parts checked for gaps, virtual
disks and their parents, made here with qemu-img), raw working copies, shadow copy comparison, volume keys and the
secrets they are stored with."""
import hashlib
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.forensic import disk_formats as df
from app.forensic import vss
from app.forensic.source import OffsetFile, parse_volume, shadow_volume_id
from app.forensic.volume_crypto import check_secret
from app.forensic.working_image import changed_files, evidence_sha256, files_sha256, needs_working_copy

QEMU = shutil.which('qemu-img')


def _disk(tmp_path, size=3 << 20) -> tuple[Path, bytes]:
    """A raw disk with data, zeros and a recognisable end."""
    data = bytearray(size)
    data[0:4096] = os.urandom(4096)
    data[1 << 20:(1 << 20) + 300] = b'middle of the disk ' * 15 + b'xxxxxxxxxxxxxxx'
    data[-512:] = b'E' * 512
    p = tmp_path / 'disk.raw'
    p.write_bytes(bytes(data))
    return p, bytes(data)


def _ewf_segment(path: Path, number: int, last: bool):
    """The parts of an EWF segment file classify reads: header with the segment number, then sections to next/done."""
    head = b'EVF\x09\x0d\x0a\xff\x00' + b'\x01' + number.to_bytes(2, 'little') + b'\x00\x00'
    first = b'header'.ljust(16, b'\0') + (13 + 76).to_bytes(8, 'little') + (76).to_bytes(8, 'little') + bytes(44)
    end = (b'done' if last else b'next').ljust(16, b'\0') + (13 + 76).to_bytes(8, 'little') + bytes(52)
    path.write_bytes(head + first + end + bytes(64))


def test_formats_come_from_the_bytes(tmp_path):
    cases = {'a.E01': b'EVF\x09\x0d\x0a\xff\x00' + bytes(600), 'b.Ex01': b'EVF2\x0d\x0a\x81\x00' + bytes(600),
             'c.bin': b'vhdxfile' + bytes(600), 'd.bin': b'KDMV' + bytes(600), 'e.vmdk': b'# Disk DescriptorFile\nversion=1\n' + bytes(600),
             'f.bin': b'QFI\xfb' + bytes(600), 'g.vhd': bytes(1024) + b'conectix' + bytes(504), 'h.E01': b'not an EnCase image' + bytes(600)}
    want = {'a.E01': 'E01', 'b.Ex01': 'EX01', 'c.bin': 'VHDX', 'd.bin': 'VMDK', 'e.vmdk': 'VMDK', 'f.bin': 'QCOW2', 'g.vhd': 'VHD', 'h.E01': 'RAW'}
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
        assert df.detect(tmp_path / name) == want[name], name
    assert df.extension_ok('disk.E07') and df.extension_ok('disk.dd.003') and df.extension_ok('x.vhdx') and not df.extension_ok('notes.txt')
    assert [df.ewf_index(x) for x in ('E01', 'e09', 'E99', 'EAA', 'EAB', 'EBA', 'Ex02')] == [1, 9, 99, 100, 101, 126, 2]


def test_encase_segments_are_complete_and_in_order(tmp_path):
    for n in (1, 2, 3):
        _ewf_segment(tmp_path / f'case.E0{n}', n, last=n == 3)
    s = df.classify([tmp_path / 'case.E03', tmp_path / 'case.E01', tmp_path / 'case.E02'])
    assert (s['format'], s['kind'], [p.name for p in s['order']]) == ('E01', 'segments', ['case.E01', 'case.E02', 'case.E03'])
    with pytest.raises(df.SetError, match=r'missing: \.E02'):
        df.classify([tmp_path / 'case.E01', tmp_path / 'case.E03'])
    with pytest.raises(df.SetError, match='not the last segment'):
        df.classify([tmp_path / 'case.E01', tmp_path / 'case.E02'])
    with pytest.raises(df.SetError, match='segment 1 of an EnCase image with more segments'):
        df.classify([tmp_path / 'case.E01'])
    with pytest.raises(df.SetError, match='segment 2'):
        df.classify([tmp_path / 'case.E02'])
    (tmp_path / 'other').mkdir()
    shutil.copy(tmp_path / 'case.E02', tmp_path / 'other' / 'case.E01')
    shutil.copy(tmp_path / 'case.E01', tmp_path / 'other' / 'case.E02')
    with pytest.raises(df.SetError, match='renamed'):
        df.classify([tmp_path / 'other' / 'case.E01', tmp_path / 'other' / 'case.E02'])


def test_split_raw_parts(tmp_path):
    disk, data = _disk(tmp_path)
    parts = []
    for i, start in enumerate(range(0, len(data), 1 << 20)):
        p = tmp_path / f'disk.{i + 1:03d}'
        p.write_bytes(data[start:start + (1 << 20)])
        parts.append(p)
    s = df.classify(list(reversed(parts)))
    assert (s['kind'], [p.name for p in s['order']]) == ('split', ['disk.001', 'disk.002', 'disk.003'])
    joined = df.ConcatenatedParts(s['order'])
    assert joined.size == len(data) and joined.read((1 << 20) - 10, 30) == data[(1 << 20) - 10:(1 << 20) + 20]
    with pytest.raises(df.SetError, match=r'missing: \.002'):
        df.classify([parts[0], parts[2]])
    with pytest.raises(df.SetError, match='part 3 of a split image'):
        df.classify([parts[2]])
    (tmp_path / 'odd').mkdir()
    (tmp_path / 'odd' / 'disk.001').write_bytes(b'a' * 100)
    (tmp_path / 'odd' / 'disk.002').write_bytes(b'b' * 200)
    with pytest.raises(df.SetError, match='same size except the last'):
        df.classify([tmp_path / 'odd' / 'disk.001', tmp_path / 'odd' / 'disk.002'])
    with pytest.raises(df.SetError, match='not numbered parts'):
        df.classify([disk, tmp_path / 'odd' / 'disk.001'])
    assert df.classify([parts[0]])['kind'] == 'single'  # .001 alone may be a whole image


@pytest.mark.skipif(not QEMU, reason='qemu-img is not installed')
def test_virtual_disks_read_back_the_raw_disk(tmp_path):
    disk, data = _disk(tmp_path)
    for fmt, qemu_fmt, opts in (('VHDX', 'vhdx', []), ('VMDK', 'vmdk', []), ('QCOW2', 'qcow2', []), ('VHD', 'vpc', ['-o', 'subformat=fixed,force_size=on'])):
        out = tmp_path / f'disk.{fmt.lower()}'
        subprocess.run([QEMU, 'convert', '-f', 'raw', '-O', qemu_fmt, *opts, str(disk), str(out)], check=True, capture_output=True)
        s = df.classify([out])
        assert (s['format'], s['kind']) == (fmt, 'single'), fmt
        m = df.open_media({'format': fmt, 'filename': out.name, 'storage_path': str(out)})
        try:
            assert m.size == len(data) and m.read(0, m.size) == data, fmt
        finally:
            m.close()
        ev = {'evidence_id': 'EVID-T', 'case_id': 'C', 'format': fmt, 'filename': out.name, 'storage_path': str(out)}
        assert needs_working_copy(ev)


@pytest.mark.skipif(not QEMU, reason='qemu-img is not installed')
def test_a_disk_with_its_parent(tmp_path):
    disk, data = _disk(tmp_path)
    base = tmp_path / 'base.qcow2'
    subprocess.run([QEMU, 'convert', '-f', 'raw', '-O', 'qcow2', str(disk), str(base)], check=True, capture_output=True)
    top = tmp_path / 'top.qcow2'
    subprocess.run([QEMU, 'create', '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2', str(top)], check=True, capture_output=True, cwd=tmp_path)
    subprocess.run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x41 8192 4096', str(top)], check=True, capture_output=True)
    with pytest.raises(df.SetError, match=r'differencing disk.*base\.qcow2'):
        df.classify([top])
    s = df.classify([base, top])
    assert ([p.name for p in s['order']], s['roles']) == (['top.qcow2', 'base.qcow2'], {'top.qcow2': 'disk', 'base.qcow2': 'parent'})
    files = [{'name': p.name, 'path': str(p), 'role': s['roles'][p.name]} for p in s['order']]
    m = df.open_media({'format': 'QCOW2', 'image_files': files})
    try:
        want = data[:8192] + b'A' * 4096 + data[12288:]
        assert m.read(0, m.size) == want
    finally:
        m.close()
    other = tmp_path / 'other.qcow2'
    shutil.copy(base, other)
    with pytest.raises(df.SetError, match='each the top of a chain'):
        df.classify([base, top, other])


def test_raw_copies_are_hashed_and_sparse(tmp_path):
    disk, data = _disk(tmp_path, size=12 << 20)
    out = tmp_path / 'copy.raw'
    info = df.write_raw(lambda o, n: data[o:o + n], len(data), out)
    assert out.read_bytes() == data
    assert (info['sha256'], info['md5'], info['sha512']) == (hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(), hashlib.sha512(data).hexdigest())
    assert os.stat(out).st_blocks * 512 < len(data)  # the zero stretches were not written
    with pytest.raises(ValueError, match='ended early'):
        df.write_raw(lambda o, n: data[o:o + n][:10], len(data), tmp_path / 'short.raw')
    with pytest.raises(ValueError, match='Not enough free space'):
        df.ensure_space(tmp_path, 1 << 62, 'the test')


def test_image_set_hash_and_changed_files(tmp_path):
    a, b = tmp_path / 'x.001', tmp_path / 'x.002'
    a.write_bytes(b'first part ')
    b.write_bytes(b'second')
    ev = {'storage_path': str(a), 'image_files': [{'name': 'x.001', 'path': str(a), 'sha256': hashlib.sha256(b'first part ').hexdigest()},
                                                  {'name': 'x.002', 'path': str(b), 'sha256': hashlib.sha256(b'second').hexdigest()}]}
    assert evidence_sha256(ev) == hashlib.sha256(b'first part second').hexdigest() == files_sha256([a, b])
    b.write_bytes(b'Second')
    assert changed_files(ev) == ['x.002']
    b.unlink()
    with pytest.raises(FileNotFoundError, match='x.002'):
        evidence_sha256(ev)


def test_shadow_copy_comparison():
    t = lambda *a: int(datetime(*a, tzinfo=timezone.utc).timestamp())
    snapshot = [
        {'path': '/Users/alice/payroll.csv', 'inode': '40', 'size': 900, 'is_dir': False, 'mtime': t(2026, 9, 1, 9, 41)},
        {'path': '/Users/alice/notes.txt', 'inode': '41', 'size': 10, 'is_dir': False, 'mtime': t(2026, 8, 1)},
        {'path': '/Users/alice/same.txt', 'inode': '42', 'size': 5, 'is_dir': False, 'mtime': t(2026, 8, 1)},
        {'path': '/Users/alice/Old folder', 'inode': '43', 'size': 0, 'is_dir': True, 'mtime': None},
        {'path': '/$MFT', 'inode': '0', 'size': 1, 'is_dir': False, 'mtime': 1},
        {'path': '/$Recycle.Bin/S-1-5-21-1/$RABC.csv', 'inode': '44', 'size': 3, 'is_dir': False, 'mtime': 1},
        {'path': '/System Volume Information/{3808876b}', 'inode': '45', 'size': 3, 'is_dir': False, 'mtime': 1},
        {'path': '/gone.txt', 'inode': '46', 'size': 1, 'is_dir': False, 'deleted': True, 'mtime': 1},
    ]
    current = {p.lower(): dict(path=p, **v) for p, v in {
        '/Users/alice/NOTES.txt': {'size': 12, 'is_dir': False, 'mtime': datetime(2026, 9, 2, tzinfo=timezone.utc)},
        '/Users/alice/same.txt': {'size': 5, 'is_dir': False, 'mtime': datetime(2026, 8, 1, tzinfo=timezone.utc)},
        '/Users/alice/new.txt': {'size': 1, 'is_dir': False, 'mtime': None},
        '/Users/alice/new.txt:Zone.Identifier': {'size': 1, 'is_dir': False, 'mtime': None},
        '/$LogFile': {'size': 1, 'is_dir': False, 'mtime': None},
    }.items()}
    got = sorted((c, (o or n)['path']) for c, o, n in vss.compare(snapshot, current))
    assert got == [('ADDED_SINCE', '/Users/alice/new.txt'), ('CHANGED_SINCE', '/Users/alice/notes.txt'),
                   ('DELETED_SINCE', '/$Recycle.Bin/S-1-5-21-1/$RABC.csv'), ('DELETED_SINCE', '/Users/alice/Old folder'),
                   ('DELETED_SINCE', '/Users/alice/payroll.csv')]
    assert vss.to_datetime(t(2026, 9, 1, 9, 41)) == datetime(2026, 9, 1, 9, 41, tzinfo=timezone.utc) and vss.to_datetime(0) is None


def test_volume_ids_and_windows(tmp_path):
    assert parse_volume('p2048') == (2048, None) and parse_volume('p0/vss3') == (0, 3) and shadow_volume_id(2048, 2) == 'p2048/vss2'
    for bad in ('p2048/vss0', 'x', 'p2048/vss', 'p-1'):
        with pytest.raises(ValueError):
            parse_volume(bad)
    f = tmp_path / 'img'
    f.write_bytes(bytes(range(256)) * 8)
    w = OffsetFile(f, 512, 100)
    assert w.get_size() == 100 and w.read(4) == bytes([0, 1, 2, 3]) and w.tell() == 4
    w.seek(-2, os.SEEK_END)
    assert w.read(10) == bytes([98, 99]) and w.read(1) == b''
    w.close()


def test_volume_keys_are_checked_and_stored_encrypted(monkeypatch):
    good = '000000-111111-222222-333333-444444-555555-666666-777777'
    assert check_secret('BitLocker', 'recovery_password', good.replace('-', ' ')) == good
    for kind, method, secret, msg in (('BitLocker', 'recovery_password', '123456-' * 7 + '123456', 'divisible by 11'),
                                      ('BitLocker', 'recovery_password', '12345', '48 digits'),
                                      ('LUKS', 'recovery_password', good, 'unlocked with: password'),
                                      ('BitLocker', 'password', '', 'Give the password'),
                                      ('VeraCrypt', 'password', 'x', 'cannot be unlocked')):
        with pytest.raises(ValueError, match=msg) as exc:
            check_secret(kind, method, secret)
        assert not secret or secret not in str(exc.value)
    from app.core.config import settings
    from app.services import secrets
    monkeypatch.setattr(settings, 'data_encryption_key', 'first key for the test')
    token = secrets.encrypt('bde-TEST')
    assert 'bde-TEST' not in token and secrets.decrypt(token) == 'bde-TEST'
    monkeypatch.setattr(settings, 'data_encryption_key', 'a different key')
    with pytest.raises(ValueError, match='has changed since it was stored'):
        secrets.decrypt(token)
