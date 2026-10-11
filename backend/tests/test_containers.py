"""Archives and embedded files: readers, limits against archive bombs, and safe extraction."""
import io
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / 'fixtures'))
import winfmt  # noqa: E402

from app.forensic.containers import (Budget, kind_for, parse_7z_listing, parse_ole10native, read_7z, read_ole, read_zip)
from app.forensic.modules.base import run_tool


class Blob:
    def __init__(self, data: bytes):
        self.data, self.size = data, len(data)

    def read(self, offset, n):
        return self.data[offset:offset + n]


def _tool(argv, timeout, **kw):
    return run_tool(argv, timeout=timeout, **kw)


def _zip(members, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', method) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


@pytest.mark.parametrize('entry,kind', [
    ({'mime': 'application/zip'}, 'zip'),
    ({'mime': 'application/zip', 'encryption': {'kind': 'ZIP'}}, 'zip'),  # listed, members flagged
    ({'mime': 'application/x-7z-compressed'}, '7z'),
    ({'mime': 'application/gzip'}, '7z'),
    ({'mime': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}, 'ooxml'),
    ({'mime': 'application/vnd.oasis.opendocument.text'}, 'odf'),
    ({'mime': 'application/msword'}, 'ole'),
    ({'mime': 'application/encrypted', 'encryption': {'kind': 'OFFICE'}}, None),
    ({'mime': 'application/pdf'}, 'pdf'),
    ({'mime': 'application/pdf', 'encryption': {'kind': 'PDF'}}, None),
    ({'mime': 'text/plain'}, None),
])
def test_kind_for(entry, kind):
    assert kind_for(entry) == kind


def test_zip_members_are_written_under_generated_names(tmp_path):
    data = _zip([('payroll-export.csv', b'employee,iban\n'), ('../../etc/evil', b'not where it says'), ('notes/', b''),
                 ('notes/readme.txt', b'backup')])
    members = read_zip(Blob(data), 'zip', tmp_path, Budget())
    assert [m.name for m in members] == ['payroll-export.csv', '../../etc/evil', 'notes/readme.txt']  # the folder is skipped
    for m in members:
        assert m.store.parent == tmp_path and len(m.store.name) == 32  # never the member's own name
    assert members[0].store.read_bytes() == b'employee,iban\n' and members[1].store.read_bytes() == b'not where it says'
    assert members[0].modified and members[0].packed is not None


def test_encrypted_zip_members_are_listed_not_extracted(tmp_path):
    data = bytearray(_zip([('payroll-export.csv', b'secret')]))
    for sig, at in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):  # set the encryption flag where a real encrypted ZIP has it
        i = data.index(sig)
        data[i + at] |= 1
    m, = read_zip(Blob(bytes(data)), 'zip', tmp_path, Budget())
    assert m.encrypted and m.store is None and 'encrypted' in m.note and not list(tmp_path.iterdir())


def test_archive_bomb_is_not_extracted(tmp_path):
    data = _zip([('zeros.bin', b'\0' * (40 << 20))])  # 40 MiB of zeros deflates to about 40 KiB
    m, = read_zip(Blob(data), 'zip', tmp_path, Budget())
    assert m.store is None and 'archive bomb' in m.note


def test_unpacking_budget(tmp_path):
    data = _zip([('a.txt', b'a' * 100), ('b.txt', b'b' * 100)], zipfile.ZIP_STORED)
    budget = Budget(evidence=150)
    a, b = read_zip(Blob(data), 'zip', tmp_path, budget)
    assert a.store and b.store is None and 'limit' in b.note and budget.evidence == 50


def test_office_documents_give_their_media_and_embedded_objects(tmp_path):
    data = _zip([('[Content_Types].xml', '<Types/>'), ('word/document.xml', '<w/>'), ('word/media/image1.png', b'\x89PNG....'),
                 ('word/embeddings/oleObject1.bin', b'\xd0\xcf\x11\xe0'), ('word/theme/theme1.xml', '<t/>')])
    assert [m.name for m in read_zip(Blob(data), 'ooxml', tmp_path, Budget())] == ['word/media/image1.png', 'word/embeddings/oleObject1.bin']


def test_ole_embedded_package_and_documents(tmp_path):
    cfb = winfmt.compound_file({'\x01Ole10Native': winfmt.ole10native('payroll-summary.txt', b'Q3 payroll summary'),
                                'ObjectPool/_1/Package': b'PK\x03\x04' + b'x' * 5000, 'WordDocument': b'w' * 100})
    members = read_ole(Blob(cfb), tmp_path, Budget())
    assert [m.name for m in members] == ['payroll-summary.txt', 'ObjectPool/_1/Package']
    assert members[0].store.read_bytes() == b'Q3 payroll summary' and members[1].size == 5004


def test_ole10native_parser_rejects_damaged_streams():
    good = winfmt.ole10native('a.txt', b'abc')
    assert parse_ole10native(good) == ('a.txt', b'abc')
    assert parse_ole10native(good[:20]) is None and parse_ole10native(b'') is None


def test_7z_listing_parser():
    text = 'Path = dir\nFolder = +\nSize = 0\n\nPath = dir/a.txt\nSize = 12\nPacked Size = 10\nModified = 2026-09-01 10:00:00\nEncrypted = -\n\n'
    assert [(e['Path'], e.get('Size')) for e in parse_7z_listing(text)] == [('dir', '0'), ('dir/a.txt', '12')]


def _7z(tmp_path, files: dict, *args) -> bytes:
    src = tmp_path / 'src'
    for name, data in files.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_bytes(data)
    out = tmp_path / 'a.7z'
    subprocess.run(['7z', 'a', '-bd', *args, str(out), '.'], cwd=src, check=True, capture_output=True)
    return out.read_bytes()


def test_7z_members(tmp_path):
    data = _7z(tmp_path, {'q3-salaries.csv': b'name,salary\nalice,1\n', 'sub/readme.txt': b'hello'})
    members, names_encrypted = read_7z(Blob(data), tmp_path / 'out', Budget(), _tool, tmp_path / 'work')
    got = {m.name: m.store.read_bytes() for m in members}
    assert not names_encrypted and got == {'q3-salaries.csv': b'name,salary\nalice,1\n', 'sub/readme.txt': b'hello'}
    assert not list((tmp_path / 'work').iterdir())  # the copy and the unpacking folder are removed


def test_encrypted_7z(tmp_path):
    data = _7z(tmp_path, {'secret.txt': b'secret'}, '-psummer2026')
    members, names_encrypted = read_7z(Blob(data), tmp_path / 'out', Budget(), _tool, tmp_path / 'work')
    assert not names_encrypted and [(m.name, m.encrypted, m.store) for m in members] == [('secret.txt', True, None)]
    data = _7z(tmp_path / 'h', {'secret.txt': b'secret'}, '-psummer2026', '-mhe=on')  # the names are encrypted too
    members, names_encrypted = read_7z(Blob(data), tmp_path / 'out2', Budget(), _tool, tmp_path / 'work2')
    assert names_encrypted and members == []


def test_links_in_an_archive_are_never_followed(tmp_path):
    secret = tmp_path / 'secret.txt'
    secret.write_text('outside the archive')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as t:
        link = tarfile.TarInfo('link-to-secret')
        link.type, link.linkname = tarfile.SYMTYPE, str(secret)
        t.addfile(link)
        info = tarfile.TarInfo('real.txt')
        info.size = 4
        t.addfile(info, io.BytesIO(b'real'))
    members, _ = read_7z(Blob(buf.getvalue()), tmp_path / 'out', Budget(), _tool, tmp_path / 'work')
    stored = {m.name: m.store for m in members}
    assert stored['real.txt'].read_bytes() == b'real'
    assert stored.get('link-to-secret') is None or stored['link-to-secret'].read_bytes() != b'outside the archive'
    assert all(not p.is_symlink() for p in (tmp_path / 'out').iterdir())


def test_tool_file_size_limit(tmp_path):
    r = run_tool(['sh', '-c', f'head -c 2000000 /dev/zero > {tmp_path}/big'], timeout=20, file_bytes=1_000_000)
    assert r['status'] == 'FAILED' and os.path.getsize(tmp_path / 'big') <= 1_000_000
