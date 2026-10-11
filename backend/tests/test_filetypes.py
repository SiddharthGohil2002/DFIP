"""File processing: real type and category, names that don't match the content, entropy and encryption markers."""
import io
import random
import struct
import zipfile

import numpy as np
import pytest

from app.forensic.filetypes import (CONTAINER_MIN, category, encryption, entropy, extension, histogram, mismatch,
                                    refine_zip)


class Blob:
    """Stands in for an evidence blob: a size and range reads."""

    def __init__(self, data: bytes):
        self.data, self.size = data, len(data)

    def read(self, offset, n):
        return self.data[offset:offset + n]


def _zip(members, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', method) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def _encrypted_zip(method: int) -> bytes:
    """A ZIP whose first entry is marked encrypted (general-purpose flag bit 0), as a password-protected ZIP is."""
    data = bytearray(_zip([('payroll-export.csv', 'employee,iban\n')]))
    flags, = struct.unpack_from('<H', data, 6)
    struct.pack_into('<HH', data, 6, flags | 1, method)          # local header
    central = data.index(b'PK\x01\x02')
    struct.pack_into('<HH', data, central + 8, flags | 1, method)  # central directory
    return bytes(data)


def _random(n, seed=7) -> bytes:
    return random.Random(seed).randbytes(n)


# ------------------------------------------------------------------ type and category
@pytest.mark.parametrize('mime,name,desc,expected', [
    ('application/x-dosexec', 'SecureDelete.exe', 'PE32 executable', 'executable'),
    ('text/plain', 'cleanup.ps1', 'ASCII text', 'script'),
    ('text/plain', 'notes.txt', 'ASCII text', 'text'),
    ('text/csv', 'holiday.jpg', 'CSV ASCII text', 'text'),
    ('application/zip', 'private.zip', 'Zip archive data', 'archive'),
    ('application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'a.docx', '', 'document'),
    ('application/encrypted', 'salary-review.docx', 'CDFV2 Encrypted', 'document'),
    ('application/pdf', 'offer-letter.pdf', 'PDF document', 'document'),
    ('image/png', 'whiteboard.png', 'PNG image data', 'image'),
    ('video/mp4', 'clip.mp4', '', 'video'),
    ('message/rfc822', 'mail.eml', '', 'email'),
    ('application/vnd.sqlite3', 'History', 'SQLite 3.x database', 'database'),
    ('application/octet-stream', 'SYSTEM', 'MS Windows registry file, NT/2000 or above', 'registry'),
    ('application/octet-stream', 'a.lnk', 'MS Windows shortcut', 'shortcut'),
    ('inode/x-empty', 'empty.txt', 'empty', 'empty'),
    ('application/octet-stream', 'vault.dat', 'data', 'other'),
])
def test_category(mime, name, desc, expected):
    assert category(mime, name, desc) == expected


def test_extension():
    assert extension('Photo.JPG') == '.jpg' and extension('archive.tar.gz') == '.gz'
    assert extension('.bashrc') == '' and extension('README') == '' and extension('') == ''


@pytest.mark.parametrize('name,mime,expected', [
    ('holiday.jpg', 'text/csv', 'JPEG image'),               # a CSV renamed to look like a photo
    ('Photo.JPG', 'image/jpeg', None),
    ('eicar.com', 'text/plain', 'executable program'),
    ('report.pdf', 'application/zip', 'PDF document'),
    ('notes.txt', 'text/plain', None),
    ('data.csv', 'application/csv', None),
    ('notes.txt', 'application/x-dosexec', 'text'),          # a program named .txt
    ('setupapi.dev.log', 'application/x-wine-extension-ini', None),  # INI-style text is still text
    ('salary-review.docx', 'application/encrypted', None),   # encrypted Office documents are OLE containers
    ('a.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', None),
    ('a.xlsx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', None),  # any OOXML part set
    ('vault.dat', 'application/octet-stream', None),         # extension with no expectation
    ('private.zip', 'application/octet-stream', None),       # type unknown: nothing to compare
    ('README', 'image/png', None),
])
def test_mismatch(name, mime, expected):
    assert mismatch(name, mime) == expected


# ------------------------------------------------------------------ entropy
def test_entropy_bounds():
    assert entropy(histogram(b'')) == 0.0
    assert entropy(histogram(b'a' * 1000)) == 0.0
    assert entropy(histogram(bytes(range(256)) * 16)) == pytest.approx(8.0)
    assert entropy(histogram(b'ab' * 500)) == pytest.approx(1.0)
    assert entropy(histogram(_random(1 << 20))) > 7.99


def test_histograms_add_up_across_chunks():
    data = _random(300_000)
    assert np.array_equal(histogram(data[:100_000]) + histogram(data[100_000:]), histogram(data))


# ------------------------------------------------------------------ encryption markers
def test_encrypted_zip_entries():
    aes = _encrypted_zip(99)
    assert encryption(Blob(aes), aes, 'application/zip', 7.0) == {'kind': 'ZIP', 'detail': 'Encrypted ZIP entries (AES)'}
    legacy = _encrypted_zip(8)
    assert encryption(Blob(legacy), legacy, 'application/zip', 7.0)['detail'] == 'Encrypted ZIP entries (ZipCrypto)'
    plain = _zip([('a.txt', 'hello')])
    assert encryption(Blob(plain), plain, 'application/zip', 4.0) is None


def test_pdf_encryption_dictionary():
    body = b'%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n' + b'x' * 200_000
    enc = body + b'trailer\n<< /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF\n'
    assert encryption(Blob(enc), enc[:65536], 'application/pdf', 5.0)['kind'] == 'PDF'  # found in the tail
    plain = body + b'trailer\n<< /Root 1 0 R >>\n%%EOF\n'
    assert encryption(Blob(plain), plain[:65536], 'application/pdf', 5.0) is None


def test_encrypted_office_type_from_libmagic():
    head = b'\x00' * 64
    assert encryption(Blob(head), head, 'application/encrypted', 6.0)['kind'] == 'OFFICE'


def test_high_entropy_container():
    data = _random(2 << 20)
    ent = entropy(histogram(data))
    found = encryption(Blob(data), data[:65536], 'application/octet-stream', ent)
    assert found['kind'] == 'HIGH_ENTROPY' and 'VeraCrypt' in found['detail']
    # Not for a file with a known type (compressed media is high-entropy too) ...
    assert encryption(Blob(data), data[:65536], 'image/jpeg', ent) is None
    # ... nor for small files or sizes that are not whole sectors.
    small = data[:CONTAINER_MIN // 2]
    assert encryption(Blob(small), small, 'application/octet-stream', ent) is None
    odd = data[:(1 << 20) + 100]
    assert encryption(Blob(odd), odd[:65536], 'application/octet-stream', ent) is None
    text = b'hello world ' * 200_000
    assert encryption(Blob(text), text[:65536], 'application/octet-stream', entropy(histogram(text))) is None


# ------------------------------------------------------------------ ZIP-based formats
def test_refine_zip_recognises_zip_based_formats():
    plain = _zip([('a.txt', 'hello')])
    assert refine_zip(Blob(plain), 'application/octet-stream', 'data') == ('application/zip', 'Zip archive data')
    docx = _zip([('[Content_Types].xml', '<Types/>'), ('_rels/.rels', '<r/>'), ('word/document.xml', '<w/>')])
    assert refine_zip(Blob(docx), 'application/octet-stream', 'data')[0] == \
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    xlsx = _zip([('[Content_Types].xml', '<Types/>'), ('xl/workbook.xml', '<w/>')])
    assert refine_zip(Blob(xlsx), 'application/zip', 'Zip archive data')[0].endswith('spreadsheetml.sheet')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr(zipfile.ZipInfo('mimetype'), 'application/vnd.oasis.opendocument.text')
        z.writestr('content.xml', '<office:document-content/>', zipfile.ZIP_DEFLATED)
    assert refine_zip(Blob(buf.getvalue()), 'application/octet-stream', 'data') == \
        ('application/vnd.oasis.opendocument.text', 'OpenDocument')


def test_refine_zip_reports_encrypted_entries_and_ignores_damaged_files():
    mime, desc = refine_zip(Blob(_encrypted_zip(99)), 'application/octet-stream', 'data')
    assert mime == 'application/zip' and 'encrypted' in desc
    broken = b'PK\x03\x04' + b'\x00' * 100  # a local header with no central directory
    assert refine_zip(Blob(broken), 'application/octet-stream', 'data') == ('application/octet-stream', 'data')


def test_category_and_mismatch_after_refinement():
    mime, desc = refine_zip(Blob(_zip([('a.txt', 'x')])), 'application/octet-stream', 'data')
    assert category(mime, 'private.zip', desc) == 'archive' and mismatch('private.zip', mime) is None
    assert mismatch('holiday.jpg', mime) == 'JPEG image'
