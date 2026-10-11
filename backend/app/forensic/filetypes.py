"""What a file really is, from its content: type, category, a name that does not match it, entropy and encryption.

The type comes from libmagic (the `file` command's database) applied to the first bytes, never from the name.
A file whose content contradicts its extension (a CSV named holiday.jpg, a text file named .com) is flagged as
renamed. Encryption is recognised from format markers (encrypted ZIP entries, encrypted Office documents, PDF
encryption dictionaries) and, for files with no recognisable format, from very high entropy (an encrypted
container such as VeraCrypt has no header at all).
"""
from __future__ import annotations
import io
import struct

import numpy as np

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
ZIP_LOCAL = b'PK\x03\x04'
HEAD_BYTES = 64 * 1024
ENTROPY_BYTES = 4 << 20
HIGH_ENTROPY = 7.95
CONTAINER_MIN = 1 << 20
OLE_MAX = 64 << 20   # Office containers parsed for encryption markers up to this size

SCRIPT_EXTS = {'.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.hta', '.wsf', '.py', '.sh'}
EXECUTABLE_MIMES = {'application/x-dosexec', 'application/vnd.microsoft.portable-executable', 'application/x-executable',
                    'application/x-sharedlib', 'application/x-pie-executable', 'application/x-mach-binary', 'application/x-msi'}
ARCHIVE_MIMES = {'application/zip', 'application/x-7z-compressed', 'application/x-rar', 'application/vnd.rar', 'application/gzip',
                 'application/x-gzip', 'application/x-bzip2', 'application/x-xz', 'application/x-tar', 'application/x-compress',
                 'application/zstd', 'application/x-lzh-compressed', 'application/vnd.ms-cab-compressed'}
DOCUMENT_MIMES = {'application/pdf', 'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
                  'application/rtf', 'text/rtf', 'application/x-ole-storage', 'application/CDFV2', 'application/encrypted',
                  'application/vnd.ms-outlook', 'application/epub+zip'}
# Text that libmagic types as application/* (setupapi.dev.log, for example, is "Generic INItialization configuration").
TEXT_LIKE = {'application/json', 'application/xml', 'application/javascript', 'application/x-subrip', 'application/csv',
             'application/x-wine-extension-ini', 'application/x-setupscript', 'application/x-shellscript', 'application/x-msdos-batch',
             'application/x-perl', 'application/x-ruby', 'application/x-php', 'application/x-awk', 'application/x-tex',
             'application/x-ndjson', 'application/x-yaml', 'application/toml', 'application/x-desktop'}

_OOXML = {'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'application/vnd.openxmlformats-officedocument.presentationml.presentation'}
_LEGACY_OFFICE = {'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint', 'application/x-ole-storage',
                  'application/CDFV2', 'application/encrypted'}
TEXT = 'text'
_OFFICE_CONTAINER = {'application/zip', 'application/encrypted', 'application/CDFV2', 'application/x-ole-storage'}
# What each extension's content should be: (what the name suggests, the types that agree with it). TEXT means any text type.
_GROUPS = [
    ('JPEG image', ('.jpg', '.jpeg', '.jfif'), {'image/jpeg'}), ('PNG image', ('.png',), {'image/png'}),
    ('GIF image', ('.gif',), {'image/gif'}), ('BMP image', ('.bmp',), {'image/bmp', 'image/x-ms-bmp'}),
    ('WebP image', ('.webp',), {'image/webp'}), ('TIFF image', ('.tif', '.tiff'), {'image/tiff'}),
    ('HEIC image', ('.heic', '.heif'), {'image/heic', 'image/heif'}), ('PDF document', ('.pdf',), {'application/pdf'}),
    ('ZIP archive', ('.zip',), {'application/zip'}), ('7-Zip archive', ('.7z',), {'application/x-7z-compressed'}),
    ('RAR archive', ('.rar',), {'application/x-rar', 'application/vnd.rar'}), ('gzip archive', ('.gz',), {'application/gzip', 'application/x-gzip'}),
    ('Word document', ('.docx', '.docm'), _OOXML | _OFFICE_CONTAINER), ('Excel workbook', ('.xlsx', '.xlsm'), _OOXML | _OFFICE_CONTAINER),
    ('PowerPoint presentation', ('.pptx', '.pptm'), _OOXML | _OFFICE_CONTAINER),
    ('Word 97-2003 document', ('.doc',), _LEGACY_OFFICE), ('Excel 97-2003 workbook', ('.xls',), _LEGACY_OFFICE),
    ('PowerPoint 97-2003 presentation', ('.ppt',), _LEGACY_OFFICE),
    ('executable program', ('.exe', '.dll', '.sys', '.scr', '.com', '.cpl', '.ocx'), EXECUTABLE_MIMES),
    ('text', ('.txt', '.csv', '.log', '.ini', '.xml', '.json', '.md', '.html', '.htm'), TEXT),
    ('MP4 video', ('.mp4', '.m4v'), {'video/mp4'}), ('QuickTime video', ('.mov',), {'video/quicktime'}),
    ('AVI video', ('.avi',), {'video/x-msvideo'}), ('MP3 audio', ('.mp3',), {'audio/mpeg'}),
    ('WAV audio', ('.wav',), {'audio/x-wav', 'audio/wav'}), ('SQLite database', ('.sqlite', '.db3'), {'application/vnd.sqlite3', 'application/x-sqlite3'}),
]
EXPECTED: dict[str, tuple[str, set | str]] = {ext: (label, types) for label, exts, types in _GROUPS for ext in exts}
_UNKNOWN = {'application/octet-stream', 'inode/x-empty', 'application/x-empty', ''}


def extension(name: str) -> str:
    dot = (name or '').rfind('.')
    return name[dot:].lower() if dot > 0 else ''


def category(mime: str, name: str, description: str = '') -> str:
    """A coarse kind of file for filtering: executable, script, document, archive, image, video, audio, text, email,
    database, registry, shortcut, empty or other."""
    mime = mime or ''
    ext = extension(name)
    desc = (description or '').lower()
    if mime in ('inode/x-empty', 'application/x-empty'):
        return 'empty'
    if mime in EXECUTABLE_MIMES:
        return 'executable'
    if ext in SCRIPT_EXTS and (mime.startswith('text/') or mime in TEXT_LIKE):
        return 'script'
    if mime in ARCHIVE_MIMES:
        return 'archive'
    if mime in DOCUMENT_MIMES or mime in _OOXML or mime.startswith('application/vnd.oasis.opendocument'):
        return 'document'
    if mime.startswith('image/'):
        return 'image'
    if mime.startswith('video/'):
        return 'video'
    if mime.startswith('audio/'):
        return 'audio'
    if mime in ('message/rfc822',) or mime.startswith('message/'):
        return 'email'
    if mime in ('application/vnd.sqlite3', 'application/x-sqlite3'):
        return 'database'
    if 'registry file' in desc:
        return 'registry'
    if 'shortcut' in desc:
        return 'shortcut'
    if mime.startswith('text/') or mime in TEXT_LIKE:
        return 'text'
    return 'other'


def mismatch(name: str, mime: str) -> str | None:
    """What the extension promises (for example 'JPEG image'), when the content clearly says otherwise; None when they
    agree or it can't be told."""
    expected = EXPECTED.get(extension(name))
    if expected is None or (mime or '') in _UNKNOWN:
        return None
    label, types = expected
    if types == TEXT:
        return None if mime.startswith('text/') or mime in TEXT_LIKE else label
    return None if mime in types else label


_OOXML_PARTS = (('word/', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Microsoft Word 2007+'),
                ('xl/', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Microsoft Excel 2007+'),
                ('ppt/', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'Microsoft PowerPoint 2007+'))


def refine_zip(blob, mime: str, description: str) -> tuple[str, str]:
    """The type of a file that starts like a ZIP, from its member names.

    libmagic's ZIP rules read the end of the file, so from the first bytes alone it reports every ZIP (and every
    Office document, OpenDocument or EPUB built on one) as plain data. The central directory is read here instead.
    """
    import zipfile
    try:
        z = zipfile.ZipFile(BlobFile(blob))
        infos = z.infolist()
    except Exception:
        return mime, description
    names = {i.filename for i in infos}
    encrypted = any(i.flag_bits & 0x0001 for i in infos)
    if '[Content_Types].xml' in names:
        for prefix, ooxml, label in _OOXML_PARTS:
            if any(n.startswith(prefix) for n in names):
                return ooxml, label
    first = infos[0] if infos else None
    if first is not None and first.filename == 'mimetype' and first.compress_type == zipfile.ZIP_STORED and first.file_size < 100 and not encrypted:
        kind = z.read('mimetype').decode('ascii', 'replace').strip()
        if kind.startswith('application/vnd.oasis.opendocument'):
            return kind, 'OpenDocument'
        if kind == 'application/epub+zip':
            return kind, 'EPUB document'
    return 'application/zip', 'Zip archive data' + (', encrypted entries' if encrypted else '')


def entropy(histogram) -> float:
    """Shannon entropy in bits per byte (0 = constant, 8 = indistinguishable from random) of a byte histogram."""
    total = float(histogram.sum())
    if total <= 0:
        return 0.0
    p = histogram[histogram > 0] / total
    return float(-(p * np.log2(p)).sum())


def histogram(data: bytes):
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)


class BlobFile(io.RawIOBase):
    """A read-only, seekable file object over an evidence Blob (for parsers that need random access)."""

    def __init__(self, blob):
        self._blob, self._pos = blob, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self._pos

    def seek(self, offset, whence=0):
        self._pos = offset if whence == 0 else self._pos + offset if whence == 1 else self._blob.size + offset
        return self._pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self._blob.size - self._pos
        data = self._blob.read(self._pos, n) if self._pos < self._blob.size else b''
        self._pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def _ole_encryption(blob) -> dict | None:
    import olefile
    try:
        ole = olefile.OleFileIO(BlobFile(blob))
    except Exception:
        return None
    try:
        streams = {'/'.join(s).lower() for s in ole.listdir(streams=True, storages=False)}
        if 'encryptedpackage' in streams or 'encryptioninfo' in streams:
            return {'kind': 'OFFICE', 'detail': 'Encrypted Office Open XML document (password-protected)'}
        if 'worddocument' in streams:
            fib = ole.openstream('WordDocument').read(12)
            if len(fib) >= 12 and struct.unpack_from('<H', fib, 0x0A)[0] & 0x0100:
                return {'kind': 'OFFICE', 'detail': 'Encrypted Word 97-2003 document'}
        if 'workbook' in streams:
            data = ole.openstream('Workbook').read(8192)
            pos = 0
            while pos + 4 <= len(data):
                rtype, rlen = struct.unpack_from('<HH', data, pos)
                if rtype == 0x002F:  # FILEPASS
                    return {'kind': 'OFFICE', 'detail': 'Encrypted Excel 97-2003 workbook'}
                if rtype == 0x000A:  # EOF of the workbook globals
                    break
                pos += 4 + rlen
        if 'encryptedsummary' in streams:
            return {'kind': 'OFFICE', 'detail': 'Encrypted PowerPoint 97-2003 presentation'}
    finally:
        ole.close()
    return None


def encryption(blob, head: bytes, mime: str, ent: float) -> dict | None:
    """Encryption recognised in a file, or None: {kind: ZIP|OFFICE|PDF|HIGH_ENTROPY, detail}."""
    size = blob.size
    if head[:4] == ZIP_LOCAL and len(head) >= 10:
        flags, method = struct.unpack_from('<HH', head, 6)
        if flags & 0x0001:
            return {'kind': 'ZIP', 'detail': 'Encrypted ZIP entries (' + ('AES' if method == 99 else 'ZipCrypto') + ')'}
    if head[:8] == OLE_MAGIC and size <= OLE_MAX:
        found = _ole_encryption(blob)
        if found:
            return found
    if mime == 'application/encrypted':
        return {'kind': 'OFFICE', 'detail': 'Encrypted Office document'}
    if mime == 'application/pdf':
        tail = blob.read(max(0, size - 65536), 65536)
        if b'/Encrypt' in tail or b'/Encrypt' in head:
            return {'kind': 'PDF', 'detail': 'PDF with an encryption dictionary (password or permissions)'}
    if ent >= HIGH_ENTROPY and (mime or '') in _UNKNOWN and size >= CONTAINER_MIN and size % 512 == 0:
        return {'kind': 'HIGH_ENTROPY', 'detail': f'No recognisable format and entropy {ent:.3f} bits/byte: possibly an '
                                                  'encrypted container (for example VeraCrypt)'}
    return None
