"""Builds the synthetic user artifacts placed inside the DFIP test disk image.

Everything here is fabricated test data for exercising the parsers, except the
SYSTEM registry hive, which is a real Windows 7 hive from the regipy test suite
(MIT licensed): https://github.com/mkorman90/regipy/tree/master/regipy_tests/data
"""
import lzma
import sqlite3
import struct
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

# Writers for the Windows artifact formats (shared with the backend unit tests).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'backend' / 'tests' / 'fixtures'))
import winfmt  # noqa: E402

OUT = Path(sys.argv[1])
HIVE_XZ = Path(sys.argv[2])

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


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    write('Windows/System32/config/SYSTEM', lzma.open(HIVE_XZ).read())
    write('Windows/INF/setupapi.dev.log', SETUPAPI.replace('\n', '\r\n'))
    chrome_history(OUT / 'Users/alice/AppData/Local/Google/Chrome/User Data/Default/History')
    firefox_places(OUT / 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite')
    write('Users/alice/Documents/project-notes.txt', 'Q3 project notes. Nothing sensitive here.\n' * 40)
    # Deleted by make-test-image.sh after being copied into the image.
    write('Users/alice/Documents/payroll-export.csv', PAYROLL)
    write('Users/alice/Downloads/cleanup.ps1',
          'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n')
    windows_activity()
    write('Users/alice/Pictures/whiteboard.png', png())
    write('Users/alice/Documents/offer-letter.pdf', pdf())
    print(PREFETCH_NAME)


if __name__ == '__main__':
    main()
