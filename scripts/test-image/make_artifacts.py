"""Builds the synthetic user artifacts placed inside the DFIP test disk image.

Everything here is fabricated test data for exercising the parsers, except the
SYSTEM registry hive, which is a real Windows 7 hive from the regipy test suite
(MIT licensed): https://github.com/mkorman90/regipy/tree/master/regipy_tests/data
"""
import lzma
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

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


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    write('Windows/System32/config/SYSTEM', lzma.open(HIVE_XZ).read())
    write('Windows/INF/setupapi.dev.log', SETUPAPI.replace('\n', '\r\n'))
    chrome_history(OUT / 'Users/alice/AppData/Local/Google/Chrome/User Data/Default/History')
    firefox_places(OUT / 'Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite')
    write('Users/alice/Documents/project-notes.txt', 'Q3 project notes. Nothing sensitive here.\n' * 40)
    # Deleted by make-test-image.sh after being copied into the image.
    write('Users/alice/Documents/payroll-export.csv',
          'employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60)))
    write('Users/alice/Downloads/cleanup.ps1',
          'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n')


if __name__ == '__main__':
    main()
