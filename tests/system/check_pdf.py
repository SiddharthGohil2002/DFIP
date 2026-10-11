"""Checks the text of the PDF reports produced by the API test run."""
import json, subprocess
exp = json.load(open('/out/pdf_expect.json'))
def text(name):
    return subprocess.run(['pdftotext', '-layout', f'/out/{name}', '-'], capture_output=True, text=True).stdout
fails = passes = 0
def check(name, cond):
    global fails, passes
    fails += 0 if cond else 1
    passes += 1 if cond else 0
    print(('  PASS ' if cond else '  FAIL ') + name)
a = text('report-A.pdf')
flat = ' '.join(a.split())
check('title and case', 'Digital Forensics Investigation Report' in a and exp['case'] in a and 'Payroll exfiltration test' in a)
import re
# Section titles in order; the numbers are checked to run 1, 2, 3, ... rather than listed, so adding a section
# does not need every later number edited here.
titles = ['Evidence register', 'Chain of custody', 'Analysis summary', 'Computer and users', 'Deleted files', 'Recovered files',
          'USB device history', 'Browser history', 'Browser downloads', 'Browser searches, bookmarks, logins and recovered history', 'Email',
          'Chat and cloud storage', 'Windows activity', 'Execution evidence', 'Folders browsed',
          'Searches and typed paths', 'Persistence', 'Installed programs', 'Remote desktop and network drives',
          'Jump lists, Timeline, thumbnails, SRUM and search index', 'NTFS: timestomping, alternate data streams and USN journal',
          'Event logs', 'Malware indicators',
          'Hash set matches', 'Renamed and encrypted files', 'Found data',
          'Investigator findings', 'Tagged evidence', 'Timeline of notable events', 'Audit trail integrity']
found = [(int(m.group(1)), m.group(2)) for m in re.finditer(r'^\s*(\d+)\. (' + '|'.join(map(re.escape, titles)) + r')', a, re.M)]
check(f'all {len(titles)} sections present, in order and numbered 1 to {len(titles)} {[t for t in titles if t not in [f[1] for f in found]] or ""}',
      found == list(zip(range(1, len(titles) + 1), titles)))
subs = [m.group(0).strip() for m in re.finditer(r'^\s*\d+\.\d+ (Programs run|Recently opened files|Recycle Bin)', a, re.M)]
check('Windows activity has its three subsections', len(subs) == 3)
subs = [m.group(1) for m in re.finditer(r'^\s*\d+\.\d+ (Logs read|Detections|Notable events)', a, re.M)]
check('Event logs has its three subsections', subs == ['Logs read', 'Detections', 'Notable events'])
subs = [m.group(1) for m in re.finditer(r'^\s*\d+\.\d+ (Jump lists|Windows Timeline|Thumbnails|Network usage \(SRUM\)|Windows Search index)', a, re.M)]
check('Jump lists, Timeline, thumbnails, SRUM and search index has its five subsections',
      subs == ['Jump lists', 'Windows Timeline', 'Thumbnails', 'Network usage (SRUM)', 'Windows Search index'])
check('Jump lists, the Timeline and thumbnails listed: Notepad, the deleted Timeline entry, the wiped screenshot\'s thumbnail',
      all(x in flat for x in ('Notepad (64-bit)', 'Google Chrome', 'deleted by the user', '9f3a6c21e4d07b58', 'payroll-screenshot.png',
                              'No SRUM database was found.')))
subs = [m.group(1) for m in re.finditer(r'^\s*\d+\.\d+ (Searches|Deleted history entries \(recovered\)|Bookmarks|Saved logins|Form history|Mailboxes|Messages sent, deleted or with attachments|Chat apps|Messages, calls and file transfers|Cloud storage accounts|Cloud storage files)', a, re.M)]
check('browser, email, chat and cloud sections have their subsections',
      subs == ['Searches', 'Deleted history entries (recovered)', 'Bookmarks', 'Saved logins', 'Form history', 'Mailboxes',
               'Messages sent, deleted or with attachments', 'Chat apps', 'Messages, calls and file transfers', 'Cloud storage accounts', 'Cloud storage files'])
check('browser depth listed: a recovered search, the deleted upload page, the bookmark folder, the saved login, the private address typed',
      all(x in flat for x in ('how to permanently delete files from usb', 'filetransfer.example.net/d/7Hq2xK', 'bar/tools',
                              'filetransfer.example.net/login', 'alice.private@mailbox.example', 'WAL frame 1')))
check('no saved password, encrypted or not, is in the report', 'password_value' not in flat and 'encryptedPassword' not in flat)
check('email listed: the Thunderbird folders, the export sent home with its attachment, the deleted reply',
      all(x in flat for x in ('Thunderbird', 'backup', 'Re: the list', '(deleted)', 'alice.private@mailbox.')))
check('chat and cloud listed: Skype messages and the transfer, WhatsApp not read, the OneDrive copy of the payroll and where else it is',
      all(x in flat for x in ('Offer letter attached', 'offer-letter.pdf', 'WhatsApp', 'encrypted', 'OneDrive', '/Backup/payroll-export.csv',
                              'holiday.jpg', r'C:\Users\alice\Dropbox')))
check('evidence ID and full SHA-256', exp['evidence'] in a and exp['sha256'] in flat.replace(' ', '') )
import re
custody = ' '.join(a[a.index('2. Chain of custody'):a.index('3. Analysis summary')].split())
check('custody actions listed as readable labels', all(x in custody for x in ('Evidence registered', 'Evidence verified', 'Analysis integrity check', 'File recovered')))
check('custody shows people by name, never a database ID', not re.search(r'\b[0-9a-f]{24}\b(?!…)', custody))
check('deleted payroll export listed', 'payroll-export.csv' in flat)
check('USB serials listed', 'AA951D0000007252' in flat and '4C530001230518109141' in flat)
check('browser visits and downloads listed', all(x in flat for x in ('filetransfer.example.net', 'pastebin.example.com', 'SecureDelete.exe', 'archiver.zip')))
check('YARA hit on cleanup.ps1 listed', 'cleanup.ps1' in flat)
check('hash set matches listed: the payroll copies as notable', 'Payroll exports' in flat and 'holiday.jpg' in flat)
check('registry activity listed: execution evidence, folders, searches, flagged persistence, programs, remote desktop',
      all(x in flat for x in ('SecureDelete.exe', 'UserAssist', 'ShimCache', '23854be75a', 'E:\\Exports', 'usb wipe', 'sethc.exe',
                              'SecureDelete 1.4', 'fileserver.corp.example')))
check('event logs listed: the logs read, the detections and the notable events (cleared log, admin group, SanDisk removed)',
      all(x in flat for x in ('Security.evtx', 'Security event log cleared', 'Local user account created', 'Security log cleared by',
                              'backup_admin added to group', 'Disk removed: SanDisk', 'decoded command: IEX')))
check('found data listed, the card number masked and never in full',
      all(x in flat for x in ('zoe.martin@example.org', 'GB82 WEST 1234 5698 7654 32', '1111')) and '4111 1111 1111 1111' not in flat
      and '4111111111111111' not in flat.replace(' ', ''))
check('renamed and encrypted files listed', all(x in flat for x in ('text/csv', 'private.zip', 'salary-review', 'vault.dat', 'Encrypted ZIP entries (AES)')))
check('Windows activity listed: program run, file opened from E:, Recycle Bin original path',
      all(x in flat for x in ('SECUREDELETE.EXE', r'E:\payroll-export.csv', r'C:\Users\alice\Documents\payroll-export.csv')))
check('finding listed', 'Payroll export deleted after USB activity' in flat)
# Table cells wrap, so long notes are checked in fragments.
check('tagged evidence listed with labels and notes', all(x in flat for x in ('Shortcut proves the file was', 'opened from E:', 'Check who uploaded what', 'Follow')))
check('legal hold status in the header', 'Legal hold' in a and 'Not under legal hold' in flat)
check("time basis in the header: the computer's time zone from the SYSTEM hive", 'America/New_York' in flat and 'Eastern Standard Time' in flat)
check('computer and users listed: LAPTOP-07, Windows 10 Pro, alice with her SID',
      all(x in flat for x in ('LAPTOP-07', 'Windows 10 Pro', 'alice', 'Alice Example')) and '30300820-1001' in flat.replace(' ', ''))
check('audit chain reported valid', 'valid' in flat.lower() and 'INVALID' not in flat)
import os
if os.path.exists('/out/report-ntfs.pdf'):
    nt = ' '.join(text('report-ntfs.pdf').split())
    check('NTFS report: the timestomped file, the hidden stream, the download source and the wipe in the USN journal',
          all(x in nt for x in ('strong /Users/alice/Documents/budget-2', 'Copy the payroll to the SanDisk', 'Internet', 'tools.example.org',
                                'AAAAAAAA.AAA', 'FILE_DELETE', 'RENAME_NEW_NAME', 'BASIC_INFO_CHANGE')))
else:
    check('NTFS report saved by the system test', False)
m = text('report-markup.pdf')
check('markup in case text is printed literally', '<b>Bold</b> & "quoted" <script>alert(1)</script>' in ' '.join(m.split()))
t = text('report-tamper.pdf')
check('tampered evidence shows INTEGRITY_FAILED in its report', 'INTEGRITY_FAILED' in t and exp['tamper_case'] in t)
pages = subprocess.run(['pdfinfo', '/out/report-A.pdf'], capture_output=True, text=True).stdout
print('  NOTE', ' '.join(l for l in pages.splitlines() if l.startswith(('Pages', 'Producer', 'Page size'))))
print(f'pdf: {passes} passed, {fails} failed')
