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
          'USB device history', 'Browser history', 'Browser downloads', 'Windows activity', 'Malware indicators',
          'Hash set matches', 'Renamed and encrypted files',
          'Investigator findings', 'Tagged evidence', 'Timeline of notable events', 'Audit trail integrity']
found = [(int(m.group(1)), m.group(2)) for m in re.finditer(r'^\s*(\d+)\. (' + '|'.join(map(re.escape, titles)) + r')', a, re.M)]
check(f'all {len(titles)} sections present, in order and numbered 1 to {len(titles)} {[t for t in titles if t not in [f[1] for f in found]] or ""}',
      found == list(zip(range(1, len(titles) + 1), titles)))
subs = [m.group(0).strip() for m in re.finditer(r'^\s*\d+\.\d+ (Programs run|Recently opened files|Recycle Bin)', a, re.M)]
check('Windows activity has its three subsections', len(subs) == 3)
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
m = text('report-markup.pdf')
check('markup in case text is printed literally', '<b>Bold</b> & "quoted" <script>alert(1)</script>' in ' '.join(m.split()))
t = text('report-tamper.pdf')
check('tampered evidence shows INTEGRITY_FAILED in its report', 'INTEGRITY_FAILED' in t and exp['tamper_case'] in t)
pages = subprocess.run(['pdfinfo', '/out/report-A.pdf'], capture_output=True, text=True).stdout
print('  NOTE', ' '.join(l for l in pages.splitlines() if l.startswith(('Pages', 'Producer', 'Page size'))))
print(f'pdf: {passes} passed, {fails} failed')
