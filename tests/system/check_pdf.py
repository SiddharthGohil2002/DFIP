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
sections = ['1. Evidence register', '2. Chain of custody', '3. Analysis summary', '4. Deleted files', '5. Recovered files', '6. USB device history',
            '7. Browser history', '8. Browser downloads', '9. Windows activity', '9.1 Programs run', '9.2 Recently opened files', '9.3 Recycle Bin',
            '10. Malware indicators', '11. Investigator findings', '12. Tagged evidence', '13. Timeline of notable events', '14. Audit trail integrity']
missing = [s for s in sections if s not in a]
check(f'all {len(sections)} sections present {missing or ""}', not missing)
check('evidence ID and full SHA-256', exp['evidence'] in a and exp['sha256'] in flat.replace(' ', '') )
import re
custody = ' '.join(a[a.index('2. Chain of custody'):a.index('3. Analysis summary')].split())
check('custody actions listed as readable labels', all(x in custody for x in ('Evidence registered', 'Evidence verified', 'Analysis integrity check', 'File recovered')))
check('custody shows people by name, never a database ID', not re.search(r'\b[0-9a-f]{24}\b(?!…)', custody))
check('deleted payroll export listed', 'payroll-export.csv' in flat)
check('USB serials listed', 'AA951D0000007252' in flat and '4C530001230518109141' in flat)
check('browser visits and downloads listed', all(x in flat for x in ('filetransfer.example.net', 'pastebin.example.com', 'SecureDelete.exe', 'archiver.zip')))
check('YARA hit on cleanup.ps1 listed', 'cleanup.ps1' in flat)
check('Windows activity listed: program run, file opened from E:, Recycle Bin original path',
      all(x in flat for x in ('SECUREDELETE.EXE', r'E:\payroll-export.csv', r'C:\Users\alice\Documents\payroll-export.csv')))
check('finding listed', 'Payroll export deleted after USB activity' in flat)
# Table cells wrap, so long notes are checked in fragments.
check('tagged evidence listed with labels and notes', all(x in flat for x in ('Shortcut proves the file was', 'opened from E:', 'Check who uploaded what', 'Follow')))
check('legal hold status in the header', 'Legal hold' in a and 'Not under legal hold' in flat)
check('audit chain reported valid', 'valid' in flat.lower() and 'INVALID' not in flat)
m = text('report-markup.pdf')
check('markup in case text is printed literally', '<b>Bold</b> & "quoted" <script>alert(1)</script>' in ' '.join(m.split()))
t = text('report-tamper.pdf')
check('tampered evidence shows INTEGRITY_FAILED in its report', 'INTEGRITY_FAILED' in t and exp['tamper_case'] in t)
pages = subprocess.run(['pdfinfo', '/out/report-A.pdf'], capture_output=True, text=True).stdout
print('  NOTE', ' '.join(l for l in pages.splitlines() if l.startswith(('Pages', 'Producer', 'Page size'))))
print(f'pdf: {passes} passed, {fails} failed')
