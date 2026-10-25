"""Loads demonstration data into a running DFIP, so that every page has something to show.

It uses only DFIP's own API, signed in as the demo accounts (DEMO_MODE=true), and the test evidence the scripts in
scripts/test-image/ generate. Nothing here is real evidence: it is the synthetic "payroll data leak" scenario of the
test disk plus, when they were downloaded, public test samples (dfVFS, Plaso, python-evtx).

From the repository root, with DFIP running (`docker compose up -d`) and the test images generated (README, "Load the
demo data"):

    docker compose run --rm --no-deps -v "${PWD}/scripts:/scripts:ro" -v "${PWD}/storage/test-images:/img:ro" backend python /scripts/demo/load_demo_data.py

It creates up to three cases. Running it again is safe: it completes whatever is missing (after an interruption, or
once the public samples have been downloaded) and repeats nothing that is already there.

1. "DEMO - Payroll data leak (Alice's laptop)": the Windows laptop image, the office desktop's NTFS disk, the network
   capture, an Android and an iPhone extraction and Plaso's timeline of the laptop, all analysed with the Full profile;
   a recovered deleted file, carved files, tags, findings in each review state with a comment that mentions a colleague,
   the seized laptop booked in as physical evidence with its custody moves, and a signed report.
2. "DEMO - Collections: Linux server, Mac and triage packages": a Linux server disk, a Mac collection, and KAPE and
   Velociraptor packages.
3. "DEMO - Encrypted volumes, shadow copies and image formats" (only when the public samples were downloaded): a
   BitLocker To Go and a LUKS volume unlocked with their passwords, a volume with shadow copies, a split EnCase image
   and the samples disk (real SRUM, Windows Search, Jump Lists, Timeline, Outlook, Chrome, Firefox and event logs).

As administrator it also adds a YARA rule set and a known-bad and a notable hash set built from the scenario's files,
and leaves one self-registered account waiting for approval. With --clamav it first downloads ClamAV's official
databases (needs internet access) so the analysis includes the ClamAV scan.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PASSWORD = 'DemoPassword!2026'
CASE_MAIN = "DEMO - Payroll data leak (Alice's laptop)"
CASE_COLLECTIONS = 'DEMO - Collections: Linux server, Mac and triage packages'
CASE_SAMPLES = 'DEMO - Encrypted volumes, shadow copies and image formats'
DONE = {'COMPLETED', 'FAILED', 'CANCELLED'}

YARA_RULES = r'''
rule DFIP_Demo_SecureDelete
{
    meta:
        description = "The wiping tool of the demo scenario (SecureDelete.exe and its packed copy)"
    strings:
        $name = "SecureDelete" ascii wide nocase
    condition:
        $name
}

rule DFIP_Demo_Payroll_Export
{
    meta:
        description = "Files holding the demo company's payroll export"
    strings:
        $header = "employee_id,name,iban" ascii wide nocase
        $title = "payroll" ascii wide nocase
    condition:
        $header or #title > 2
}
'''


class Api:
    """The DFIP API through the URL given (inside the Compose network: http://backend:8000)."""

    def __init__(self, base: str):
        self.base = base.rstrip('/')
        self.token = ''

    def call(self, method: str, path: str, body=None, raw: bytes | None = None, ctype: str = 'application/json',
             timeout: int = 1800, ok404: bool = False):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + '/api' + path, data=data, method=method)
        if data is not None:
            req.add_header('Content-Type', ctype)
        if self.token:
            req.add_header('Authorization', 'Bearer ' + self.token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = r.read()
                return json.loads(payload) if payload and r.headers.get_content_type() == 'application/json' else payload
        except urllib.error.HTTPError as e:
            if ok404 and e.code == 404:
                return None
            detail = e.read().decode(errors='replace')[:500]
            raise SystemExit(f'DFIP refused {method} {path}: HTTP {e.code} {detail}')

    def get(self, path: str, **params):
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        return self.call('GET', path + (('?' + q) if q else ''))

    def post(self, path: str, body=None, **params):
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        return self.call('POST', path + (('?' + q) if q else ''), body if body is not None else {})

    def form(self, path: str, fields: dict, files: list[tuple[str, str, bytes]], timeout: int = 3600):
        """multipart/form-data: fields, and files as (field name, file name, content)."""
        b = uuid.uuid4().hex
        parts = []
        for k, v in fields.items():
            if v is not None:
                parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        for field, name, content in files:
            parts += [f'--{b}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\n'
                      f'Content-Type: application/octet-stream\r\n\r\n'.encode(), content, b'\r\n']
        parts.append(f'--{b}--\r\n'.encode())
        return self.call('POST', path, raw=b''.join(parts), ctype=f'multipart/form-data; boundary={b}', timeout=timeout)

    def sign_in(self, email: str):
        self.token = ''
        self.token = self.post('/auth/login', {'email': email, 'password': PASSWORD})['access_token']
        return self


def rows(result) -> list:
    return result.get('data', []) if isinstance(result, dict) else (result or [])


def say(text: str):
    print(text, flush=True)


def wait_healthy(base: str):
    for _ in range(90):
        try:
            with urllib.request.urlopen(base.rstrip('/') + '/health', timeout=5) as r:
                h = json.loads(r.read())
            if h.get('status') == 'ok':
                if not h.get('demo_mode'):
                    raise SystemExit('DFIP is not in demo mode (DEMO_MODE=false): the demo accounts this script signs in with '
                                     'do not exist. Load the demo data only into a demonstration installation.')
                return
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(2)
    raise SystemExit(f'DFIP did not answer at {base}/health. Start it first: docker compose up -d')


def wait_job(api: Api, job_id: str, what: str) -> dict:
    last = None
    while True:
        j = api.get(f'/jobs/{job_id}')
        stage = (j.get('status'), j.get('stage'), j.get('progress'))
        if stage != last and j.get('status') not in DONE:
            say(f'    {what}: {j.get("status")} {j.get("progress") or 0}% {j.get("stage") or ""}'.rstrip())
            last = stage
        if j.get('status') in DONE:
            if j['status'] != 'COMPLETED':
                say(f'    {what}: {j["status"]} {j.get("error") or ""}'.rstrip())
            return j
        time.sleep(3)


def ensure_case(api: Api, name: str, description: str, priority: str) -> str:
    """The case of that name: an existing one is continued (its finished steps are skipped), else it is created."""
    c = next((c for c in rows(api.get('/cases')) if c.get('name') == name), None)
    if c:
        say(f'{c["case_id"]}: {name} (exists; completing what is missing)')
        return c['case_id']
    c = api.post('/cases', {'name': name, 'description': description, 'priority': priority})
    say(f'Created {c["case_id"]}: {name}')
    return c['case_id']


def case_evidence(api: Api, case_id: str) -> list[dict]:
    return [e for e in rows(api.get('/evidence')) if e.get('case_id') == case_id]


def ensure_evidence(api: Api, case_id: str, files: list[Path], kind: str | None = None) -> str:
    """The evidence item of these files in the case, uploaded unless it is already there."""
    have = next((e for e in case_evidence(api, case_id) if e.get('filename') == files[0].name), None)
    if have:
        return have['evidence_id']
    names = ', '.join(f.name for f in files)
    say(f'  Uploading {names} ({sum(f.stat().st_size for f in files) / 2**20:.1f} MiB)')
    e = api.form('/evidence/upload', {'case_id': case_id, 'kind': kind}, [('file', f.name, f.read_bytes()) for f in files])
    say(f'    {e["evidence_id"]} registered, SHA-256 {e["sha256"][:16]}...')
    return e['evidence_id']


def analyse(api: Api, case_id: str, evidence_ids: list[str], profile: str = 'full'):
    """Queues the analysis of each evidence item not analysed yet, then waits for all of them (the worker runs two at
    a time)."""
    done = {e['evidence_id'] for e in case_evidence(api, case_id) if e.get('analysis_status') == 'COMPLETED'}
    todo = [eid for eid in evidence_ids if eid not in done]
    jobs = [(eid, api.post(f'/jobs/analysis/{eid}', {'profile': profile})['job_id']) for eid in todo]
    for eid, job_id in jobs:
        wait_job(api, job_id, f'Analysis of {eid} ({job_id})')
    if todo:
        say(f'  Analysed {", ".join(todo)}')


def user_id(api: Api, email: str) -> str | None:
    return next((u['_id'] for u in rows(api.get('/admin/users')) if u.get('email') == email), None)


# ------------------------------------------------------------------------------------------------ administration
def admin_setup(admin: Api, clamav: bool):
    say('Administration')
    sets = rows(admin.get('/malware/yara'))
    if not any(s.get('name') == 'Demo scenario rules' for s in sets):
        admin.form('/malware/yara', {'name': 'Demo scenario rules', 'description': 'The wiping tool and the payroll export of the demo scenario'},
                   [('file', 'demo-scenario.yar', YARA_RULES.encode())])
        say('  Added the YARA rule set "Demo scenario rules"')
    if not any(u.get('email') == 'priya.shah@dfip.local' for u in rows(admin.get('/admin/users'))):
        Api(admin.base).post('/auth/register', {'name': 'Priya Shah', 'email': 'priya.shah@dfip.local', 'password': secrets.token_urlsafe(18)})
        say('  Registered priya.shah@dfip.local, waiting for approval on the Users page')
    if clamav:
        say('  Downloading the ClamAV databases (needs internet access)')
        j = admin.post('/malware/clamav/update')
        if j.get('job_id'):
            wait_job(admin, j['job_id'], 'ClamAV update')


def hash_sets(admin: Api, laptop: str):
    """A known-bad set with the wiping tool's hashes and a notable set with the payroll export's, built from the files
    the analysis found; importing a set re-matches the evidence already analysed."""
    existing = {s.get('name') for s in rows(admin.get('/hashsets'))}
    wanted = {'Demo known-bad tools': ('KNOWN_BAD', 'SecureDelete'), 'Demo notable payroll files': ('NOTABLE', 'payroll')}
    for name, (kind, q) in wanted.items():
        if name in existing:
            continue
        hashes = sorted({f['sha256'] for f in rows(admin.get(f'/forensics/evidence/{laptop}/files', q=q, limit=200)) if f.get('sha256')})
        if not hashes:
            say(f'  No files matching "{q}" to build "{name}" from; skipped')
            continue
        r = admin.form('/hashsets', {'name': name, 'kind': kind, 'description': f'Demo: files whose name contains "{q}"'},
                       [('file', f'{kind.lower()}.txt', ('\n'.join(hashes) + '\n').encode())])
        if isinstance(r, dict) and r.get('job_id'):
            wait_job(admin, r['job_id'], f'Hash set "{name}"')
        say(f'  Imported the hash set "{name}" ({len(hashes)} hashes, {kind})')


# ------------------------------------------------------------------------------------------------ case 1
def main_case(inv: Api, admin: Api, img: Path):
    laptop_img = img / 'dfip-test-disk.dd'
    if not laptop_img.is_file():
        raise SystemExit(f'{laptop_img} is missing. Generate the test images first (README, "Load the complete demo data").')
    case = ensure_case(inv, CASE_MAIN, 'Demonstration case built from synthetic test evidence. Alice, an accountant, is '
                       'suspected of exporting the payroll, copying it to a USB drive, sending it out and wiping the traces.', 'HIGH')
    laptop = ensure_evidence(inv, case, [laptop_img])
    others = [ensure_evidence(inv, case, [p]) for p in (img / 'dfip-ntfs-disk.dd', img / 'dfip-test-capture.pcap',
                                                         img / 'dfip-test-android.zip', img / 'dfip-test-iphone.zip') if p.is_file()]
    analyse(inv, case, [laptop] + others)

    plaso = img / 'dfip-test-disk.plaso.jsonl'
    if plaso.is_file() and not rows(inv.get(f'/cases/{case}/timeline-imports')):
        r = inv.form(f'/cases/{case}/timeline-imports', {'evidence_id': laptop}, [('file', plaso.name, plaso.read_bytes())])
        if isinstance(r, dict) and r.get('job_id'):
            wait_job(inv, r['job_id'], 'Plaso timeline import')
        say('  Imported Plaso\'s timeline of the laptop')

    # The deleted payroll export, recovered from the image (Files, Recovered files).
    deleted = [f for f in rows(inv.get(f'/forensics/evidence/{laptop}/files', deleted='true', q='payroll', limit=50)) if not f.get('is_dir')]
    if deleted and not rows(inv.get('/forensics/artifacts', case_id=case, artifact_type='RECOVERED_FILE')):
        r = inv.post(f'/forensics/evidence/{laptop}/recover', inode=str(deleted[0]['inode']), offset=deleted[0].get('partition_offset', 0))
        if r.get('status') == 'COMPLETED':
            say(f'  Recovered the deleted file {deleted[0].get("path")} (SHA-256 {r["sha256"][:16]}...)')
        else:
            say(f'  Could not recover {deleted[0].get("path")}: {r.get("error") or r.get("status")}')
    if not rows(inv.get('/forensics/artifacts', case_id=case, artifact_type='CARVED_FILE')):
        say('  Carving files out of the laptop image with PhotoRec')
        inv.post(f'/forensics/evidence/{laptop}/carve')

    hash_sets(admin, laptop)

    # Tags on the key records (Tagged items, and the report's tagged evidence section).
    if not rows(inv.get('/tags', case_id=case)):
        def tag(item_type: str, item_id: str, label: str, note: str):
            inv.post('/tags', {'case_id': case, 'item_type': item_type, 'item_id': item_id, 'label': label, 'note': note})
        if deleted:
            tag('FILE', deleted[0]['_id'], 'EVIDENCE', 'The payroll export, deleted after it was copied out')
        usb = rows(inv.get('/forensics/usb', case_id=case))
        if usb:
            tag('USB', usb[0]['_id'], 'EVIDENCE', 'A USB drive connected to the laptop')
        downloads = rows(inv.get('/forensics/browser', case_id=case, kind='BROWSER_DOWNLOAD'))
        if downloads:
            tag('BROWSER', downloads[0]['_id'], 'NOTABLE', 'A download on the day of the leak')
        say('  Tagged the deleted export, a USB drive and a download')

    # Findings: one approved, one in review, one draft; the analyst joins the case and is mentioned in a comment.
    analyst_id = user_id(admin, 'analyst@dfip.local')
    if analyst_id:
        inv.call('PUT', f'/cases/{case}/members', {'member_ids': [analyst_id]})
    if not rows(inv.get('/findings', case_id=case)):
        admin_id = user_id(admin, 'admin@dfip.local')
        f1 = inv.post('/findings', {'case_id': case, 'severity': 'HIGH', 'evidence_ids': [laptop],
                                    'title': 'Payroll export handled on a USB drive, then deleted',
                                    'description': 'On 1 September 2026 Alice opened payroll-export.csv from the SanDisk USB drive '
                                                   '(E:, connected 14:12 UTC); the copy in Documents was deleted and another sent to '
                                                   'the Recycle Bin (Files, USB devices, Windows activity, Timeline).'})
        f2 = inv.post('/findings', {'case_id': case, 'severity': 'HIGH', 'evidence_ids': [laptop],
                                    'title': 'Wiping tool downloaded and run',
                                    'description': 'SecureDelete.exe was downloaded with Chrome and run; a "Secure Delete Helper" '
                                                   'service was installed, the Security log was cleared, and a packed copy sits in '
                                                   'the Temp folder as svchost.exe (Browser history, Windows activity, Event logs, '
                                                   'Indicators).'})
        inv.post('/findings', {'case_id': case, 'severity': 'MEDIUM', 'evidence_ids': [laptop] + others[:2],
                               'title': 'Payroll data sent out of the company',
                               'description': 'The network capture shows payroll-export.csv uploaded over plain HTTP to '
                                              'filetransfer.example.net at 14:20 UTC (Network), and the mailbox shows it sent to '
                                              'a private address at 14:20:31 (Email). To be confirmed with the mail server logs.'})
        for f in (f1, f2):
            inv.post(f'/findings/{f["_id"]}/submit', {'reviewer_id': admin_id, 'note': 'Ready for review'})
        admin.post(f'/findings/{f1["_id"]}/review', {'decision': 'APPROVED', 'note': 'Agreed; well supported.'})
        inv.post('/comments', {'case_id': case, 'target_type': 'FINDING', 'target_id': f2['_id'],
                               'text': '@analyst@dfip.local can you confirm when svchost.exe in Temp was first run?'})
        say('  Recorded three findings (approved, in review, draft) and a comment mentioning the analyst')

    # The seized laptop, booked in and moved through the custody log.
    if not rows(inv.get('/physical', case_id=case)):
        item = inv.post('/physical', {'case_id': case, 'description': "Alice's laptop, Dell Latitude 5420", 'kind': 'Laptop',
                                      'make': 'Dell', 'model': 'Latitude 5420', 'serial_number': 'DL5420-7781', 'bag_number': 'BAG-0417',
                                      'seal_number': 'SEAL-20931', 'seized_from': 'Finance office, desk 3', 'seized_by': 'D. Investigator',
                                      'location': 'Evidence store, shelf B2', 'evidence_ids': [laptop]})
        iid = item['item_id']
        inv.post(f'/physical/{iid}/custody', {'action': 'CHECK_OUT', 'person': 'Analyst', 'purpose': 'Imaging in the lab'})
        inv.post(f'/physical/{iid}/custody', {'action': 'CHECK_IN', 'location': 'Evidence store, shelf B2', 'seal_intact': True})
        say('  Booked the laptop in as physical evidence, checked it out and back in')

    if not rows(inv.get('/reports', case_id=case)):
        r = inv.post('/reports', {}, case_id=case)
        say(f'  Generated the signed report {r.get("report_id", "")}')


# ------------------------------------------------------------------------------------------------ case 2
def collections_case(inv: Api, img: Path):
    files = [p for p in (img / 'dfip-linux-disk.dd', img / 'dfip-test-macos.tar', img / 'dfip-test-kape.zip',
                         img / 'dfip-test-velociraptor.zip') if p.is_file()]
    if not files:
        return
    case = ensure_case(inv, CASE_COLLECTIONS, 'Demonstration case: a Linux server disk, a collection from a Mac, and KAPE and '
                       'Velociraptor triage packages of the laptop.', 'MEDIUM')
    analyse(inv, case, [ensure_evidence(inv, case, [p]) for p in files])


# ------------------------------------------------------------------------------------------------ case 3
def samples_case(inv: Api, img: Path):
    dfvfs = img / 'samples' / 'dfvfs'
    if not dfvfs.is_dir():
        say('Public samples not downloaded (scripts/test-image/fetch_samples.py); the encrypted-volume case is skipped.')
        return
    case = ensure_case(inv, CASE_SAMPLES, 'Demonstration case built from public test samples (dfVFS, Plaso, python-evtx): '
                       'encrypted volumes, Volume Shadow Copies, a split EnCase image and a disk with real Windows records.', 'LOW')
    ids = [ensure_evidence(inv, case, [p]) for p in (dfvfs / 'vss.raw', img / 'dfip-samples-disk.dd') if p.is_file()]
    split = [dfvfs / 'ext2.split.E01', dfvfs / 'ext2.split.E02']
    if all(p.is_file() for p in split):
        ids.append(ensure_evidence(inv, case, split))
    locked = [(ensure_evidence(inv, case, [dfvfs / name]), secret) for name, secret in (('bdetogo.raw', 'bde-TEST'), ('luks1.raw', 'luksde-TEST'))
              if (dfvfs / name).is_file()]
    analyse(inv, case, ids + [eid for eid, _ in locked])
    unlocked = {(e.get('derived_from') or {}).get('evidence_id') for e in case_evidence(inv, case)}
    for eid, secret in locked:
        if eid in unlocked:
            continue
        r = inv.post(f'/evidence/{eid}/volumes/p0/unlock', {'method': 'password', 'secret': secret})
        j = wait_job(inv, r['job_id'], f'Unlocking {eid}')
        then = (j.get('result') or {}).get('analysis_job_id')
        if then:
            wait_job(inv, then, 'Analysis of the decrypted volume')
        say(f'  Unlocked the encrypted volume of {eid} into {(j.get("result") or {}).get("derived_evidence_id")}')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--base', default='http://backend:8000', help='DFIP address (default: the backend inside the Compose network)')
    ap.add_argument('--images', default='/img', help='folder holding the generated test images (storage/test-images)')
    ap.add_argument('--clamav', action='store_true', help='download the ClamAV databases first (needs internet access)')
    a = ap.parse_args()
    img = Path(a.images)
    wait_healthy(a.base)
    admin = Api(a.base).sign_in('admin@dfip.local')
    inv = Api(a.base).sign_in('investigator@dfip.local')
    start = time.time()
    admin_setup(admin, a.clamav)
    main_case(inv, admin, img)
    collections_case(inv, img)
    samples_case(inv, img)
    say(f'Done in {(time.time() - start) / 60:.0f} min. Sign in at http://localhost and pick a DEMO case in the case switcher.')


if __name__ == '__main__':
    sys.exit(main())
