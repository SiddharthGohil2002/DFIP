"""End-to-end check of the analysis pipeline against a running DFIP stack.

Usage (from the repo root, after building the test image):
    python scripts/test-image/e2e_analysis.py [http://localhost]
Logs in as the demo investigator, creates a case, uploads
storage/test-images/dfip-test-disk.dd, runs Full Analysis and prints what was found.
"""
import hashlib
import json
import sys
import time
import urllib.request
import uuid
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://localhost').rstrip('/') + '/api'
IMAGE = Path('storage/test-images/dfip-test-disk.dd')


def call(method, path, token=None, body=None, raw=None, content_type='application/json'):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header('Content-Type', content_type)
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req, timeout=600) as r:
        payload = r.read()
        return json.loads(payload) if r.headers.get_content_type() == 'application/json' else payload


def upload(token, case_id):
    boundary = uuid.uuid4().hex
    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'.encode(),
             f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{IMAGE.name}"\r\n'
             f'Content-Type: application/octet-stream\r\n\r\n'.encode(), IMAGE.read_bytes(), f'\r\n--{boundary}--\r\n'.encode()]
    return call('POST', '/evidence/upload', token, raw=b''.join(parts), content_type=f'multipart/form-data; boundary={boundary}')


def main():
    token = call('POST', '/auth/login', body={'email': 'investigator@dfip.local', 'password': 'DemoPassword!2026'})['access_token']
    case = call('POST', '/cases', token, {'name': 'Test image analysis', 'priority': 'HIGH'})
    ev = upload(token, case['case_id'])
    local = hashlib.sha256(IMAGE.read_bytes()).hexdigest()
    print(f"case {case['case_id']}  evidence {ev['evidence_id']}  sha256 match: {ev['sha256'] == local}")

    job_id = call('POST', f"/jobs/analysis/{ev['evidence_id']}", token)['job_id']
    while True:
        job = call('GET', f'/jobs/{job_id}', token)
        if job['status'] in ('COMPLETED', 'FAILED', 'CANCELLED'):
            break
        time.sleep(1)
    print(f"job {job_id}: {job['status']} {job.get('error') or ''}")
    if job['status'] != 'COMPLETED':
        print(job.get('traceback'))
        sys.exit(1)
    summary = job['result']['summary']
    print('counts:', json.dumps(summary['counts']))
    print('filesystems:', [(f['partition_offset'], f['filesystem_type'], f.get('files')) for f in summary['filesystems']])
    print('warnings:', summary['warnings'])

    eid = ev['evidence_id']
    deleted = call('GET', f'/forensics/evidence/{eid}/files?deleted=true', token)
    print('deleted files:', [(f['path'], f['inode']) for f in deleted['data']])
    d = deleted['data'][0]
    rec = call('POST', f"/forensics/evidence/{eid}/recover?inode={d['inode']}&offset={d['partition_offset']}", token)
    print('recovered:', rec['filename'], rec['size'], 'bytes, was_deleted', rec['was_deleted'], rec['sha256'][:16])
    blob = call('GET', f"/forensics/artifacts/{rec['artifact_id']}/download", token)
    print('download sha256 match:', hashlib.sha256(blob).hexdigest() == rec['sha256'], '| first line:', blob.split(b'\n')[0])

    usb = call('GET', f"/forensics/usb?case_id={case['case_id']}", token)['data']
    for u in usb:
        print('usb:', u.get('friendly_name') or f"{u['vendor']} {u['product']}", u['serial'], u.get('vid'), u.get('pid'),
              u.get('drive_letters'), 'first_install', u.get('first_install'), 'setupapi', u.get('setupapi_first_install'))
    hist = call('GET', f"/forensics/browser?case_id={case['case_id']}&kind=BROWSER_HISTORY", token)['data']
    dls = call('GET', f"/forensics/browser?case_id={case['case_id']}&kind=BROWSER_DOWNLOAD", token)['data']
    print('browser history:', [(h['browser'], h['url']) for h in hist])
    print('browser downloads:', [(h['browser'], h['target_path']) for h in dls])
    mal = call('GET', f"/forensics/artifacts?case_id={case['case_id']}&artifact_type=MALWARE_INDICATOR", token)['data']
    print('yara:', [m['description'] for m in mal])
    tl = call('GET', f"/forensics/timeline?case_id={case['case_id']}&start=2026-09-01T00:00:00Z&order=asc&type=FILE_MACB,BROWSER_VISIT,BROWSER_DOWNLOAD,USB_ACTIVITY", token)
    print(f"timeline 2026-09-01 onwards ({tl['total']} events):")
    for e in tl['data'][:25]:
        print('  ', e['timestamp'], e['type'], e['description'])
    call('POST', '/findings', token, {'case_id': case['case_id'], 'title': 'Payroll export deleted after USB activity',
                                      'description': 'payroll-export.csv was created at 09:41 and later deleted; see timeline.',
                                      'severity': 'HIGH', 'evidence_ids': [eid]})
    report = call('POST', f"/reports?case_id={case['case_id']}", token)
    pdf = call('GET', f"/reports/{report['report_id']}/download", token)
    out = IMAGE.parent / f"{report['report_id']}.pdf"
    out.write_bytes(pdf)
    print(f"report {report['report_id']} v{report['version']}: {len(pdf)} bytes, sha256 match:",
          hashlib.sha256(pdf).hexdigest() == report['sha256'], '->', out)
    print('case', case['case_id'], 'evidence', eid)


if __name__ == '__main__':
    main()
