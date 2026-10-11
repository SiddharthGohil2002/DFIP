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
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def bodyfile_truth():
    """Parses `fls -r -m / -o 2048` directly: the filesystem as Sleuth Kit sees it."""
    out = sh('fls', '-r', '-m', '/', '-o', '2048', str(IMG)).stdout.decode('utf-8', 'replace')
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
    check('path filter is case-insensitive (the CSV and its Recent shortcut)', q['total'] == len(want) == 2
          and {d['path'] for d in q['data']} == want, (q['total'], want))
    check('regex characters in the filter are treated literally', get(f'/api/forensics/evidence/{E}/files?q=.%2A', inv).json['total'] == 0)
    check('deleted=false excludes the deleted file', all(not f['deleted'] for f in get(f'/api/forensics/evidence/{E}/files?deleted=false&limit=1000', inv).json['data']))
    ist = post(f"/api/forensics/evidence/{E}/istat?inode={pay['inode']}&offset={pay['partition_offset']}", inv)
    check('istat on the deleted file shows its size', ist.status == 200 and '2191' in json.dumps(ist.json), str(ist)[:200])
    check('istat refuses an injected inode value (400)', post(f"/api/forensics/evidence/{E}/istat?inode=5;id&offset=2048", inv).status == 400)


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
        fh.write(sh('fls', '-r', '-m', '/', '-o', '2048', str(IMG)).stdout.decode('utf-8', 'replace'))
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
    check('USB event count equals the USB times the devices have', len(usb) == sum(
        sum(1 for k in ('first_install', 'last_install', 'last_arrival', 'last_removal', 'setupapi_first_install') if d.get(k))
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
        local = datetime.strptime(m.group(2), '%Y/%m/%d %H:%M:%S').replace(tzinfo=timezone.utc)
        first.setdefault(m.group(1).upper(), local + timedelta(minutes=bias))
    by = {d['serial'].upper(): d for d in devs}
    check('every USBSTOR device in the registry is reported', serials <= set(by), (serials, set(by)))
    check('the device only in setupapi.dev.log (SanDisk) is reported', '4C530001230518109141' in by, set(by))
    for serial, when in first.items():
        d = by.get(serial, {})
        check(f'setupapi first install for {serial} is {when:%Y-%m-%d %H:%M:%S} UTC (log time + ActiveTimeBias)',
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
    visit = next(r for r in get(f'/api/forensics/browser?case_id={A}&kind=BROWSER_HISTORY', inv).json['data'] if 'filetransfer' in r['url'])
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
          and tag({'item_type': 'EMAIL', 'item_id': C['PAY']['_id']}).status == 400)
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
    check('providers report which have keys (none configured here)', p == {'virustotal': False, 'abuseipdb': False, 'otx': False, 'urlhaus': False}, p)
    h = post(f"/api/threat-intel/hash/{hashlib.sha256(CLEANUP).hexdigest()}?case_id={A}", inv)
    check('hash lookup without keys answers cleanly', h.status == 200, h)
    note('hash lookup result without keys', json.dumps(h.json)[:300])
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
    j = wait_job(inv, post(f"/api/jobs/analysis/{eid}", inv).json['job_id'])
    check('E01 analysis completes', j['status'] == 'COMPLETED', j.get('error'))
    wc = [c for c in get(f'/api/chain?case_id={case}', inv).json['data'] if c['action'] == 'WORKING_COPY_CREATED']
    check('the verified raw working copy is recorded in the chain of custody', wc and wc[0]['sha256'] == C['IMG_SHA256'],
          wc[:1] or 'no WORKING_COPY_CREATED record')
    check('the uploaded E01 itself is unchanged', hashlib.sha256(Path(r.json['storage_path']).read_bytes()).hexdigest() == r.json['sha256'])
    check('partitions can be examined after the analysis', get(f'/api/forensics/evidence/{eid}/partitions', inv).status == 200)
    if j['status'] == 'COMPLETED':
        c = j['result']['summary']['counts']
        same = {k: (c.get(k), C['COUNTS'].get(k)) for k in C['COUNTS'] if c.get(k) != C['COUNTS'].get(k)}
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
    }
    diff = {k: (c.get(k), v) for k, v in exp.items() if c.get(k) != v}
    check('every overview count equals the matching list', not diff, diff)
    check('overview lists recent jobs', len(o['jobs']) >= 1)


ACTIVITY_EVENT_TYPES = 'BROWSER_VISIT,BROWSER_DOWNLOAD,USB_ACTIVITY,PROGRAM_RUN,RECENT_FILE_OPENED,FILE_DELETED_TO_RECYCLE_BIN'


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
    fields = ('setupapi_first_install', 'first_install', 'last_install', 'last_arrival', 'last_removal')
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
    job = post(f'/api/jobs/analysis/{eid}', inv).json['job_id']
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
    results = ('fs_entries', 'timeline_events', 'forensic_artifacts', 'usb_artifacts')
    before = {c: db[c].count_documents({'evidence_id': eid}) for c in results}
    stored = [p for p in glob.glob(f'/app/storage/analysis/*/{eid}') if os.path.isdir(p)]
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
    check('the stored image and its recovered, carved and pipeline files are removed',
          len(stored) >= 3 and not original.exists() and not any(os.path.exists(p) for p in stored), stored)
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
    'main': [t_platform, t_auth, t_register, t_cases, t_rbac, t_evidence, t_analysis, t_filesystem, t_recovery, t_viewer, t_timeline,
             t_browser, t_usb, t_activity, t_indicators, t_carving, t_search, t_findings, t_tags, t_analyst, t_reports, t_audit, t_notifications,
             t_admin, t_desktop, t_websocket, t_misc, t_e01, t_bad_images, t_cancel, t_overview, t_dashboard, t_tamper, t_audit_tamper, t_delete, t_legal_hold],
    'desktop_writes': [t_desktop_writes],
    'reg_open': [t_reg_open],
    'reg_disabled': [t_reg_disabled],
}

if __name__ == '__main__':
    t0 = time.time()
    for fn in PHASES[PHASE]:
        fn()
    (OUT / f'results-{PHASE}.json').write_text(json.dumps(RESULTS, indent=1, default=str))
    if PHASE == 'main':  # what check_pdf.py looks for in the saved reports
        (OUT / 'pdf_expect.json').write_text(json.dumps({'case': C.get('A'), 'evidence': C.get('E'), 'sha256': C.get('IMG_SHA256'),
                                                         'tamper_case': C.get('TAMPER_CASE')}))
    n_pass = sum(1 for r in RESULTS if r['ok'] is True)
    n_fail = sum(1 for r in RESULTS if r['ok'] is False)
    print(f'\n{PHASE}: {n_pass} passed, {n_fail} failed, {sum(1 for r in RESULTS if r["ok"] is None)} notes in {time.time() - t0:.0f}s')
