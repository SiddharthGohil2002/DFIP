"""Checks the desktop build (dist-desktop) served on 127.0.0.1:1420, as `tauri dev` would load it."""
import json, subprocess, time, urllib.error, urllib.request, uuid
from playwright.sync_api import sync_playwright, expect

srv = subprocess.Popen(['python3', '-m', 'http.server', '1420', '--bind', '127.0.0.1', '--directory', '/dist'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)
APP = 'http://127.0.0.1:1420/'
API = 'http://host.docker.internal:8000/api'
problems, step = [], {'v': 'start'}


def api(method, path, token=None, body=None, raw=None, ctype='application/json'):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(API + path, data=data, method=method)
    if data is not None:
        req.add_header('Content-Type', ctype)
    if token:
        req.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


def laptop_case():
    """A case holding the analysed laptop image, for a stack where no other suite left one (a fresh installation:
    ui_e2e deletes the evidence it uploaded)."""
    token = api('POST', '/auth/login', body={'email': 'investigator@dfip.local', 'password': 'DemoPassword!2026'})['access_token']
    case_id = api('POST', '/cases', token, {'name': f'UI desktop — laptop image {uuid.uuid4().hex[:4]}', 'priority': 'LOW'})['case_id']
    b = uuid.uuid4().hex
    body = (f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="dfip-test-disk.dd"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() \
        + open('/img/dfip-test-disk.dd', 'rb').read() + f'\r\n--{b}--\r\n'.encode()
    eid = api('POST', '/evidence/upload', token, raw=body, ctype=f'multipart/form-data; boundary={b}')['evidence_id']
    job = api('POST', f'/jobs/analysis/{eid}', token)['job_id']
    for _ in range(600):
        try:
            if api('GET', f'/jobs/{job}', token)['status'] in ('COMPLETED', 'FAILED'):
                break
        except urllib.error.URLError:  # a dropped poll (container networking) is retried
            pass
        time.sleep(1)
    return case_id

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={'width': 1440, 'height': 900})
    page.on('pageerror', lambda e: problems.append(f'[{step["v"]}] JS error: {e}'))
    page.on('response', lambda r: '/api/' in r.url and r.status >= 400 and problems.append(f'[{step["v"]}] HTTP {r.status} {r.url}'))
    expect.set_options(timeout=20000)

    step['v'] = 'opens on login'
    page.goto(APP)
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
    assert '#/login' in page.url, page.url
    expect(page.get_by_text('DFIP Investigator desktop')).to_be_visible()
    expect(page.get_by_text('Back to the DFIP website')).to_have_count(0)
    expect(page.get_by_text('Server unreachable')).to_be_visible()

    step['v'] = 'configure server'
    page.get_by_role('button', name='Server').click()
    page.get_by_placeholder('http://localhost:8000').fill('http://host.docker.internal:8000')
    page.get_by_role('button', name='Save and test connection').click()
    expect(page.get_by_text('Server online · v2.1.0')).to_be_visible()
    page.screenshot(path='/out/d1-login.png')

    step['v'] = 'sign in'
    page.get_by_role('button', name='Investigator Full case work').click()
    page.get_by_role('button', name='Sign in').click()
    expect(page.get_by_text('Investigation functions')).to_be_visible()
    assert '#/app' in page.url, page.url
    expect(page.get_by_text('This workstation')).to_be_visible()
    expect(page.get_by_role('definition').filter(has_text='host.docker.internal:8000')).to_be_visible()
    token = page.evaluate("sessionStorage.getItem('dfip_device_token')")
    assert token, 'workstation was not registered'
    page.screenshot(path='/out/d2-desktop-home.png', full_page=True)

    step['v'] = 'evidence detail'
    # Other suites may have left a newer, empty case active: switch to one with analysed evidence.
    analysed = page.evaluate("""async () => {
        const r = await fetch('http://host.docker.internal:8000/api/evidence',
                              { headers: { Authorization: 'Bearer ' + sessionStorage.getItem('dfip_token') } });
        const e = (await r.json()).data.find((x) => x.analysis_status === 'COMPLETED' && x.filename === 'dfip-test-disk.dd');  // the laptop
        return e && e.case_id;
    }""")
    if not analysed:
        analysed = laptop_case()
        page.reload()  # the case list is loaded at sign-in
        expect(page.get_by_text('Investigation functions')).to_be_visible()
    page.get_by_label('Active case').select_option(analysed)
    page.get_by_role('link', name='Case desktop').first.click()
    page.get_by_role('link', name='Open', exact=True).first.click()
    expect(page.get_by_text('Verify a local copy')).to_be_visible()
    expect(page.get_by_text('Available in the installed DFIP desktop app.')).to_be_visible()

    step['v'] = 'pages'
    for label, text in [('Timeline', 'Events over time'), ('USB devices', 'HP v100w USB Device'), ('Reports', 'What the report holds'), ('System & tools', 'This workstation')]:
        page.get_by_role('link', name=label).first.click()
        expect(page.get_by_text(text).first).to_be_visible()
    page.screenshot(path='/out/d3-timeline.png') if False else None

    step['v'] = 'sign out'
    page.get_by_title('Sign out').click()
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
    page.goto(APP + '#/')
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
    b.close()

srv.terminate()
print('DESKTOP CHECKS PASSED' if not problems else 'Problems:\n' + '\n'.join(problems))
