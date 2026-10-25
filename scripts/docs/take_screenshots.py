"""Takes the screenshots of docs/USER_GUIDE.md (docs/guide/images/*.webp) from a DFIP that holds the demo data
(scripts/demo/load_demo_data.py), so the guide shows the product as it is. Retake them after visible UI changes.

From the repository root, with DFIP on http://localhost and the demo data loaded:

    docker run --rm --add-host=host.docker.internal:host-gateway -v "${PWD}/scripts/docs:/w:ro" -v "${PWD}/docs/guide/images:/out" mcr.microsoft.com/playwright/python:v1.48.0-jammy bash -c "pip install -q playwright==1.48.0 pillow==11.3.0 && python /w/take_screenshots.py"

An address other than http://localhost (DFIP on port 80 of this computer) can be given as the argument. Inside the
container the browser resolves localhost to the computer running it, so the pages show the address a user would see.
"""
import io
import json
import sys
import urllib.request

from PIL import Image
from playwright.sync_api import expect, sync_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://localhost').rstrip('/')
API = BASE.replace('//localhost', '//host.docker.internal')  # the script's own requests, from inside the container
OUT = '/out'
PASSWORD = 'DemoPassword!2026'
MAIN = "DEMO - Payroll data leak (Alice's laptop)"
COLLECTIONS = 'DEMO - Collections: Linux server, Mac and triage packages'
SAMPLES = 'DEMO - Encrypted volumes, shadow copies and image formats'

# (image name, route) of the investigator's pages in the main demo case, in the guide's order.
CASE_PAGES = [
    ('case-desktop', '/app'), ('cases', '/app/cases'), ('evidence', '/app/evidence'), ('physical', '/app/physical'),
    ('dashboard', '/app/dashboard'), ('files', '/app/files'), ('timeline', '/app/timeline'), ('browser', '/app/browser'),
    ('email', '/app/email'), ('chat-cloud', '/app/chat-cloud'), ('phones', '/app/phones'), ('network', '/app/network'),
    ('media', '/app/media'), ('usb', '/app/usb'), ('activity', '/app/activity'), ('event-logs', '/app/event-logs'),
    ('ntfs', '/app/ntfs'), ('computer', '/app/computer'), ('indicators', '/app/indicators'), ('carving', '/app/carving'),
    ('found-data', '/app/found-data'), ('graph', '/app/graph'), ('summary', '/app/summary'),
    ('search', '/app/search?q=payroll'), ('findings', '/app/findings'), ('tagged', '/app/tagged'),
    ('reports', '/app/reports'), ('custody', '/app/custody'),
]
ADMIN_PAGES = [('users', '/app/admin/users'), ('audit', '/app/admin/audit'), ('hashsets', '/app/admin/hashsets'),
               ('malware-rules', '/app/admin/malware-rules'), ('retention', '/app/admin/retention'), ('system', '/app/admin/system')]


def api(path, token=None, body=None):
    req = urllib.request.Request(API + '/api' + path, data=json.dumps(body).encode() if body is not None else None,
                                 method='POST' if body is not None else 'GET')
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def save(page, name):
    Image.open(io.BytesIO(page.screenshot())).convert('RGB').save(f'{OUT}/{name}.webp', 'WEBP', quality=80, method=6)
    print(name, flush=True)


def settle(page):
    """Waits for the page's data: no requests for a moment (pages that poll never go fully quiet), then the render."""
    try:
        page.wait_for_load_state('networkidle', timeout=8000)
    except Exception:
        pass
    page.wait_for_timeout(800)


def sign_in(page, role):
    page.goto(BASE + '/login')
    page.get_by_role('button', name=role).click()
    page.get_by_role('button', name='Sign in', exact=True).click()
    expect(page.get_by_role('button', name='Sign out')).to_be_visible(timeout=30000)


def shoot(page, name, route):
    page.goto(BASE + route)
    settle(page)
    save(page, name)


def main():
    token = api('/auth/login', body={'email': 'investigator@dfip.local', 'password': PASSWORD})['access_token']
    cases = {c['name']: c['case_id'] for c in api('/cases', token)['data']}
    if MAIN not in cases:
        raise SystemExit(f'"{MAIN}" is not in this DFIP: load the demo data first (scripts/demo/load_demo_data.py).')
    laptop = next(e['evidence_id'] for e in api('/evidence', token)['data']
                  if e['case_id'] == cases[MAIN] and e['filename'] == 'dfip-test-disk.dd')

    with sync_playwright() as p:
        browser = p.chromium.launch(args=['--host-resolver-rules=MAP localhost host.docker.internal'])
        page = browser.new_page(viewport={'width': 1440, 'height': 900})
        page.set_default_timeout(30000)
        expect.set_options(timeout=30000)

        shoot(page, 'website', '/')
        shoot(page, 'sign-in', '/login')

        sign_in(page, 'Investigator Full case work')
        page.get_by_label('Active case').select_option(cases[MAIN])
        settle(page)
        for name, route in CASE_PAGES:
            shoot(page, name, route)
        shoot(page, 'evidence-detail', f'/app/evidence/{laptop}')
        page.get_by_role('button', name='Analysis options').click()
        expect(page.get_by_role('button', name='Start analysis')).to_be_visible()
        page.wait_for_timeout(500)
        save(page, 'analysis-options')
        page.keyboard.press('Escape')

        if COLLECTIONS in cases:
            page.get_by_label('Active case').select_option(cases[COLLECTIONS])
            settle(page)
            shoot(page, 'unix', '/app/unix')
        if SAMPLES in cases:
            page.get_by_label('Active case').select_option(cases[SAMPLES])
            settle(page)
            shoot(page, 'shadow-copies', '/app/shadow-copies')

        page.get_by_role('button', name='Sign out').click()
        sign_in(page, 'Administrator Everything + users')
        page.get_by_label('Active case').select_option(cases[MAIN])
        settle(page)
        for name, route in ADMIN_PAGES:
            shoot(page, name, route)
        browser.close()


if __name__ == '__main__':
    main()
