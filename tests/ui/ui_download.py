import hashlib, json, urllib.request
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
info = json.load(urllib.request.urlopen(BASE + '/api/desktop/download/info'))
assert info['available'], info
f = info['files'][0]
print('published:', f['filename'], f['size'], f['sha256'][:16])

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={'width': 1440, 'height': 900}, accept_downloads=True)
    page = ctx.new_page()
    page.goto(BASE + '/')
    nav_btn = page.locator('.lp-hero').get_by_role('link', name='Download for Windows')
    expect(nav_btn).to_be_visible()
    expect(page.locator('.lp-platform.featured').get_by_role('link', name='Download')).to_be_visible()
    page.screenshot(path='/out/dl-1-landing.png')
    with page.expect_download() as d:
        nav_btn.click()
    path = '/out/' + d.value.suggested_filename
    d.value.save_as(path)
    digest = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    print('downloaded:', d.value.suggested_filename, 'sha256 match:', digest == f['sha256'])
    assert digest == f['sha256']

    page.locator('#download').scroll_into_view_if_needed()
    page.screenshot(path='/out/dl-2-section.png')

    page.goto(BASE + '/login')
    expect(page.get_by_text('Prefer a desktop app?')).to_be_visible()
    page.screenshot(path='/out/dl-3-login.png')

    tok = page.request.post(BASE + '/api/auth/login', data=json.dumps({'email': 'investigator@dfip.local', 'password': 'DemoPassword!2026'}),
                            headers={'Content-Type': 'application/json'}).json()
    page.evaluate("t => { sessionStorage.setItem('dfip_token', t.access_token); sessionStorage.setItem('dfip_refresh', t.refresh_token); }", tok)
    page.goto(BASE + '/app')
    expect(page.locator('.nav-download').get_by_role('link', name='Download for Windows')).to_be_visible()
    page.screenshot(path='/out/dl-4-workspace.png')
    b.close()
print('DOWNLOAD CHECKS PASSED')
