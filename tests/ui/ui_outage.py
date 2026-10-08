"""What the UI does while the API is down and after it comes back. The host stops and starts the
backend container when this script signals it through marker files in /out."""
import os, time
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
results = []


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('  PASS ' if cond else '  FAIL ') + name + ('' if cond else f'  ::  {detail}'), flush=True)


def signal(name):
    open(f'/out/{name}', 'w').close()


def wait_for(name, timeout=180):
    t0 = time.time()
    while not os.path.exists(f'/out/{name}'):
        if time.time() - t0 > timeout:
            raise TimeoutError(name)
        time.sleep(0.5)


with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={'width': 1440, 'height': 900})
    expect.set_options(timeout=30000)
    page.goto(BASE + '/login')
    page.get_by_role('button', name='Investigator Full case work').click()
    page.locator('form').get_by_role('button', name='Sign in').click()
    expect(page.locator('.topbar')).to_be_visible()

    signal('ready-for-stop')
    wait_for('backend-stopped')
    page.get_by_role('link', name='Timeline').first.click()
    page.wait_for_timeout(10000)
    page.screenshot(path='/out/o1-down.png')
    body = page.inner_text('body')
    check('while the API is down, pages explain that the server is not responding', 'The DFIP server is not responding' in body,
          body[:600].replace('\n', ' | '))
    page.reload()
    expect(page.get_by_text('Server unreachable')).to_be_visible()
    check('reloading while down shows the sign-in page with "Server unreachable"', '/login' in page.url, page.url)
    token_kept = page.evaluate("sessionStorage.getItem('dfip_token') !== null")
    check('the session is kept during the outage', token_kept)

    signal('ready-for-start')
    wait_for('backend-started')
    page.goto(BASE + '/app')
    expect(page.locator('.topbar')).to_be_visible()
    check('after the API is back, the user continues without signing in again', '/app' in page.url, page.url)
    b.close()

print(f'ui_outage: {sum(results)} passed, {len(results) - sum(results)} failed')
