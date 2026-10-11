import json, random
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
EMAIL = f'new.investigator.{random.randint(1000, 9999)}@example.org'
PW = 'Correct-Horse-Battery-7'
problems = []

with sync_playwright() as p:
    b = p.chromium.launch()
    expect.set_options(timeout=20000)

    # 1. Create an account from the website.
    ctx = b.new_context(viewport={'width': 1440, 'height': 900})
    page = ctx.new_page()
    page.on('pageerror', lambda e: problems.append(f'JS error: {e}'))
    page.goto(BASE + '/')
    page.locator('.lp-nav-actions').get_by_role('link', name='Create account').click()
    expect(page.get_by_role('heading', name='Create your account')).to_be_visible()
    page.get_by_label('Full name').fill('Meera Nair')
    page.get_by_label('Work email').fill(EMAIL)
    page.get_by_label('Password', exact=True).fill(PW)
    page.get_by_label('Confirm password').fill('mismatch-password-1')
    expect(page.get_by_text('The passwords do not match.')).to_be_visible()
    page.get_by_label('Confirm password').fill(PW)
    page.screenshot(path='/out/a1-register.png')
    page.locator('form').get_by_role('button', name='Create account').click()
    expect(page.get_by_text('Account created. An administrator must approve it before you can sign in.')).to_be_visible()
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()

    # 2. Signing in before approval is refused with a clear message.
    page.get_by_label('Email').fill(EMAIL)
    page.get_by_label('Password').fill(PW)
    page.locator('form').get_by_role('button', name='Sign in').click()
    expect(page.get_by_text('Your account is waiting for administrator approval.')).to_be_visible()
    page.screenshot(path='/out/a2-pending.png')
    ctx.close()

    # 3. Administrator approves it from the Users page.
    ctx = b.new_context(viewport={'width': 1440, 'height': 900})
    page = ctx.new_page()
    page.goto(BASE + '/login')
    page.get_by_role('button', name='Administrator Everything + users').click()
    page.locator('form').get_by_role('button', name='Sign in').click()
    expect(page.get_by_text('Investigation functions').or_(page.get_by_text('Welcome,'))).to_be_visible()
    badge = page.get_by_title('Accounts waiting for approval')
    expect(badge).to_be_visible()
    page.locator('a.nav-link[href$="/admin/users"]').click()  # not "Computer and users"
    row = page.locator('tr', has_text=EMAIL)
    expect(row.get_by_role('button', name='Approve')).to_be_visible()
    page.screenshot(path='/out/a3-approvals.png', full_page=True)
    row.get_by_role('button', name='Approve').click()
    expect(page.get_by_text(f'{EMAIL} updated')).to_be_visible()
    ctx.close()

    # 4. The new user signs in; a new browser session must sign in again.
    ctx = b.new_context(viewport={'width': 1440, 'height': 900})
    page = ctx.new_page()
    page.goto(BASE + '/login')
    page.get_by_label('Email').fill(EMAIL)
    page.get_by_label('Password').fill(PW)
    page.locator('form').get_by_role('button', name='Sign in').click()
    expect(page.get_by_text('Welcome, Meera Nair')).to_be_visible()
    expect(page.get_by_role('button', name='Create a case')).to_be_visible()
    page.screenshot(path='/out/a4-new-user.png')
    page.reload()
    expect(page.get_by_text('Welcome, Meera Nair')).to_be_visible()  # same session survives a reload
    stored = page.evaluate("[localStorage.getItem('dfip_token'), !!sessionStorage.getItem('dfip_token')]")
    assert stored == [None, True], stored
    ctx.close()

    ctx = b.new_context(viewport={'width': 1440, 'height': 900})  # browser closed and reopened
    page = ctx.new_page()
    page.goto(BASE + '/app')
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()

    # 5. A token left in localStorage by an older version is ignored and deleted.
    tok = page.request.post(BASE + '/api/auth/login', data=json.dumps({'email': EMAIL, 'password': PW}),
                            headers={'Content-Type': 'application/json'}).json()
    page.evaluate("t => { localStorage.setItem('dfip_token', t.access_token); localStorage.setItem('dfip_refresh', t.refresh_token); }", tok)
    page.goto(BASE + '/app')
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
    assert page.evaluate("localStorage.getItem('dfip_token')") is None
    b.close()

print('AUTH CHECKS PASSED' if not problems else 'Problems:\n' + '\n'.join(problems))
