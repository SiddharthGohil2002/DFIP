import json
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
PAGES = ['', 'cases', 'evidence', 'files', 'timeline', 'browser', 'usb', 'indicators', 'carving', 'search', 'findings',
         'reports', 'custody', 'admin/users', 'admin/audit', 'admin/system', 'admin/hashsets']
problems = []

with sync_playwright() as p:
    b = p.chromium.launch()
    for email in ['viewer@dfip.local', 'analyst@dfip.local', 'admin@dfip.local']:
        ctx = b.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        where = {'v': ''}
        page.on('pageerror', lambda e: problems.append(f'[{email} {where["v"]}] JS error: {e}'))
        page.on('response', lambda r: '/api/' in r.url and r.status >= 400 and problems.append(f'[{email} {where["v"]}] HTTP {r.status} {r.url.split("/api")[1][:90]}'))
        tok = page.request.post(BASE + '/api/auth/login', data=json.dumps({'email': email, 'password': 'DemoPassword!2026'}),
                                headers={'Content-Type': 'application/json'}).json()
        page.goto(BASE + '/login')
        page.evaluate("t => { sessionStorage.setItem('dfip_token', t.access_token); sessionStorage.setItem('dfip_refresh', t.refresh_token); }", tok)
        for path in PAGES:
            where['v'] = '/app/' + path
            page.goto(f'{BASE}/app/{path}')
            page.wait_for_load_state('networkidle')
            if len(page.inner_text('main').strip()) < 20:
                problems.append(f'[{email} /app/{path}] blank page')
        role = email.split('@')[0]
        nav = page.inner_text('nav')
        if role == 'viewer':
            page.goto(BASE + '/app')
            page.wait_for_load_state('networkidle')
            for label in ['New case', 'Add evidence', 'Generate report', 'Re-run', 'Analyze']:
                if page.get_by_role('button', name=label).count():
                    problems.append(f'[viewer] write action visible: {label}')
            if 'Users' in nav or 'Audit log' in nav or 'Hash sets' in nav:
                problems.append('[viewer] admin nav visible')
        if role in ('viewer', 'analyst'):
            page.goto(BASE + '/app/evidence')
            page.wait_for_load_state('networkidle')
            if page.get_by_role('button', name='Delete').count():
                problems.append(f'[{role}] Delete evidence visible')
        if role == 'analyst' and 'Users' in nav:
            problems.append('[analyst] Users nav visible')
        if role == 'admin':
            page.goto(BASE + '/app/admin/users')
            expect(page.get_by_text('investigator@dfip.local')).to_be_visible()
            page.screenshot(path='/out/r-admin-users.png', full_page=True)
        ctx.close()
    b.close()
print(f'{len(problems)} problems')
print('\n'.join(problems))
