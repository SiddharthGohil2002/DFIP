from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
with sync_playwright() as p:
    b = p.chromium.launch()
    expect.set_options(timeout=20000)
    for width in (1440, 1100):
        page = b.new_context(viewport={'width': width, 'height': 900}).new_page()
        page.goto(BASE + '/login')
        page.get_by_role('button', name='Investigator Full case work').click()
        page.locator('form').get_by_role('button', name='Sign in').click()
        expect(page.get_by_text('Investigation functions')).to_be_visible()
        btn = page.locator('.topbar').get_by_role('button', name='Sign out')
        expect(btn).to_be_visible()
        box = btn.bounding_box()
        assert box['x'] + box['width'] <= width, f'Sign out button overflows at {width}px: {box}'
        overflow = page.evaluate("document.querySelector('.topbar').scrollWidth > document.querySelector('.topbar').clientWidth")
        print(f'{width}px: sign-out button at x={int(box["x"])}, top bar overflow={overflow}')
        page.screenshot(path=f'/out/s-topbar-{width}.png')
        btn.click()
        expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
        expect(page.get_by_text('You have signed out.')).to_be_visible()
        assert page.evaluate("sessionStorage.getItem('dfip_token')") is None
        page.goto(BASE + '/app')
        page.wait_for_load_state('networkidle')
        expect(page.get_by_role('heading', name='Sign in')).to_be_visible()  # the workspace URL cannot be reopened without signing in
        if width == 1440:
            page.screenshot(path='/out/s-signed-out.png')
        page.context.close()
    b.close()
print('SIGN-OUT CHECKS PASSED')
