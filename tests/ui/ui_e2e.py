"""Drives the rebuilt web UI through a full investigation and screenshots each page."""
import sys
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
OUT = '/out'
IMAGE = '/img/dfip-test-disk.dd'
problems, step = [], {'v': 'start'}


def shot(page, name):
    page.screenshot(path=f'{OUT}/{name}.png', full_page=True)


with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={'width': 1440, 'height': 900}, accept_downloads=True)
    page = ctx.new_page()
    page.on('pageerror', lambda e: problems.append(f'[{step["v"]}] JS error: {e}'))
    page.on('console', lambda m: m.type == 'error' and problems.append(f'[{step["v"]}] console: {m.text[:200]}'))
    page.on('response', lambda r: '/api/' in r.url and r.status >= 400 and problems.append(f'[{step["v"]}] HTTP {r.status} {r.url.split("/api")[1][:100]}'))
    expect.set_options(timeout=20000)

    step['v'] = 'landing'
    page.goto(BASE + '/')
    expect(page.get_by_role('heading', level=1)).to_have_text('Turn disk images into evidence you can defend')
    expect(page.locator('.lp-hero').get_by_role('link', name='Download for Windows')).to_be_visible()
    shot(page, '01-landing')

    step['v'] = 'login'
    page.locator('.lp-nav-actions').get_by_role('link', name='Sign in').click()
    expect(page.get_by_text('Demo accounts (demo mode only)')).to_be_visible()
    shot(page, '02-login')
    page.get_by_role('button', name='Investigator Full case work').click()
    page.get_by_role('button', name='Sign in').click()
    expect(page.get_by_text('Investigation functions')).to_be_visible()

    step['v'] = 'new case'
    page.get_by_role('button', name='New case').click()
    page.get_by_placeholder('e.g. Suspected payroll data exfiltration').fill('UI rebuild end-to-end test')
    page.get_by_role('button', name='Create case').click()
    expect(page.get_by_role('heading', name='UI rebuild end-to-end test')).to_be_visible()
    shot(page, '03-home-empty')

    step['v'] = 'upload'
    page.get_by_role('link', name='Evidence').first.click()
    page.locator('input[type=file]').set_input_files(IMAGE)
    page.get_by_role('button', name='Upload and seal').click()
    expect(page.get_by_text('registered · dfip-test-disk.dd')).to_be_visible(timeout=60000)
    shot(page, '04-evidence-uploaded')
    page.get_by_role('button', name='Run analysis').click()

    step['v'] = 'analysis'
    page.get_by_role('link', name='Case desktop').click()
    expect(page.get_by_text('Analyzed: 27 files (1 deleted)')).to_be_visible(timeout=180000)
    shot(page, '05-home-analyzed')

    step['v'] = 'evidence detail'
    page.get_by_role('link', name='Open', exact=True).first.click()
    expect(page.get_by_text('Partition table (mmls)')).to_be_visible()
    expect(page.get_by_text('Win95 FAT32 (0x0c)')).to_be_visible()
    shot(page, '06-evidence-detail')

    step['v'] = 'deleted files'
    page.get_by_role('link', name='Deleted files').first.click()
    expect(page.get_by_text('/Users/alice/Documents/payroll-export.csv')).to_be_visible()
    page.get_by_role('button', name='Recover').first.click()
    expect(page.get_by_role('button', name='Download').first).to_be_visible()
    with page.expect_download() as d:
        page.get_by_role('button', name='Download').first.click()
    d.value.save_as(f'{OUT}/recovered.csv')
    page.get_by_role('tab', name='Recovered files').click()
    expect(page.get_by_text('WAS DELETED')).to_be_visible()
    page.get_by_role('button', name='Metadata').first.click()
    expect(page.get_by_text('Extracted with ExifTool')).to_be_visible()
    page.keyboard.press('Escape')
    shot(page, '07-files')

    step['v'] = 'timeline'
    page.get_by_role('link', name='Timeline').first.click()
    expect(page.get_by_text('66 events')).to_be_visible()
    shot(page, '08-timeline')
    page.locator('svg.chart rect.bar').last.click()
    expect(page.get_by_role('button', name='Full range')).to_be_visible()
    shot(page, '09-timeline-zoomed')

    step['v'] = 'browser'
    page.get_by_role('link', name='Browser history').first.click()
    expect(page.get_by_text('Anonymous File Upload')).to_be_visible()
    shot(page, '10-browser')
    page.get_by_role('tab', name='Downloads').click()
    expect(page.get_by_text('SecureDelete.exe')).to_be_visible()

    step['v'] = 'usb'
    page.get_by_role('link', name='USB devices').first.click()
    expect(page.get_by_text('HP v100w USB Device')).to_be_visible()
    shot(page, '11-usb')

    step['v'] = 'indicators'
    page.get_by_role('link', name='Indicators').first.click()
    expect(page.get_by_text('Suspicious_PowerShell_EncodedCommand')).to_be_visible()
    shot(page, '12-indicators')

    step['v'] = 'search'
    page.get_by_role('link', name='Keyword search').first.click()
    page.get_by_label('Keyword').fill('payroll')
    page.get_by_role('button', name='Search').click()
    expect(page.get_by_text('matches for “payroll”')).to_be_visible()
    shot(page, '13-search')

    step['v'] = 'findings'
    page.get_by_role('link', name='Findings').first.click()
    page.get_by_role('button', name='Record finding').first.click()
    page.get_by_placeholder('e.g. Payroll export deleted after USB activity').fill('Payroll export <deleted> & exfiltrated?')
    page.locator('textarea').fill('payroll-export.csv was deleted at 09:41 UTC; a SanDisk drive was first installed later that day.')
    page.locator('label.check input').first.check()
    page.get_by_role('button', name='Save finding').click()
    expect(page.get_by_role('heading', name='Payroll export <deleted> & exfiltrated?')).to_be_visible()

    step['v'] = 'reports'
    page.get_by_role('link', name='Reports').first.click()
    page.get_by_role('button', name='Generate report').click()
    expect(page.get_by_text('v1')).to_be_visible(timeout=60000)
    with page.expect_download() as d:
        page.get_by_role('button', name='PDF').first.click()
    d.value.save_as(f'{OUT}/report.pdf')
    shot(page, '14-reports')

    step['v'] = 'custody'
    page.get_by_role('link', name='Chain of custody').first.click()
    expect(page.get_by_text('File recovered', exact=True).first).to_be_visible()
    expect(page.get_by_text('Audit hash chain verified')).to_be_visible()
    shot(page, '15-custody')

    step['v'] = 'carving'
    page.get_by_role('link', name='File carving').first.click()
    expect(page.get_by_role('button', name='Start carving')).to_be_visible()

    step['v'] = 'audit+system'
    page.get_by_role('link', name='Audit log').click()
    page.get_by_role('button', name='Verify hash chain').click()
    expect(page.get_by_text('Chain intact')).to_be_visible()
    page.get_by_role('link', name='System & tools').click()
    expect(page.get_by_text('Partitions tables').or_(page.get_by_text('Partition tables'))).to_be_visible()
    shot(page, '16-system')

    step['v'] = 'home-final'
    page.get_by_role('link', name='Case desktop').click()
    expect(page.get_by_text('Investigation functions')).to_be_visible()
    shot(page, '17-home-final')

    step['v'] = 'logout'
    page.get_by_title('Sign out').click()
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
    b.close()

print('ALL STEPS PASSED' if not problems else 'Problems:\n' + '\n'.join(problems))
