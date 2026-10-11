"""Drives the rebuilt web UI through a full investigation and screenshots each page."""
import re
import sys
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
OUT = '/out'
IMAGE = '/img/dfip-test-disk.dd'
problems, step = [], {'v': 'start'}


def shot(page, name):
    page.screenshot(path=f'{OUT}/{name}.png', full_page=True)


def api_get(page, path):
    """GET an API path as the signed-in user (expected UI values come from the API; the system tests check the
    API itself against ground truth)."""
    return page.evaluate("""async (p) => (await fetch('/api' + p, {
        headers: { Authorization: 'Bearer ' + sessionStorage.getItem('dfip_token') } })).json()""", path)


with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={'width': 1440, 'height': 900}, accept_downloads=True)
    page = ctx.new_page()
    page.on('pageerror', lambda e: problems.append(f'[{step["v"]}] JS error: {e}'))
    page.on('console', lambda m: m.type == 'error' and not (step['v'] == 'duplicate upload' and '409' in m.text)
            and problems.append(f'[{step["v"]}] console: {m.text[:200]}'))
    # The duplicate upload is expected to be refused with 409; every other API error is a problem.
    page.on('response', lambda r: '/api/' in r.url and r.status >= 400 and not (r.status == 409 and step['v'] == 'duplicate upload')
            and problems.append(f'[{step["v"]}] HTTP {r.status} {r.url.split("/api")[1][:100]}'))
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
    expect(page.get_by_text('Analyzed:')).to_be_visible(timeout=180000)
    href = page.get_by_role('link', name='Open', exact=True).first.get_attribute('href')  # this case's evidence
    counts = api_get(page, f"/evidence/{href.rstrip('/').rsplit('/', 1)[-1]}")['analysis_summary']
    expect(page.get_by_text(f"Analyzed: {counts['files']} files ({counts['deleted_files']} deleted)")).to_be_visible()
    shot(page, '05-home-analyzed')

    step['v'] = 'evidence detail'
    page.get_by_role('link', name='Open', exact=True).first.click()
    expect(page.get_by_text('Partition table (mmls)')).to_be_visible()
    expect(page.get_by_text('Win95 FAT32 (0x0c)')).to_be_visible()
    shot(page, '06-evidence-detail')

    step['v'] = 'analysis modules'
    modules_card = page.locator('.card', has=page.get_by_role('heading', name='Analysis modules'))
    expect(modules_card.get_by_role('row')).to_have_count(4)  # header + 3 modules
    eid = page.url.rstrip('/').rsplit('/', 1)[-1]
    before = api_get(page, f'/evidence/{eid}')['modules']['yara']['run_id']
    page.get_by_role('button', name='Analysis options').click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('Quick triage')).to_be_visible()
    dialog.get_by_text('Choose modules').click()
    dialog.get_by_role('checkbox', name='YARA scan').check()
    shot(page, '06b-analysis-options')
    dialog.get_by_role('button', name='Start analysis').click()
    expect(dialog).to_have_count(0)
    for _ in range(120):  # wait for a new YARA run (not the earlier one) to finish
        yara = api_get(page, f'/evidence/{eid}')['modules']['yara']
        if yara['run_id'] != before and yara['status'] == 'COMPLETED':
            break
        page.wait_for_timeout(1000)
    else:
        problems.append('[analysis modules] the YARA re-run did not complete')
    expect(page.get_by_role('button', name='Re-run analysis')).to_be_enabled(timeout=30000)
    yara_row = modules_card.get_by_role('row').filter(has_text='YARA scan')
    expect(yara_row.get_by_text('COMPLETED', exact=True)).to_be_visible()
    n = counts['yara_matches']
    expect(yara_row.get_by_text(f"{n} YARA match{'' if n == 1 else 'es'}")).to_be_visible()
    shot(page, '06c-analysis-modules')

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

    step['v'] = 'file viewer'
    page.get_by_role('tab', name='Deleted entries').click()
    page.get_by_role('button', name='View').first.click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('employee,iban,salary').first).to_be_visible()
    dialog.get_by_role('tab', name='Hex').click()
    expect(dialog.get_by_text('65 6d 70 6c')).to_be_visible()
    dialog.get_by_label('Go to offset').fill('0x100')
    dialog.get_by_role('button', name='Go to offset').click()
    expect(dialog.get_by_text('Bytes 256–2,191 of 2,191')).to_be_visible()
    expect(dialog.locator('pre.hex-dump')).to_contain_text('00000100  30 35 33 32')
    shot(page, '07b-hex-viewer')
    page.keyboard.press('Escape')
    page.get_by_role('tab', name='All files').click()
    for name, media in (('whiteboard', 'img'), ('offer-letter', 'iframe.viewer-pdf')):
        page.get_by_placeholder('Filter by path, e.g. payroll or .docx').fill(name)
        page.get_by_role('button', name='Filter').click()
        page.get_by_role('button', name='View').first.click()
        expect(page.get_by_role('dialog').locator(media)).to_have_count(1)
        shot(page, f'07c-preview-{name}')
        page.keyboard.press('Escape')

    step['v'] = 'timeline'
    page.get_by_role('link', name='Timeline').first.click()
    expect(page.get_by_text(f"{counts['timeline_events']} events")).to_be_visible()
    shot(page, '08-timeline')
    page.locator('svg.chart rect.bar').last.click()
    expect(page.get_by_role('button', name='Full range')).to_be_visible()
    shot(page, '09-timeline-zoomed')

    step['v'] = 'tag'
    page.get_by_role('button', name='Tag this item').first.click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_label('Notable').check()
    dialog.get_by_label('Note').fill('Activity right before the upload')
    dialog.get_by_role('button', name='Add tag').click()
    expect(page.get_by_text('Tagged as Notable')).to_be_visible()
    expect(page.get_by_role('button', name='Tagged Notable: Activity right before the upload')).to_be_visible()

    # Every state the table passes through after a tab switch must show that tab's rows (or none), never the
    # previous tab's rows under the new columns; a DOM observer records each state, however briefly shown.
    def mismatches(tab, column, header, expected):
        page.evaluate("""(c) => { window.__states = []; window.__obs?.disconnect(); (window.__obs = new MutationObserver(() => window.__states.push([
            document.querySelectorAll('main table thead th')[c]?.innerText || '', document.querySelector('main table tbody tr')?.innerText || ''])))
            .observe(document.querySelector('main'), { subtree: true, childList: true, characterData: true }); }""", column)
        page.get_by_role('tab', name=tab).click()
        expect(page.locator('main table tbody tr', has_text=expected).first).to_be_visible()
        return [x for x in page.evaluate('() => window.__states') if x[0].lower() == header and x[1] and expected not in x[1]]

    step['v'] = 'browser'
    page.get_by_role('link', name='Browser history').first.click()
    expect(page.get_by_text('Anonymous File Upload')).to_be_visible()
    shot(page, '10-browser')
    if mismatches('Downloads', 1, 'started', 'Downloads'):
        problems.append('[browser] the history rows were shown under the Downloads columns')
    expect(page.get_by_text('SecureDelete.exe')).to_be_visible()

    step['v'] = 'usb'
    page.get_by_role('link', name='USB devices').first.click()
    expect(page.get_by_text('HP v100w USB Device')).to_be_visible()
    shot(page, '11-usb')

    step['v'] = 'windows activity'
    page.get_by_role('link', name='Windows activity').first.click()
    expect(page.get_by_text('SECUREDELETE.EXE', exact=True)).to_be_visible()
    shot(page, '11b-programs-run')
    if mismatches('Recently opened files', 0, 'last opened', 'E:\\payroll-export.csv'):
        problems.append('[windows activity] the Programs run rows were shown under the Recently opened files columns')
    expect(page.get_by_text('Removable drive')).to_be_visible()
    if mismatches('Recycle Bin', 0, 'deleted', 'C:\\Users\\alice\\Documents\\payroll-export.csv'):
        problems.append('[windows activity] the Recently opened files rows were shown under the Recycle Bin columns')
    shot(page, '11c-recycle-bin')

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

    step['v'] = 'dashboard'
    page.get_by_role('link', name='Activity dashboard').first.click()
    expect(page.locator('rect.heat-cell')).to_have_count(168)
    expect(page.get_by_text('Top websites')).to_be_visible()
    expect(page.get_by_text('user activity events')).to_be_visible()
    shot(page, '17a-dashboard')
    page.get_by_label('Include filesystem times (MACB)').check()
    expect(page.get_by_text('events, including filesystem times')).to_be_visible()

    step['v'] = 'tagged items'
    page.get_by_role('link', name='Tagged items').first.click()
    expect(page.get_by_text('Activity right before the upload')).to_be_visible()
    shot(page, '17b-tagged-items')

    step['v'] = 'legal hold'
    page.get_by_role('link', name='Case desktop').click()
    page.get_by_role('button', name='Place legal hold').click()
    dialog = page.get_by_role('dialog')
    dialog.get_by_label('Reason for the hold').fill('Litigation hold for the UI test')
    dialog.get_by_role('button', name='Place hold').click()
    expect(page.locator('header.topbar').get_by_text('Legal hold', exact=True)).to_be_visible()
    page.get_by_role('link', name='Evidence').first.click()
    expect(page.get_by_role('button', name='Delete', exact=True)).to_be_disabled()
    shot(page, '17c-legal-hold')
    page.get_by_role('link', name='Case desktop').click()
    page.get_by_role('button', name='Release legal hold').click()
    page.get_by_role('dialog').get_by_label('Reason for releasing the hold').fill('Released for the UI test')
    page.get_by_role('dialog').get_by_role('button', name='Release hold').click()
    expect(page.get_by_role('button', name='Place legal hold')).to_be_visible()
    expect(page.locator('header.topbar').get_by_text('Legal hold', exact=True)).to_have_count(0)

    step['v'] = 'duplicate upload'
    page.get_by_role('link', name='Evidence').first.click()
    page.locator('input[type=file]').set_input_files(IMAGE)
    expect(page.get_by_text('same name and size as')).to_be_visible()
    page.get_by_role('button', name='Upload and seal').click()
    expect(page.get_by_text('is already registered in')).to_be_visible(timeout=60000)
    expect(page.locator('table tbody tr')).to_have_count(1)
    shot(page, '18-duplicate-refused')

    step['v'] = 'delete evidence'
    page.get_by_role('link', name='Details').first.click()
    page.get_by_role('button', name='Delete', exact=True).click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_text('This permanently deletes')).to_be_visible()
    confirm = dialog.get_by_role('button', name=re.compile(r'^Delete EVID-'))
    expect(confirm).to_be_disabled()
    dialog.get_by_label('Reason for deletion').fill('End-to-end test clean-up')
    shot(page, '19-delete-dialog')
    confirm.click()
    expect(page.get_by_text('No evidence in this case')).to_be_visible()
    page.get_by_role('link', name='Chain of custody').first.click()
    expect(page.get_by_text('Evidence deleted', exact=True)).to_be_visible()
    expect(page.get_by_text('Reason: End-to-end test clean-up')).to_be_visible()
    shot(page, '20-custody-after-delete')

    step['v'] = 'home-final'
    page.get_by_role('link', name='Case desktop').click()
    expect(page.get_by_text('Investigation functions')).to_be_visible()
    shot(page, '17-home-final')

    step['v'] = 'logout'
    page.get_by_title('Sign out').click()
    expect(page.get_by_role('heading', name='Sign in')).to_be_visible()
    b.close()

print('ALL STEPS PASSED' if not problems else 'Problems:\n' + '\n'.join(problems))
