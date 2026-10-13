"""UI checks not covered by the other suites: keyboard sign-in, UTC/local display, case editing and
switching, top-bar search, user administration, password change, bad sessions and narrow windows.
Runs against a DFIP stack at http://host.docker.internal; it first creates and analyses its own case
from the test image mounted at /img."""
import hashlib, json, re, sys, time, urllib.error, urllib.request, uuid
from playwright.sync_api import sync_playwright, expect

BASE = 'http://host.docker.internal'
OUT = '/out'
PW = 'DemoPassword!2026'
CASE_NAME = f'UI extra — laptop image {uuid.uuid4().hex[:4]}'
results = []


def api(method, path, token=None, body=None, raw=None, ctype='application/json'):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + '/api' + path, data=data, method=method)
    if data is not None:
        req.add_header('Content-Type', ctype)
    if token:
        req.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


def analysed_case(image='/img/dfip-test-disk.dd', name=CASE_NAME):
    """A case holding an analysed test image (by default the laptop: deleted payroll export at 09:41:02 UTC, browser and
    USB data)."""
    token = api('POST', '/auth/login', body={'email': 'investigator@dfip.local', 'password': PW})['access_token']
    case_id = api('POST', '/cases', token, {'name': name, 'priority': 'HIGH'})['case_id']
    b = uuid.uuid4().hex
    body = (f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{image.rsplit("/", 1)[-1]}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() \
        + open(image, 'rb').read() + f'\r\n--{b}--\r\n'.encode()
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


SHOWCASE = analysed_case()
NTFS_CASE = analysed_case('/img/dfip-ntfs-disk.dd', f'UI extra — office desktop (NTFS) {uuid.uuid4().hex[:4]}')
SAMPLES = '/img/samples/dfvfs'


def volumes_case():
    """A case with a BitLocker To Go stick (quick analysis) and an NTFS volume with two shadow copies (dfVFS samples)."""
    token = api('POST', '/auth/login', body={'email': 'investigator@dfip.local', 'password': PW})['access_token']
    case_id = api('POST', '/cases', token, {'name': f'UI extra — volumes {uuid.uuid4().hex[:4]}', 'priority': 'LOW'})['case_id']
    ids = []
    for name, body in (('bdetogo.raw', {'profile': 'quick'}), ('vss.raw', {'modules': ['shadow_copies']})):
        b = uuid.uuid4().hex
        data = (f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'
                f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() \
            + open(f'{SAMPLES}/{name}', 'rb').read() + f'\r\n--{b}--\r\n'.encode()
        eid = api('POST', '/evidence/upload', token, raw=data, ctype=f'multipart/form-data; boundary={b}')['evidence_id']
        job = api('POST', f'/jobs/analysis/{eid}', token, body)['job_id']
        for _ in range(300):
            if api('GET', f'/jobs/{job}', token)['status'] in ('COMPLETED', 'FAILED'):
                break
            time.sleep(1)
        ids.append(eid)
    return case_id, ids


VOL_CASE, (BDE_EV, VSS_EV) = volumes_case()


def unix_case():
    """The Linux server's disk, the Mac collection and the laptop's KAPE collection, analysed (quick)."""
    token = api('POST', '/auth/login', body={'email': 'investigator@dfip.local', 'password': PW})['access_token']
    case_id = api('POST', '/cases', token, {'name': f'UI extra — Linux, Mac, collections {uuid.uuid4().hex[:4]}', 'priority': 'LOW'})['case_id']
    ids = []
    for path in ('/img/dfip-linux-disk.dd', '/img/dfip-test-macos.tar', '/img/dfip-test-kape.zip'):
        b = uuid.uuid4().hex
        data = (f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'
                f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{path.rsplit("/", 1)[-1]}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() \
            + open(path, 'rb').read() + f'\r\n--{b}--\r\n'.encode()
        eid = api('POST', '/evidence/upload', token, raw=data, ctype=f'multipart/form-data; boundary={b}')['evidence_id']
        job = api('POST', f'/jobs/analysis/{eid}', token, {'profile': 'quick'})['job_id']
        for _ in range(300):
            if api('GET', f'/jobs/{job}', token)['status'] in ('COMPLETED', 'FAILED'):
                break
            time.sleep(1)
        ids.append(eid)
    return case_id, ids


UNIX_CASE, (LINUX_EV, MAC_EV, KAPE_EV) = unix_case()


def phone_net_case():
    """The laptop's network capture and alice's Android and iPhone extractions, analysed (standard)."""
    token = api('POST', '/auth/login', body={'email': 'investigator@dfip.local', 'password': PW})['access_token']
    case_id = api('POST', '/cases', token, {'name': f'UI extra — network and phones {uuid.uuid4().hex[:4]}', 'priority': 'LOW'})['case_id']
    for path in ('/img/dfip-test-capture.pcap', '/img/dfip-test-android.zip', '/img/dfip-test-iphone.zip'):
        b = uuid.uuid4().hex
        data = (f'--{b}\r\nContent-Disposition: form-data; name="case_id"\r\n\r\n{case_id}\r\n'
                f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{path.rsplit("/", 1)[-1]}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() \
            + open(path, 'rb').read() + f'\r\n--{b}--\r\n'.encode()
        eid = api('POST', '/evidence/upload', token, raw=data, ctype=f'multipart/form-data; boundary={b}')['evidence_id']
        job = api('POST', f'/jobs/analysis/{eid}', token, {'profile': 'standard'})['job_id']
        for _ in range(300):
            if api('GET', f'/jobs/{job}', token)['status'] in ('COMPLETED', 'FAILED'):
                break
            time.sleep(1)
    return case_id


NET_PHONE_CASE = phone_net_case()


REVIEW_TITLE = f'UI review finding {uuid.uuid4().hex[:4]}'


def _png() -> bytes:
    import struct, zlib
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rows = b''.join(b'\x00' + bytes([200, 60, 40]) * 8 for _ in range(6))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 8, 6, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')


def check(name, cond, detail=''):
    results.append(bool(cond))
    print(('  PASS ' if cond else '  FAIL ') + name + ('' if cond else f'  ::  {detail}'), flush=True)


def sign_in(page, email, password=PW, enter=False):
    page.goto(BASE + '/login')
    page.get_by_label('Email').fill(email)
    page.get_by_label('Password', exact=True).fill(password)
    if enter:
        page.get_by_label('Password', exact=True).press('Enter')
    else:
        page.locator('form').get_by_role('button', name='Sign in').click()


with sync_playwright() as p:
    b = p.chromium.launch()
    expect.set_options(timeout=20000)
    errors = []

    # ---- investigator, browser in India (UTC+05:30) so local time differs from UTC
    ctx = b.new_context(viewport={'width': 1440, 'height': 900}, timezone_id='Asia/Kolkata')
    page = ctx.new_page()
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto(BASE + '/login')
    page.evaluate("c => { localStorage.setItem('dfip_active_case', c); localStorage.setItem('dfip_time_mode', 'utc'); }", SHOWCASE)
    print('== keyboard and time display')
    sign_in(page, 'investigator@dfip.local', enter=True)
    expect(page.get_by_text('Investigation functions')).to_be_visible()
    check('sign-in works from the keyboard (Enter)', page.url.endswith('/app'))
    page.get_by_role('link', name='Timeline').first.click()
    search = page.get_by_placeholder('Search event descriptions (Enter)')
    search.fill('payroll-export.csv')
    search.press('Enter')
    expect(page.locator('tbody tr', has_text='09:41:02 UTC').first).to_be_visible()
    rows = page.locator('tbody tr')
    idx = next(i for i in range(rows.count()) if '2026-09-01 09:41:02 UTC' in rows.nth(i).inner_text())
    row = rows.nth(idx)  # by position: its text changes with the time mode
    check('timeline shows the payroll export event at 09:41:02 UTC', 'payroll-export.csv' in row.inner_text(), row.inner_text()[:120])
    page.get_by_role('group', name='Time display').get_by_role('button', name='Local').click()
    expect(row).to_contain_text('2026-09-01 15:11:02 local')
    check('switching to local time shows 15:11:02 local (UTC+05:30)', 'payroll-export.csv' in row.inner_text(), row.inner_text()[:120])
    page.get_by_role('group', name='Time display').get_by_role('button', name='UTC').click()
    expect(row).to_contain_text('09:41:02 UTC')

    print('== top-bar search')
    page.get_by_label('Search this case').fill('payroll')
    page.get_by_label('Search this case').press('Enter')
    expect(page).to_have_url(BASE + '/app/search?q=payroll')
    expect(page.get_by_text('/Users/alice/Documents/payroll-export.csv').first).to_be_visible()
    expect(page.get_by_text('Payroll Portal').first).to_be_visible()
    check('top-bar search opens results for the active case (file and browser hits)', True)

    print('== case editing and switching')
    page.get_by_role('link', name='Cases').first.click()
    page.get_by_role('button', name='New case').first.click()
    name = f'UI extra test {uuid.uuid4().hex[:5]}'
    page.get_by_label('Case title').fill(name)
    page.get_by_role('dialog').get_by_role('button', name='Create case').click()
    expect(page.get_by_text('Investigation functions')).to_be_visible()
    check('a new case becomes the active case', name in page.get_by_label('Active case').locator('option:checked').inner_text())
    page.get_by_role('link', name='Cases').first.click()
    page.locator('tr', has_text=name).get_by_role('button', name='Edit').click()
    page.get_by_label('Case title').fill(name + ' (renamed)')
    page.get_by_role('dialog').get_by_label('Status').select_option('ON_HOLD')
    page.get_by_role('dialog').get_by_role('button', name='Save changes').click()
    expect(page.locator('tr', has_text=name + ' (renamed)')).to_contain_text('ON')
    check('case can be renamed and put on hold', True)
    page.get_by_label('Active case').select_option(SHOWCASE)
    page.get_by_role('link', name='Case desktop').first.click()
    expect(page.get_by_role('heading', name=CASE_NAME)).to_be_visible()
    check('case switcher changes the active case', True)

    print('== file system journal (NTFS)')
    page.get_by_label('Active case').select_option(NTFS_CASE)
    page.get_by_role('link', name='File system journal').first.click()
    tab_rows = lambda **kw: page.locator('.card:has([role="tablist"]) table tbody tr', **kw)  # not the volumes table below
    row = tab_rows(has_text='budget-2025.txt')
    expect(row.get_by_text('STRONG', exact=True)).to_be_visible()
    expect(row).to_contain_text('2024-03-02')
    check('timestomping: budget-2025.txt is flagged strong, with its $SI and $FN times', tab_rows().count() == 1)
    page.screenshot(path=f'{OUT}/x4-ntfs-timestomp.png')
    page.get_by_role('tab', name=re.compile(r'^Alternate data streams')).click()
    hidden = tab_rows(has_text='notes.txt:hidden.txt')
    expect(hidden.get_by_text('HIDDEN DATA?', exact=True)).to_be_visible()
    expect(tab_rows(has_text='SecureDelete.exe:Zone.Identifier')).to_contain_text('tools.example.org/securedelete/SecureDelete.exe')
    hidden.get_by_role('button', name='View').click()
    expect(page.get_by_role('dialog')).to_contain_text('Copy the payroll to the SanDisk, then wipe it.')
    page.keyboard.press('Escape')
    check('streams: the hidden note is flagged and opens in the viewer; the download shows where it came from', True)
    page.get_by_role('tab', name=re.compile(r'^USN journal')).click()
    expect(tab_rows()).to_have_count(20)
    page.get_by_label('Change', exact=True).select_option('FILE_DELETE')
    expect(tab_rows()).to_have_count(1)
    expect(tab_rows().first).to_contain_text('/Users/alice/Documents/AAAAAAAA.AAA')
    check('USN journal: all 20 records, and the deletion of the wiped file found by its reason', True)
    page.screenshot(path=f'{OUT}/x5-ntfs-usn.png')

    print('== email, chat and cloud, browser depth')
    page.get_by_label('Active case').select_option(SHOWCASE)
    page.get_by_role('link', name='Email').first.click()
    expect(page.locator('tr', has_text='imap.corp.example/Sent').first).to_be_visible()
    expect(page.locator('tr', has_text='Re: the list').get_by_text('DELETED', exact=True)).to_be_visible()
    check('email: the Thunderbird folders, and the reply alice deleted marked deleted', True)
    page.evaluate("window.__pwned = false; window.addEventListener('message', (e) => { if (e.data === 'pwned') window.__pwned = true; })")
    page.get_by_role('button', name='Payroll export ready for review').click()
    page.get_by_role('dialog').get_by_role('tab', name='HTML (safe view)').click()
    frame_el = page.locator('iframe.email-html')
    expect(frame_el).to_be_visible()
    expect(page.frame_locator('iframe.email-html').get_by_text('The September payroll export is ready on the portal.')).to_be_visible()
    expect(page.get_by_role('dialog')).to_contain_text('1 remote picture or style not loaded')
    frame = next(f for f in page.frames if f.url == 'about:srcdoc')
    inside = frame.evaluate('''() => ({scripts: document.querySelectorAll('script').length, links: document.querySelectorAll('a[href]').length,
        handlers: document.querySelectorAll('[onclick]').length, title: document.title,
        images: [...document.images].map((i) => [i.getAttribute('src') ? i.getAttribute('src').slice(0, 15) : null, i.naturalWidth])})''')
    check('HTML email: shown in a sandbox with no scripts, handlers or live links; only the inline logo loads, the tracker does not',
          frame_el.get_attribute('sandbox') == '' and inside['scripts'] == 0 and inside['links'] == 0 and inside['handlers'] == 0
          and inside['title'] != 'pwned' and inside['images'] == [['data:image/png;', 48], [None, 0]]
          and page.evaluate('window.__pwned') is False, inside)
    page.screenshot(path=f'{OUT}/x6-email-html.png')
    page.keyboard.press('Escape')
    page.get_by_role('button', name='backup', exact=True).click()
    att = page.get_by_role('dialog').locator('tr', has_text='payroll-export.csv')
    att.get_by_role('button', name='View').click()
    expect(page.get_by_role('dialog').last).to_contain_text('employee,iban,salary')
    check('the emailed attachment opens in the file viewer', True)
    page.keyboard.press('Escape')
    if page.get_by_role('dialog').count():
        page.keyboard.press('Escape')
    page.get_by_role('link', name='Chat and cloud').first.click()
    expect(page.locator('tr', has_text='Offer letter attached')).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^Chat apps found')).click()
    expect(page.locator('tr', has_text='WhatsApp').get_by_text('NOT READ', exact=True)).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^Cloud files')).click()
    pay = page.locator('tr', has_text='/Backup/payroll-export.csv')
    expect(pay).to_contain_text('Same content:')
    expect(pay).to_contain_text('/Users/alice/Pictures/holiday.jpg')
    check('chat and cloud: the Skype chat, WhatsApp found but not read, the OneDrive copy of the payroll linked to the copies on the disk', True)
    page.screenshot(path=f'{OUT}/x7-chat-cloud.png')
    page.get_by_role('link', name='Browser history').first.click()
    page.get_by_role('tab', name=re.compile(r'^Recovered history')).click()
    rows = page.locator('table tbody tr')
    expect(rows).to_have_count(4)
    expect(page.locator('tr', has_text='filetransfer.example.net/d/7Hq2xK')).to_contain_text('free space')
    expect(page.locator('tr', has_text='securedelete wipe free space')).to_contain_text('WAL frame')
    page.screenshot(path=f'{OUT}/x8-browser-recovered.png')
    page.get_by_role('tab', name=re.compile(r'^Searches')).click()
    expect(page.get_by_text('RECOVERED', exact=True)).to_have_count(3)
    page.get_by_role('tab', name=re.compile(r'^Saved logins')).click()
    expect(page.locator('tr', has_text='filetransfer.example.net/login').get_by_text('SAVED (ENCRYPTED)')).to_be_visible()
    check('browser: the 4 deleted visits with where each was found, 3 recovered searches, saved logins without passwords', True)

    print('== pictures and videos')
    page.get_by_role('link', name='Pictures and videos').first.click()
    expect(page.locator('svg.world-map circle.world-point')).to_have_count(2)
    photo = page.get_by_role('button', name='Open IMG_20260901_101032.jpg')
    expect(photo.get_by_text('GPS', exact=True)).to_be_visible()
    expect(photo.locator('img')).to_have_js_property('complete', True)
    loaded = photo.locator('img').evaluate('(i) => i.naturalWidth')
    check('gallery: the photo with its GPS badge and its thumbnail; the map shows the photo and the video', loaded == 320, loaded)
    page.screenshot(path=f'{OUT}/x9-media.png', full_page=True)
    photo.click()
    d = page.get_by_role('dialog')
    expect(d).to_contain_text('offset -04:00 in the picture')
    expect(d).to_contain_text('Google Pixel 8')
    osm = d.get_by_role('link', name=re.compile('Open in OpenStreetMap'))
    check('details: when it was taken and on what basis, the camera, and OpenStreetMap only as a link the user chooses',
          osm.get_attribute('href') == 'https://www.openstreetmap.org/?mlat=42.3601&mlon=-71.0589#map=16/42.3601/-71.0589'
          and osm.get_attribute('target') == '_blank' and 'noopener' in (osm.get_attribute('rel') or ''), osm.get_attribute('href'))
    page.keyboard.press('Escape')
    page.get_by_role('tab', name=re.compile(r'^Videos')).click()
    page.get_by_role('button', name='Open VID_20260901_101800.mp4').click()
    frames = page.get_by_role('dialog').locator('.keyframes img')
    expect(frames).to_have_count(3)
    expect(page.get_by_role('dialog')).to_contain_text('Keyframes (scene change)')
    check('a video opens with its three keyframes', True)
    page.screenshot(path=f'{OUT}/x10-video.png')
    page.keyboard.press('Escape')
    requests_out = []
    page.on('request', lambda r: requests_out.append(r.url) if 'openstreetmap' in r.url or 'tile' in r.url else None)
    page.get_by_role('tab', name=re.compile(r'^With a location')).click()
    expect(page.locator('.media-card')).to_have_count(2)
    check('the map and gallery load nothing from map servers', not requests_out, requests_out)

    print('== programs')
    page.get_by_role('link', name=re.compile(r'^Indicators')).first.click()
    card = page.locator('.card', has=page.get_by_role('heading', name='Programs that stand out'))
    row = card.locator('tr', has_text='Temp/svchost.exe')
    expect(row.get_by_text('Packed (UPX)')).to_be_visible()
    expect(row.get_by_text('Built as SecureDelete.exe, named svchost.exe')).to_be_visible()
    expect(card.locator('tr', has_text='Downloads/SecureDelete.exe').get_by_text('SIGNED, UNTRUSTED')).to_be_visible()
    check('programs: the packed svchost.exe and SecureDelete.exe listed with why they stand out and their signatures', True)
    page.screenshot(path=f'{OUT}/x11-programs.png', full_page=True)
    card.get_by_role('button', name='/Users/alice/Downloads/SecureDelete.exe').click()
    d = page.get_by_role('dialog')
    expect(d).to_contain_text('SecureDelete Project')
    expect(d.locator('tr', has_text='delete file')).to_be_visible()
    d.get_by_text(re.compile(r'^Imports \(')).click()
    flagged = d.locator('.import-flag').all_inner_texts()
    check('details: version information, the signer, capa capabilities, the wiping imports highlighted',
          {'DeleteFileW', 'WriteFile', 'MoveFileExW'} <= {x.strip(', ') for x in flagged}, flagged)
    page.screenshot(path=f'{OUT}/x12-program-detail.png')
    page.keyboard.press('Escape')

    print('== disk images, encrypted volumes and shadow copies')
    page.get_by_label('Active case').select_option(VOL_CASE)
    page.get_by_role('link', name=re.compile(r'^Evidence')).first.click()
    page.get_by_label('Disk image files').set_input_files([f'{SAMPLES}/ext2.splitraw.001', f'{SAMPLES}/ext2.splitraw.000'])
    expect(page.get_by_text('2 files of one image')).to_be_visible()
    page.get_by_role('button', name='Upload and seal').click()
    expect(page.get_by_text(re.compile(r'EVID-\d+ registered · ext2\.splitraw\.000'))).to_be_visible(timeout=60000)
    check('the two parts of a split image upload together as one evidence item', True)
    page.goto(f'{BASE}/app/evidence/{BDE_EV}')
    vols = page.locator('.card', has=page.get_by_role('heading', name='Volumes'))
    expect(vols.get_by_text('BitLocker, LOCKED')).to_be_visible()
    vols.get_by_role('button', name='Unlock').click()
    d = page.get_by_role('dialog')
    d.get_by_label('Password', exact=True).fill('not-the-password')
    d.get_by_role('button', name='Unlock and decrypt').click()
    expect(d.get_by_text('does not unlock')).to_be_visible()
    d.get_by_label('Password', exact=True).fill('bde-TEST')
    d.get_by_role('button', name='Unlock and decrypt').click()
    expect(vols.get_by_text('BitLocker, UNLOCKED')).to_be_visible(timeout=90000)
    derived = vols.get_by_role('link', name=re.compile(r'^EVID-'))
    check('a wrong password is refused in the dialog; the right one decrypts the volume into new evidence, linked from the volume',
          derived.count() == 1, derived.count())
    page.screenshot(path=f'{OUT}/x14-volumes.png', full_page=True)
    derived.click()
    expect(page.get_by_text(re.compile(r'Decrypted BitLocker volume p0 of'))).to_be_visible()
    check('the decrypted evidence says where it came from', True)
    page.get_by_role('link', name='Shadow copies').first.click()
    snaps = page.locator('.card', has=page.get_by_role('heading', name='Snapshots'))
    expect(snaps.locator('tbody tr')).to_have_count(2)
    page.get_by_role('tab', name=re.compile(r'^Added since')).click()
    expect(page.locator('td', has_text='/vss1').first).to_be_visible()
    check('shadow copies: both snapshots, and the folders added since each', True)
    page.screenshot(path=f'{OUT}/x15-shadow-copies.png', full_page=True)
    snaps.locator('tbody tr').first.get_by_role('button', name='Browse').click()
    d = page.get_by_role('dialog')
    row = d.locator('tr', has_text='passwords.txt')
    row.get_by_role('button', name='View').click()
    expect(page.get_by_role('dialog').filter(has_text='(shadow copy 1)')).to_be_visible()
    check('a snapshot can be browsed and its files opened in the viewer', True)
    page.keyboard.press('Escape')
    page.keyboard.press('Escape')

    print('== Network captures and phones')
    page.get_by_label('Active case').select_option(NET_PHONE_CASE)
    page.get_by_role('link', name=re.compile(r'^Network\b')).first.click()  # the name ends with its count once counts load
    upload_row = page.locator('tr', has_text='filetransfer.example.net/upload')
    expect(upload_row.get_by_text('payroll-export.csv')).to_be_visible()
    page.get_by_label('Only uploads').check()
    expect(page.locator('tbody tr')).to_have_count(1)
    check('Network: the HTTP upload with the file it carried; "only uploads" leaves just that request', True)
    page.screenshot(path=f'{OUT}/x18-network-http.png', full_page=True)
    page.get_by_role('tab', name=re.compile(r'^DNS lookups')).click()
    expect(page.locator('tr', has_text='pastebin.com').filter(has_text='203.0.113.81')).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^TLS connections')).click()
    expect(page.locator('tr', has_text='pastebin.com').get_by_role('button', name='Look up')).to_be_visible()
    check('DNS lookups with their answers; TLS connections with the server name and a threat-intelligence look-up', True)
    page.get_by_role('tab', name=re.compile(r'^Files carried')).click()
    page.locator('tr', has_text='payroll-export.csv').get_by_role('button', name='View').click()
    expect(page.get_by_role('dialog').get_by_text('DE89370400440532013000').first).to_be_visible()
    check('a file carried in the capture opens in the viewer with its own content', True)
    page.keyboard.press('Escape')
    page.get_by_role('link', name=re.compile(r'^Phones\b')).first.click()
    expect(page.get_by_role('heading', name=re.compile('Google Pixel 8'))).to_be_visible()
    expect(page.get_by_role('heading', name=re.compile('iPhone'))).to_be_visible()
    expect(page.locator('tr', has_text='Uploaded. Link in WhatsApp.').get_by_text('Dmitri K')).to_be_visible()
    page.locator('tr', has_text='This one?').get_by_role('button', name='View').click()
    expect(page.get_by_role('dialog').locator('img')).to_be_visible()
    page.keyboard.press('Escape')
    check('Phones: both devices; SMS named from the contacts; the MMS picture opens from the extraction', True)
    page.screenshot(path=f'{OUT}/x19-phone-messages.png', full_page=True)
    page.get_by_role('tab', name=re.compile(r'^WhatsApp')).click()
    expect(page.locator('tr', has_text='filetransfer.example.net/d/7Hq2xK')).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^Calls')).click()
    expect(page.locator('tr', has_text='FaceTime audio')).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^Apps')).click()
    page.get_by_label('Only what stands out').check()
    expect(page.locator('tbody tr')).to_have_count(4)
    check('WhatsApp messages, calls (FaceTime) and the four apps that stand out (Signal and Proton Mail on each phone)', True)

    print('== Linux and macOS, collections, Plaso timelines')
    page.get_by_label('Active case').select_option(UNIX_CASE)
    page.get_by_role('link', name='Linux and macOS').first.click()
    row = page.locator('tr', has_text='scp ~/exports/payroll.csv')
    expect(row.get_by_text('Copies data to another computer')).to_be_visible()
    page.get_by_label('Only what stands out').check()
    expect(page.locator('tbody tr')).to_have_count(7)
    check('shell history: commands with their times, the copy to another computer flagged; "only what stands out" leaves the seven', True)
    page.screenshot(path=f'{OUT}/x16-unix-history.png', full_page=True)
    page.get_by_role('tab', name=re.compile(r'^Logins and logs')).click()
    expect(page.locator('tr', has_text='Logged in over SSH').filter(has_text='198.51.100.23').first).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^Jobs and services')).click()
    expect(page.locator('tr', has_text='/tmp/.x/update --daemon').get_by_text(re.compile('temporary or hidden folder'))).to_be_visible()
    page.get_by_role('tab', name=re.compile(r'^Wi-Fi networks')).click()
    expect(page.locator('tr', has_text='Rival-Guest')).to_be_visible()
    check('logins, flagged services and the Mac\'s Wi-Fi networks are listed', True)
    page.goto(f'{BASE}/app/evidence/{KAPE_EV}')
    coll = page.locator('.card', has=page.get_by_role('heading', name='Collection'))
    expect(coll).to_contain_text('ZIP of collected files: 67 files unpacked read-only')
    expect(coll).to_contain_text('2026-09-01T190512_LAPTOP-07/C')
    check('a KAPE collection shows how it was unpacked and the drive found in it', True)
    page.get_by_role('link', name='Timeline').first.click()
    page.get_by_role('button', name='Import a Plaso timeline').click()
    d = page.get_by_role('dialog')
    d.get_by_label('Timeline file').set_input_files('/img/dfip-test-disk.plaso.jsonl')
    d.get_by_role('button', name='Import').click()
    imp = page.locator('.card', has=page.get_by_role('heading', name='Imported timelines'))
    expect(imp.get_by_text('COMPLETED')).to_be_visible(timeout=60000)
    page.get_by_label('Event type').select_option('plaso')
    expect(page.get_by_text('Plaso', exact=True).first).to_be_visible()
    check('a Plaso timeline is imported from the Timeline page and its events shown with the Plaso filter', True)
    page.screenshot(path=f'{OUT}/x17-plaso-import.png', full_page=True)

    print('== review, comments, physical evidence, link graph, case summary')
    page.get_by_label('Active case').select_option(SHOWCASE)
    page.get_by_role('link', name=re.compile(r'^Findings\b')).first.click()
    page.get_by_role('button', name='Record finding').click()
    d = page.get_by_role('dialog')
    d.get_by_label('Title').fill(REVIEW_TITLE)
    d.get_by_label('Observation').fill('payroll-export.csv was opened from E: at 14:14 UTC.')
    d.get_by_role('button', name='Save finding').click()
    card = page.locator('.card', has=page.get_by_role('heading', name=REVIEW_TITLE))
    expect(card.get_by_text('Draft', exact=True)).to_be_visible()
    card.get_by_role('button', name='Send for review').click()
    d = page.get_by_role('dialog')
    admin_opt = next(o for o in d.get_by_label('Reviewer', exact=True).locator('option').all_inner_texts() if '(admin)' in o)
    d.get_by_label('Reviewer', exact=True).select_option(label=admin_opt)
    d.get_by_role('button', name='Send', exact=True).click()
    expect(card.get_by_text('In review', exact=True)).to_be_visible()
    check('a finding is recorded as a draft and sent to the administrator for review', True)
    card.get_by_role('button', name=re.compile('History and comments')).click()
    box = card.get_by_label(re.compile('Add a comment'))
    box.click()
    box.press_sequentially('Please check the LNK time @adm')
    page.get_by_role('option', name=re.compile('admin@dfip.local')).click()
    expect(box).to_have_value(re.compile(r'@admin@dfip\.local '))
    card.get_by_role('button', name='Comment', exact=True).click()
    expect(card.locator('.comment .mention')).to_be_visible()
    expect(card.get_by_role('status')).to_contain_text('Notified')
    check('typing @ offers the case\'s people; the comment shows the mention and says who was notified', True)
    page.screenshot(path=f'{OUT}/x20-finding-review.png', full_page=True)

    page.get_by_role('link', name=re.compile(r'^Physical evidence\b')).first.click()
    page.get_by_role('button', name='Add item').click()
    d = page.get_by_role('dialog')
    d.get_by_label('Description').fill('Grey laptop (UI test)')
    d.get_by_label('Bag number').fill('B-UI-1')
    d.get_by_label('Seal number').fill('S-UI-1')
    d.get_by_label('Stored at').fill('Locker 7')
    d.get_by_role('button', name='Book in').click()
    d = page.get_by_role('dialog')
    expect(d.get_by_text('Locker 7').first).to_be_visible()
    d.get_by_role('button', name='Check out').click()
    d.get_by_label('Taken by').fill('Lab tech')
    d.get_by_label('Purpose').fill('Imaging')
    d.get_by_role('button', name='Record', exact=True).click()
    expect(d.get_by_text('Checked out', exact=True).first).to_be_visible()
    d.get_by_label('Add photo').set_input_files({'name': 'front.png', 'mimeType': 'image/png', 'buffer': _png()})
    expect(d.locator('.photo-strip img')).to_have_count(1)
    with page.expect_download() as dl:
        d.get_by_role('button', name='Print custody form').click()
    check('physical evidence: booked in, checked out, photographed, and its custody form downloaded',
          dl.value.suggested_filename.endswith('-custody.pdf'), dl.value.suggested_filename)
    page.screenshot(path=f'{OUT}/x21-physical.png', full_page=True)
    page.keyboard.press('Escape')

    page.get_by_role('link', name='Link graph').first.click()
    node = page.get_by_role('button', name='Person alice')
    expect(node).to_be_visible(timeout=30000)
    node.click()
    side = page.get_by_role('complementary', name='Selected node')
    expect(side.get_by_text('opened').first).to_be_visible()
    side.get_by_role('button', name='Expand').click()
    expect(page.locator('.card', has=page.get_by_role('heading', name='Connections')).locator('tbody tr').first).to_be_visible()
    check('link graph: selecting alice lists her connections and the records behind them; the connections table lists every line', True)
    page.screenshot(path=f'{OUT}/x22-link-graph.png', full_page=True)

    page.get_by_role('link', name='Case summary').first.click()
    page.get_by_role('button', name='Fact F1').first.click()
    expect(page.get_by_role('region', name='Fact F1')).to_be_visible()
    expect(page.get_by_text('Claude mode is off for this case')).to_be_visible()
    check('case summary: citations open their fact and its records; Claude mode is off until turned on', True)
    page.screenshot(path=f'{OUT}/x23-case-summary.png', full_page=True)

    print('== bad session')
    page.evaluate("() => { sessionStorage.setItem('dfip_token', 'garbage'); sessionStorage.setItem('dfip_refresh', 'garbage'); }")
    page.goto(BASE + '/app/timeline')
    expect(page).to_have_url(BASE + '/login')
    check('an invalid session sends the user to sign-in', True)
    ctx.close()

    print('== user administration and password change')
    ctx = b.new_context(viewport={'width': 1440, 'height': 900})
    page = ctx.new_page()
    page.on('pageerror', lambda e: errors.append(str(e)))
    sign_in(page, 'admin@dfip.local')
    expect(page.get_by_text('Investigation functions').or_(page.get_by_text('No case selected'))).to_be_visible()
    page.locator('a.nav-link[href$="/admin/users"]').click()  # not "Computer and users"
    email = f'ui.user.{uuid.uuid4().hex[:6]}@corp.local'
    page.get_by_role('button', name='Add user').click()
    d = page.get_by_role('dialog')
    d.get_by_label('Full name').fill('Priya Raman')
    d.get_by_label('Email').fill(email)
    d.get_by_label('Role').select_option('ANALYST')
    d.get_by_label('Initial password').fill('Initial-Password-77')
    d.get_by_role('button', name='Create user').click()
    row = page.locator('tr', has_text=email)
    expect(row).to_be_visible()
    check('admin adds a user with an internal .local address', True)
    page.get_by_label(f'Role of {email}').select_option('INVESTIGATOR')
    expect(page.get_by_label(f'Role of {email}')).to_have_value('INVESTIGATOR')
    page.reload()
    expect(page.get_by_label(f'Role of {email}')).to_have_value('INVESTIGATOR')
    check('role change is saved', True)
    row.get_by_role('button', name='Suspend').click()
    expect(row.get_by_role('button', name='Reactivate')).to_be_visible()
    row.get_by_role('button', name='Reactivate').click()
    expect(row.get_by_role('button', name='Suspend')).to_be_visible()
    check('user can be suspended and reactivated', True)
    page.locator('.topbar').get_by_role('button', name='Sign out').click()
    expect(page.get_by_text('You have signed out.')).to_be_visible()

    sign_in(page, email, 'Initial-Password-77')
    expect(page.locator('.topbar')).to_be_visible()
    page.locator('.topbar').get_by_role('button', name='Change password').click()
    d = page.get_by_role('dialog', name='Change password')
    d.get_by_label('Current password').fill('wrong-password-000')
    d.get_by_label('New password', exact=True).fill('Changed-Password-88')
    d.get_by_label('Confirm new password').fill('Changed-Password-8')
    expect(d.get_by_text('The passwords do not match.')).to_be_visible()
    check('change password: mismatch is flagged and saving is disabled', d.get_by_role('button', name='Change password').is_disabled())
    d.get_by_label('Confirm new password').fill('Changed-Password-88')
    d.get_by_role('button', name='Change password').click()
    expect(d.get_by_text('Current password is incorrect')).to_be_visible()
    check('change password: a wrong current password is reported', True)
    d.get_by_label('Current password').fill('Initial-Password-77')
    d.get_by_role('button', name='Change password').click()
    expect(page.get_by_text('Password changed.')).to_be_visible()
    check('change password succeeds', not d.is_visible())
    page.screenshot(path=f'{OUT}/x1-password-changed.png')
    page.locator('.topbar').get_by_role('button', name='Sign out').click()
    sign_in(page, email, 'Initial-Password-77')
    expect(page.get_by_text('Email or password is incorrect.')).to_be_visible()
    check('old password no longer works', True)
    sign_in(page, email, 'Changed-Password-88')
    expect(page.locator('.topbar')).to_be_visible()
    check('new password works', True)
    ctx.close()

    print('== hash sets (administrator)')
    ctx = b.new_context(viewport={'width': 1440, 'height': 900})
    page = ctx.new_page()
    page.on('pageerror', lambda e: errors.append(str(e)))
    sign_in(page, 'admin@dfip.local')
    expect(page.get_by_text('Investigation functions').or_(page.get_by_text('No case selected'))).to_be_visible()
    page.locator('a.nav-link[href$="/admin/hashsets"]').click()
    expect(page.get_by_role('heading', name='Hash sets', exact=True)).to_be_visible()
    set_name = f'UI test notable {uuid.uuid4().hex[:4]}'
    payroll = ('employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))).encode()
    page.get_by_role('button', name='Import a hash set').click()
    d = page.get_by_role('dialog')
    d.locator('input[type=file]').set_input_files({'name': 'notable.txt', 'mimeType': 'text/plain',
                                                    'buffer': (hashlib.sha256(payroll).hexdigest() + '  payroll-export.csv\n').encode()})
    d.get_by_label('Name').fill(set_name)
    d.get_by_label('Kind').select_option('NOTABLE')
    d.get_by_role('button', name='Import').click()
    row = page.locator('tbody tr', has_text=set_name)
    expect(row.get_by_text('READY')).to_be_visible(timeout=60000)
    expect(row.get_by_text('1 SHA256')).to_be_visible()
    check('an administrator imports a hash set and sees it ready with its counts', True)
    page.screenshot(path=f'{OUT}/x4-hash-sets.png', full_page=True)
    row.get_by_role('button', name=f'Delete {set_name}').click()
    page.get_by_role('dialog').get_by_role('button', name='Delete set').click()
    expect(page.locator('tbody tr', has_text=set_name)).to_have_count(0)
    check('...and deletes it', True)

    print('== malware rules (administrator)')
    page.locator('a.nav-link[href$="/admin/malware-rules"]').click()
    expect(page.get_by_role('heading', name='Malware rules', exact=True)).to_be_visible()
    rs_name = f'UI test rules {uuid.uuid4().hex[:4]}'
    page.get_by_role('button', name='Add a rule set').click()
    d = page.get_by_role('dialog')
    d.get_by_label('Name').fill(rs_name)
    d.get_by_label('Rules file').set_input_files({'name': 'broken.yar', 'mimeType': 'text/plain', 'buffer': b'rule broken { condition: }'})
    d.get_by_role('button', name='Add').click()
    expect(d.get_by_text(re.compile('do not compile|syntax error', re.I))).to_be_visible()
    check('a rule set that does not compile is refused with the reason', True)
    d.get_by_label('Rules file').set_input_files({'name': 'wiper.yar', 'mimeType': 'text/plain',
                                                   'buffer': b'rule UI_Wiper { strings: $a = "SDWIPE/3-PASS" condition: $a }\n'})
    d.get_by_role('button', name='Add').click()
    row = page.locator('tbody tr', has_text=rs_name)
    expect(row).to_be_visible()
    check('an administrator adds a YARA rule set (1 rule, in use)', row.locator('td').nth(1).inner_text().strip() == '1'
          and row.get_by_role('checkbox').is_checked())
    page.screenshot(path=f'{OUT}/x13-malware-rules.png', full_page=True)
    row.get_by_role('button', name=f'Delete {rs_name}').click()
    expect(page.locator('tbody tr', has_text=rs_name)).to_have_count(0)
    check('...and deletes it', True)

    print('== reviewing a finding and retention (administrator)')
    page.get_by_label('Active case').select_option(SHOWCASE)
    page.get_by_role('link', name=re.compile(r'^Findings\b')).first.click()
    card = page.locator('.card', has=page.get_by_role('heading', name=REVIEW_TITLE))
    card.get_by_role('button', name='Approve').click()
    page.get_by_role('dialog').get_by_role('button', name='Approve').click()
    expect(card.get_by_text('Approved', exact=True)).to_be_visible()
    check('the administrator approves the finding sent to them', True)
    page.locator('a.nav-link[href$="/admin/retention"]').click()
    expect(page.get_by_role('heading', name='Retention', exact=True)).to_be_visible()
    page.get_by_role('button', name='Run the check now').click()
    expect(page.get_by_text(re.compile(r'case\(s\) due'))).to_be_visible()
    check('the retention page shows the policy and runs the daily check on demand', True)
    page.screenshot(path=f'{OUT}/x24-retention.png', full_page=True)
    ctx.close()

    print('== narrower windows')
    for w, h in ((1280, 800), (1024, 768)):
        ctx = b.new_context(viewport={'width': w, 'height': h})
        page = ctx.new_page()
        page.goto(BASE + '/login')
        page.evaluate("c => localStorage.setItem('dfip_active_case', c)", SHOWCASE)
        sign_in(page, 'investigator@dfip.local')
        expect(page.get_by_text('Investigation functions')).to_be_visible()
        bad = []
        for path in ('/app', '/app/files', '/app/timeline', '/app/browser', '/app/email', '/app/chat-cloud', '/app/media', '/app/indicators', '/app/shadow-copies', '/app/unix', '/app/network', '/app/phones', '/app/physical', '/app/graph', '/app/summary', '/app/findings', '/app/usb', '/app/reports', '/app/custody'):
            page.goto(BASE + path)
            page.wait_for_load_state('networkidle')
            sw = page.evaluate('document.documentElement.scrollWidth')
            top = page.evaluate("(() => { const t = document.querySelector('.topbar'); return t.scrollWidth - t.clientWidth; })()")
            # Wide tables may scroll sideways inside their card, but their action buttons must stay in view.
            hidden_actions = page.evaluate("""[...document.querySelectorAll('.table-wrap')].flatMap(w => {
                const box = w.getBoundingClientRect();
                return [...w.querySelectorAll('td.right:last-child')].filter(td => {
                    const r = td.getBoundingClientRect(); return r.right > box.right + 1 || r.left < box.left - 1; });
            }).length""")
            squeezed = page.evaluate("[...document.querySelectorAll('td.cell-path')].filter(td => td.getBoundingClientRect().width < 150).length")
            if sw > w or top > 0 or hidden_actions or squeezed:
                bad.append((path, f'page {sw}', f'topbar +{top}', f'hidden action cells {hidden_actions}', f'squeezed cells {squeezed}'))
            if w == 1024:
                page.screenshot(path=f"{OUT}/x3-{path.strip('/').replace('/', '-')}-1024.png")
        page.goto(BASE + '/app/timeline')
        page.wait_for_load_state('networkidle')
        page.screenshot(path=f'{OUT}/x2-timeline-{w}.png')
        check(f'{w}px: no page overflow, no squeezed columns, action buttons always visible', not bad, bad)
        ctx.close()

    check('no JavaScript errors', not errors, errors[:3])
    b.close()

print(f'ui_extra: {sum(results)} passed, {len(results) - sum(results)} failed')
sys.exit(0 if all(results) else 1)
