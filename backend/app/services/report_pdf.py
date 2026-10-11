"""Builds the case investigation report PDF (ReportLab).

Every value comes from stored case data; sections with no data say so rather
than being omitted, so a reader can tell "not found" from "not examined".
"""
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .audit import verify_chain

MAX_ROWS = 200
PAGE_WIDTH = A4[0] - 30 * mm

_styles = getSampleStyleSheet()
BODY = _styles['BodyText']
H1 = _styles['Title']
H2 = _styles['Heading2']
H3 = _styles['Heading3']
CELL = ParagraphStyle('cell', parent=BODY, fontSize=7.5, leading=9)
CELL_MONO = ParagraphStyle('cellmono', parent=CELL, fontName='Courier', fontSize=7)
NOTE = ParagraphStyle('note', parent=BODY, fontSize=8, textColor=colors.HexColor('#555555'))


def _fmt(v):
    if v is None or v == '':
        return '—'
    if isinstance(v, str) and len(v) >= 19 and v[4] == '-' and v[10] == 'T':
        try:
            v = datetime.fromisoformat(v)
        except ValueError:
            return v
    if isinstance(v, datetime):
        return v.strftime('%Y-%m-%d %H:%M:%S UTC')
    if isinstance(v, (list, tuple)):
        return ', '.join(_fmt(x) for x in v) or '—'
    return str(v)


def _p(v, style=CELL):
    return Paragraph(escape(_fmt(v)), style)


def _table(header, rows, widths, mono_cols=()):
    data = [[Paragraph(f'<b>{escape(h)}</b>', CELL) for h in header]]
    for row in rows:
        data.append([_p(v, CELL_MONO if i in mono_cols else CELL) for i, v in enumerate(row)])
    total = sum(widths)
    t = Table(data, colWidths=[PAGE_WIDTH * w / total for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), .3, colors.HexColor('#b0b8c0')),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e7eef5')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    return t


def _section(story, title, header, rows, widths, empty, mono_cols=(), total=None, heading=H2):
    story.append(Paragraph(escape(title), heading))
    if not rows:
        story.append(Paragraph(escape(empty), NOTE))
    else:
        story.append(_table(header, rows[:MAX_ROWS], widths, mono_cols))
        shown_total = total if total is not None else len(rows)
        if shown_total > MAX_ROWS:
            story.append(Paragraph(f'Showing {MAX_ROWS} of {shown_total}; the complete set is available in DFIP.', NOTE))
    story.append(Spacer(1, 10))


def _time_basis(db, eids) -> str:
    """How local times were read for each evidence item (FAT file times and setupapi.dev.log are local time)."""
    parts = []
    for f in db['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'evidence_id': 1, 'tz_probe': 1}):
        tz = f.get('tz_probe') or {}
        if not tz:
            continue
        source = {'registry': f'from the SYSTEM hive ({(tz.get("detected") or {}).get("key_name")})',
                  'override': f'set by {(tz.get("override") or {}).get("set_by_name")}: {(tz.get("override") or {}).get("reason")}',
                  'default': 'no time zone found; local times shown as recorded'}.get(tz.get('source'), tz.get('source'))
        parts.append(f'{f["evidence_id"]}: {tz.get("zone")} ({source})')
    if not parts:
        return 'All times are UTC.'
    return "All times are UTC. Local times were converted with the computer's time zone — " + '; '.join(parts)


def build_case_report(db, case: dict, report_id: str, version: int, path: Path, generated_by: dict, now: datetime):
    cid = case['case_id']
    # Sections are numbered in order of appearance.
    numbers = iter(range(1, 100))
    T = lambda title: f'{next(numbers)}. {title}'
    evidence = list(db['evidence'].find({'case_id': cid}).sort('created_at', 1))
    eids = [e['evidence_id'] for e in evidence]
    investigator = None
    if case.get('investigator_id'):
        from bson import ObjectId
        if ObjectId.is_valid(case['investigator_id']):
            investigator = db['users'].find_one({'_id': ObjectId(case['investigator_id'])}, {'name': 1, 'email': 1})

    story = [
        Paragraph('Digital Forensics Investigation Report', H1),
        _table(['Field', 'Value'], [
            ['Report', f'{report_id} (version {version} for this case)'],
            ['Case', f'{cid} — {case["name"]}'],
            ['Status / priority', f'{case.get("status")} / {case.get("priority")}'],
            ['Legal hold', (f'ACTIVE since {_fmt(case["legal_hold"].get("set_at"))} by {case["legal_hold"].get("set_by_name")}: '
                            f'{case["legal_hold"].get("reason")}') if (case.get('legal_hold') or {}).get('active') else 'Not under legal hold'],
            ['Lead investigator', f'{investigator["name"]} <{investigator["email"]}>' if investigator else None],
            ['Description', case.get('description')],
            ['Generated', now],
            ['Generated by', f'{generated_by.get("name")} ({generated_by.get("role")})'],
            ['Time basis', _time_basis(db, eids)],
        ], [1, 3]),
        Spacer(1, 6),
        Paragraph('All artifacts in this report were extracted from forensic copies of the evidence listed below. '
                  'Original evidence files are stored read-only and re-verified against their acquisition SHA-256 '
                  'before every analysis run.', NOTE),
        Spacer(1, 10),
    ]

    _section(story, T('Evidence register'), ['Evidence', 'File', 'Format', 'Size (bytes)', 'Acquired', 'Integrity', 'Analysis'],
             [[e['evidence_id'], e.get('filename'), e.get('format'), e.get('size'), e.get('created_at'),
               e.get('verification_status'), e.get('analysis_status') or 'NOT RUN'] for e in evidence],
             [1.1, 2.4, 0.8, 1.2, 1.7, 1.2, 1.1], 'No evidence has been registered for this case.')
    if evidence:
        story.append(_table(['Evidence', 'SHA-256 (acquisition)'],
                            [[e['evidence_id'], e.get('sha256')] for e in evidence], [1, 5], mono_cols=(1,)))
        story.append(Spacer(1, 10))

    custody = list(db['chain_of_custody'].find({'case_id': cid}).sort('timestamp', 1))
    # Readable action labels wrap at spaces; older records may only carry a user ID.
    names = {str(x['_id']): x.get('name') for x in db['users'].find({}, {'name': 1})}
    _section(story, T('Chain of custody'), ['Time', 'Evidence', 'Action', 'By', 'SHA-256 / result'],
             [[c.get('timestamp'), c.get('evidence_id'), (c.get('action') or '').replace('_', ' ').capitalize(),
               c.get('user_name') or names.get(str(c.get('user_id'))) or c.get('user_id'),
               ((f'{(c.get("sha256") or "")[:24]}… {c.get("status") or c.get("result") or ""}'.strip() if c.get('sha256') else c.get('status') or c.get('result') or '')
                + (f' ({c["reason"]})' if c.get('reason') else ''))]
              for c in custody],
             [1.6, 0.9, 1.6, 1.6, 2.2], 'No custody events recorded.')

    story.append(Paragraph(T('Analysis summary'), H2))
    runs = []
    for e in evidence:
        s = e.get('analysis_summary') or {}
        activity = None
        if 'programs_run' in s:
            activity = f'{s.get("programs_run", 0)} / {s.get("recent_files", 0)} / {s.get("recycle_bin_items", 0)}'
        runs.append([e['evidence_id'], e.get('analyzed_at'), s.get('files'), s.get('deleted_files'), s.get('timeline_events'),
                     s.get('browser_history'), s.get('usb_devices'), activity, s.get('yara_matches')])
    story.append(_table(['Evidence', 'Analyzed', 'Files', 'Deleted', 'Timeline events', 'Browser visits', 'USB devices',
                         'Programs / recent files / recycled', 'YARA hits'],
                        runs, [1, 1.6, .6, .6, .9, .8, .8, 1.3, .6]) if runs else Paragraph('No evidence analyzed.', NOTE))
    story.append(Spacer(1, 10))

    computers = list(db['forensic_artifacts'].find({'evidence_id': {'$in': eids}, 'type': 'COMPUTER_INFO'}))
    users = list(db['forensic_artifacts'].find({'evidence_id': {'$in': eids}, 'type': 'USER_ACCOUNT'}).sort([('evidence_id', 1), ('rid', 1)]))
    _section(story, T('Computer and users'), ['Evidence', 'Computer', 'Windows', 'Installed', 'Last shutdown', 'Time zone', 'IP addresses'],
             [[c['evidence_id'], c.get('computer_name'),
               ' '.join(str(x) for x in ((c.get('os') or {}).get('product_name'), (c.get('os') or {}).get('display_version'),
                                         f'build {(c.get("os") or {}).get("build")}' if (c.get('os') or {}).get('build') else None) if x),
               (c.get('os') or {}).get('install_date'), c.get('last_shutdown'),
               (c.get('time_zone') or {}).get('key_name'), ', '.join(i['ip'] for i in c.get('interfaces') or [])] for c in computers],
             [0.9, 1.1, 1.6, 1.2, 1.2, 1.3, 1.2], 'No Windows registry (SYSTEM, SOFTWARE, SAM) was found on the evidence.')
    if users:
        story.append(_table(['Evidence', 'User', 'Full name', 'SID', 'Last logon', 'Logons', 'Profile', 'Account'],
                            [[u['evidence_id'], u.get('username'), u.get('full_name'), u.get('sid'), u.get('last_logon'),
                              u.get('logon_count'), u.get('profile_path'),
                              'profile only' if u.get('source') == 'PROFILE_LIST' else ('disabled' if u.get('disabled') else 'enabled')]
                             for u in users], [0.8, 0.9, 1.0, 2.0, 1.2, 0.5, 1.0, 0.7], mono_cols=(3,)))
        story.append(Spacer(1, 10))

    deleted_q = {'evidence_id': {'$in': eids}, 'deleted': True, 'is_virtual': False, 'container': {'$exists': False}}
    deleted = list(db['fs_entries'].find(deleted_q).sort('path', 1).limit(MAX_ROWS))
    _section(story, T('Deleted files (filesystem metadata)'), ['Evidence', 'Path', 'Inode', 'Size', 'Modified', 'Created'],
             [[d['evidence_id'], d['path'], d.get('inode'), d.get('size'), d.get('mtime'), d.get('crtime')] for d in deleted],
             [0.9, 3.2, 0.7, 0.7, 1.5, 1.5], 'No deleted file entries were found (or evidence was not analyzed).',
             total=db['fs_entries'].count_documents(deleted_q))

    recovered = list(db['forensic_artifacts'].find({'case_id': cid, 'type': 'RECOVERED_FILE'}).sort('timestamp', 1))
    _section(story, T('Recovered files'), ['Recovered', 'Original path', 'Was deleted', 'Size', 'SHA-256'],
             [[r.get('timestamp'), r.get('original_path') or f'inode {r.get("inode")}', 'yes' if r.get('was_deleted') else 'no',
               r.get('size'), r.get('sha256')] for r in recovered],
             [1.3, 2.6, 0.7, 0.7, 3.2], 'No files have been recovered.', mono_cols=(4,))

    usb = list(db['usb_artifacts'].find({'case_id': cid}))
    _section(story, T('USB device history'), ['Device', 'Serial', 'VID:PID', 'Drive', 'First install', 'Last connected', 'Last removed', 'Source'],
             [[u.get('friendly_name') or f'{u.get("vendor")} {u.get("product")}', u.get('serial'),
               f'{u["vid"]}:{u["pid"]}' if u.get('vid') else None, u.get('drive_letters'),
               u.get('first_install') or u.get('setupapi_first_install') or u.get('eventlog_first_connected'),
               u.get('last_arrival') or u.get('eventlog_last_connected'), u.get('last_removal') or u.get('eventlog_last_removed'),
               (u.get('source') or '') + (' + event logs' if u.get('eventlog_events') and u.get('source') != 'EVENT_LOG' else '')] for u in usb],
             [1.5, 1.7, 0.9, 0.6, 1.3, 1.3, 1.3, 1.2],
             'No USB storage devices were found in the SYSTEM hive, setupapi.dev.log or the event logs.')

    hist = list(db['forensic_artifacts'].find({'case_id': cid, 'type': 'BROWSER_HISTORY'}).sort('last_visit_time', -1))
    _section(story, T('Browser history'), ['Browser', 'Last visit', 'Visits', 'URL', 'Title'],
             [[h.get('browser'), h.get('last_visit_time'), h.get('visit_count'), h.get('url'), h.get('title')] for h in hist],
             [0.8, 1.5, 0.5, 3.2, 2], 'No browser history databases were found.')
    downloads = list(db['forensic_artifacts'].find({'case_id': cid, 'type': 'BROWSER_DOWNLOAD'}).sort('start_time', -1))
    _section(story, T('Browser downloads'), ['Browser', 'Started', 'Saved to', 'From'],
             [[d.get('browser'), d.get('start_time'), d.get('target_path'), d.get('tab_url')] for d in downloads],
             [0.8, 1.5, 3, 3], 'No browser downloads were found.')

    art = db['forensic_artifacts']
    activity_title = T('Windows activity')
    story.append(Paragraph(escape(activity_title), H2))
    story.append(Paragraph('Programs run come from Prefetch files, opened files from shortcuts in the user\'s Recent folder '
                           '(Windows writes the shortcut when the file is opened; the target times describe the file itself), '
                           'and deletions from Recycle Bin index ($I) files.', NOTE))
    n = activity_title.split('.')[0]
    q = {'case_id': cid, 'type': 'PROGRAM_RUN'}
    _section(story, f'{n}.1 Programs run (Prefetch)', ['Program', 'Run count', 'Last run', 'Earlier runs', 'Prefetch file'],
             [[p.get('executable_path') or p.get('executable'), p.get('run_count'), p.get('last_run'),
               (p.get('last_run_times') or [])[1:], p.get('source_path')] for p in art.find(q).sort('last_run', -1).limit(MAX_ROWS)],
             [2.6, 0.6, 1.3, 1.6, 1.9], 'No Prefetch files were found.', total=art.count_documents(q), heading=H3)
    q = {'case_id': cid, 'type': 'RECENT_FILE'}
    _section(story, f'{n}.2 Recently opened files', ['Opened (last)', 'File', 'Drive', 'Target size', 'Target modified', 'Shortcut'],
             [[f.get('lnk_modified'), f.get('target_path'),
               ' '.join(x for x in (f.get('drive_type'), f.get('volume_label'), f.get('drive_serial')) if x) or None,
               f.get('target_size'), f.get('target_modified'), f.get('source_path')]
              for f in art.find(q).sort('lnk_modified', -1).limit(MAX_ROWS)],
             [1.3, 2.2, 1.3, 0.7, 1.3, 2.2], 'No Recent-folder shortcuts were found.', total=art.count_documents(q), heading=H3)
    q = {'case_id': cid, 'type': 'RECYCLE_BIN_ITEM'}
    _section(story, f'{n}.3 Recycle Bin', ['Deleted', 'Original path', 'Size', 'Content ($R) present', 'Index file'],
             [[b.get('deleted_time'), b.get('original_path'), b.get('original_size'), 'yes' if b.get('data_present') else 'no',
               b.get('source_path')] for b in art.find(q).sort('deleted_time', -1).limit(MAX_ROWS)],
             [1.3, 2.8, 0.7, 0.9, 2.6], 'No Recycle Bin index files were found.', total=art.count_documents(q), heading=H3)

    # Registry activity (module registry).
    from ..forensic.execution import merge as merge_execution
    reg = {t: list(art.find({'case_id': cid, 'type': t}, {'_id': 0}))
           for t in ('PROGRAM_RUN', 'USERASSIST', 'BAM_ENTRY', 'AMCACHE_FILE', 'SHIMCACHE_ENTRY')}
    for rows_ in reg.values():
        for x in rows_:
            for k, v in list(x.items()):
                if hasattr(v, 'isoformat'):
                    x[k] = v.isoformat()
    execution = merge_execution(reg['PROGRAM_RUN'], reg['USERASSIST'], reg['BAM_ENTRY'], reg['AMCACHE_FILE'], reg['SHIMCACHE_ENTRY'])
    _section(story, T('Execution evidence'), ['Program', 'Traces', 'Last run', 'First recorded', 'SHA-1 (Amcache)', 'Paths'],
             [[x['program'], ', '.join({'prefetch': 'Prefetch', 'userassist': 'UserAssist', 'bam': 'BAM', 'amcache': 'Amcache',
                                        'shimcache': 'ShimCache'}[s] for s in x['sources']),
               x['last_run'], x['first_seen'], x['sha1'], '; '.join(x['paths'][:3])]
              for x in execution[:MAX_ROWS]],
             [1.4, 1.3, 1.3, 1.3, 1.7, 2.3], 'No Prefetch, UserAssist, BAM, Amcache or ShimCache records were found.',
             mono_cols=(4,), total=len(execution))
    q = {'case_id': cid, 'type': 'SHELLBAG'}
    _section(story, T('Folders browsed (ShellBags)'), ['User', 'Folder', 'Last browsed', 'Created', 'Modified', 'Accessed'],
             [[b.get('user'), b.get('path'), b.get('key_last_write') if b.get('mru_position') == 0 else None, b.get('created'),
               b.get('modified'), b.get('accessed')] for b in art.find(q).sort([('user', 1), ('path', 1)]).limit(MAX_ROWS)],
             [0.8, 2.8, 1.3, 1.2, 1.2, 1.2], 'No ShellBags were found.', total=art.count_documents(q))
    kinds = {'EXPLORER_SEARCH': 'Explorer search', 'TYPED_PATH': 'Typed path', 'TYPED_URL': 'Typed address', 'RUN_MRU': 'Run dialog',
             'RECENT_DOC': 'Recent document'}
    q = {'case_id': cid, 'type': {'$in': list(kinds)}, 'extension': None}
    _section(story, T('Searches and typed paths'), ['User', 'Kind', 'Value', 'Order', 'Key written'],
             [[s.get('user'), kinds.get(s['type']), s.get('value'), s.get('order'), s.get('key_last_write')]
              for s in art.find(q).sort([('user', 1), ('type', 1), ('order', 1)]).limit(MAX_ROWS)],
             [0.8, 1.2, 3.8, 0.5, 1.5], 'No Explorer searches, typed paths, Run dialog commands or recent documents were found.',
             total=art.count_documents(q))
    q = {'case_id': cid, 'type': 'PERSISTENCE'}
    pers = sorted(art.find(q), key=lambda p: (not p.get('flags'), p.get('kind') or '', p.get('name') or ''))[:MAX_ROWS]
    _section(story, T('Persistence (autostart entries and services)'), ['Kind', 'Name', 'Runs', 'Written', 'Why it stands out'],
             [[p.get('kind') + (f' ({p["user"]})' if p.get('user') else ''), p.get('name'), p.get('command'), p.get('key_last_write'),
               '; '.join(p.get('flags') or []) or None] for p in pers],
             [1.0, 1.2, 2.6, 1.3, 2.0], 'No Run keys, services, debuggers or Winlogon entries were found.', total=art.count_documents(q))
    q = {'case_id': cid, 'type': 'INSTALLED_PROGRAM'}
    _section(story, T('Installed programs'), ['Name', 'Version', 'Publisher', 'Installed', 'Location'],
             [[p.get('name'), p.get('version'), p.get('publisher'), p.get('install_date'), p.get('install_location')]
              for p in art.find(q).sort('name', 1).limit(MAX_ROWS)],
             [2.2, 0.9, 1.4, 0.9, 2.4], 'No installed programs were found.', total=art.count_documents(q))
    q = {'case_id': cid, 'type': {'$in': ['RDP_CONNECTION', 'NETWORK_DRIVE']}}
    _section(story, T('Remote desktop and network drives'), ['User', 'Kind', 'Target', 'Detail', 'Written'],
             [[x.get('user'), 'Remote desktop' if x['type'] == 'RDP_CONNECTION' else 'Network drive',
               x.get('server') or x.get('remote_path'), x.get('username_hint') or (f'{x.get("drive")}:' if x.get('drive') else None),
               x.get('key_last_write')] for x in art.find(q).sort('key_last_write', -1).limit(MAX_ROWS)],
             [0.8, 1.2, 2.6, 1.6, 1.5], 'No remote desktop connections or mapped network drives were found.', total=art.count_documents(q))

    # Windows event logs (module eventlogs).
    events_title = T('Event logs')
    story.append(Paragraph(escape(events_title), H2))
    story.append(Paragraph('Every record of the Windows event logs (.evtx) is stored in DFIP. Notable events are the catalogued ones an '
                           'investigation looks for (logons, account changes, cleared logs, services, PowerShell, USB devices, '
                           'Defender, startup and shutdown) and every record a detection rule matched. Detections are leads from '
                           "DFIP's curated Sigma rules, not conclusions.", NOTE))
    n = events_title.split('.')[0]
    logs = []
    for f in db['analysis_facts'].find({'evidence_id': {'$in': eids}}, {'evidence_id': 1, 'eventlogs.logs': 1}):
        logs += [dict(x, evidence_id=f['evidence_id']) for x in (f.get('eventlogs') or {}).get('logs') or []]
    logs.sort(key=lambda x: (x['evidence_id'], -(x.get('records') or 0)))
    short = lambda c: (c or '').replace('Microsoft-Windows-', '')
    _section(story, f'{n}.1 Logs read', ['Evidence', 'Log', 'Records', 'Recovered', 'First event', 'Last event', 'State'],
             [[x['evidence_id'], x.get('name'), x.get('records'), x.get('recovered'), x.get('first'), x.get('last'),
               ', '.join(w for w, on in (('not closed cleanly', x.get('dirty')), ('full', x.get('full')), ('damaged', x.get('corrupted')),
                                          ('capped', x.get('capped'))) if on) or 'OK'] for x in logs if x.get('records') or x.get('recovered')],
             [0.9, 2.4, 0.7, 0.95, 1.3, 1.3, 0.9], 'No event logs with records were found (or the Standard or Full profile has not been run).',
             total=sum(1 for x in logs if x.get('records') or x.get('recovered')), heading=H3)
    q = {'case_id': cid, 'type': 'EVENTLOG_DETECTION'}
    level_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
    dets = sorted(art.find(q), key=lambda d: (level_order.get(d.get('level'), 9), str(d.get('first') or '')))
    _section(story, f'{n}.2 Detections', ['Level', 'Rule', 'Events', 'First', 'Last', 'Example'],
             [[(d.get('level') or '').capitalize(), d.get('title') + (f' ({", ".join(f"{k} {v}" for k, v in d["group"].items())})' if d.get('group') else ''),
               d.get('count'), d.get('first'), d.get('last'), (d.get('sample') or [None])[0]] for d in dets],
             [0.7, 2.2, 0.75, 1.3, 1.3, 2.25], 'No detection rule matched the event records.', total=len(dets), heading=H3)
    q = {'case_id': cid, 'notable': True}
    _section(story, f'{n}.3 Notable events', ['Time', 'Log', 'Event', 'User', 'Description'],
             [[e.get('time'), short(e.get('channel')), e.get('event_id'), e.get('user'), e.get('description') or e.get('title')]
              for e in db['event_records'].find(q, {'xml': 0, 'text': 0, 'data': 0}).sort('time', 1).limit(MAX_ROWS)],
             [1.2, 1.5, 0.65, 1.15, 3.7], 'No notable events were found.', total=db['event_records'].count_documents(q), heading=H3)

    malware = list(db['forensic_artifacts'].find({'case_id': cid, 'type': 'MALWARE_INDICATOR'}))
    _section(story, T('Malware indicators (YARA)'), ['Evidence', 'Rule', 'File'],
             [[m.get('evidence_id'), m.get('rule'), (m.get('original_path') or m.get('path') or '') + (' (deleted)' if m.get('deleted') else '')]
              for m in malware],
             [1, 2.5, 4], 'No YARA rule matches in the executables, scripts, documents and archives scanned.')

    sets_q = {'evidence_id': {'$in': eids}, 'hash_status': {'$in': ['KNOWN_BAD', 'NOTABLE']}}
    in_sets = list(db['fs_entries'].find(sets_q).sort([('hash_status', 1), ('path', 1)]).limit(MAX_ROWS))
    _section(story, T('Hash set matches'), ['Evidence', 'Status', 'File', 'SHA-256', 'Hash sets'],
             [[f['evidence_id'], (f.get('hash_status') or '').replace('_', ' ').capitalize(),
               f['path'] + (' (deleted)' if f.get('deleted') else ''), f.get('sha256'),
               ', '.join(m['name'] for m in f.get('hash_sets') or [])] for f in in_sets],
             [0.9, 0.9, 2.2, 2.2, 1.4], 'No file matches a known-bad or notable hash set (or no hash sets are imported).',
             mono_cols=(3,), total=db['fs_entries'].count_documents(sets_q))

    flag_q = {'evidence_id': {'$in': eids}, '$or': [{'ext_mismatch': True}, {'encryption': {'$ne': None, '$exists': True}}]}
    flagged = list(db['fs_entries'].find(flag_q).sort('path', 1).limit(MAX_ROWS))
    _section(story, T('Renamed and encrypted files'), ['Evidence', 'File', 'Content', 'Name suggests', 'Encryption'],
             [[f['evidence_id'], f['path'] + (' (deleted)' if f.get('deleted') else ''), f.get('mime'), f.get('expected_type'),
               (f.get('encryption') or {}).get('detail')] for f in flagged],
             [0.8, 2.6, 1.3, 1.1, 1.8], 'No file whose content contradicts its name, and no encrypted file, was found.',
             total=db['fs_entries'].count_documents(flag_q))

    from ..forensic.found_data import LABELS as FOUND_LABELS
    found_q = {'evidence_id': {'$in': eids}}
    found = list(db['entities'].find(found_q, {'occurrences': 0}).sort([('kind', 1), ('count', -1), ('value', 1)]).limit(MAX_ROWS))
    _section(story, T('Found data'), ['Evidence', 'Kind', 'Value', 'Occurrences', 'Files'],
             [[f['evidence_id'], FOUND_LABELS.get(f['kind'], f['kind']), f.get('display'), f.get('count'), f.get('file_count')] for f in found],
             [0.9, 1.7, 3.3, 0.9, 0.8], 'No email, web or IP addresses, phone, card, IBAN, cryptocurrency or Aadhaar numbers were found, '
             'or the file contents were not indexed (Full analysis profile). Card and Aadhaar numbers are shown masked.',
             total=db['entities'].count_documents(found_q))

    story.append(Paragraph(T('Investigator findings'), H2))
    findings = list(db['findings'].find({'case_id': cid}).sort('created_at', 1))
    if not findings:
        story.append(Paragraph('No findings recorded.', NOTE))
    for f in findings:
        story.append(Paragraph(f'<b>{escape(f["title"])}</b> [{escape(f.get("severity", ""))}]', BODY))
        story.append(Paragraph(escape(f.get('description', '')), BODY))
        if f.get('evidence_ids'):
            story.append(Paragraph('Evidence: ' + escape(', '.join(f['evidence_ids'])), NOTE))
        story.append(Spacer(1, 6))

    from .tags import resolve
    tag_order = {'EVIDENCE': 0, 'NOTABLE': 1, 'FOLLOW_UP': 2}
    tagged = sorted(db['tags'].find({'case_id': cid}), key=lambda t: (tag_order.get(t.get('label'), 9), str((t.get('snapshot') or {}).get('timestamp') or '')))
    item_kind = {'FILE': 'File', 'TIMELINE_EVENT': 'Timeline event', 'BROWSER': 'Browser record', 'USB': 'USB device',
                 'ACTIVITY': 'Windows activity', 'ARTIFACT': 'Recovered / carved file', 'ENTITY': 'Found data',
                 'REGISTRY': 'Registry activity', 'EVENT': 'Event log record'}
    _section(story, T('Tagged evidence'), ['Label', 'Item', 'Type', 'Time', 'Note', 'Tagged by'],
             [[(t.get('label') or '').replace('_', ' ').capitalize(),
               f'{(t.get("snapshot") or {}).get("title")}' + ('' if resolve(db, t) is not None else ' (not in the latest analysis)'),
               item_kind.get(t.get('item_type'), t.get('item_type')), (t.get('snapshot') or {}).get('timestamp'), t.get('note'),
               t.get('created_by_name')] for t in tagged],
             [0.8, 2.8, 1.1, 1.3, 2.2, 1.1], 'No items have been tagged.')

    # Notable events: everything except per-file MACB entries, plus MACB entries of deleted files.
    notable_q = {'case_id': cid, '$or': [{'type': {'$ne': 'FILE_MACB'}}, {'deleted': True}]}
    notable = list(db['timeline_events'].find(notable_q).sort('timestamp', 1).limit(MAX_ROWS))
    file_events = db['timeline_events'].count_documents({'case_id': cid, 'type': 'FILE_MACB'})
    story.append(PageBreak())
    _section(story, T('Timeline of notable events'), ['Time (UTC)', 'Type', 'Event'],
             [[t.get('timestamp'), t.get('type'), t.get('description')] for t in notable],
             [1.5, 1.3, 5], 'No timeline events.', total=db['timeline_events'].count_documents(notable_q))
    story.append(Paragraph(f'The full filesystem timeline ({file_events} file MACB events) is available in DFIP and as '
                           'Sleuth Kit bodyfiles in the analysis directory for independent verification with mactime.', NOTE))

    chain = verify_chain()
    story += [Spacer(1, 10), Paragraph(T('Audit trail integrity'), H2),
              Paragraph(escape(f'Hash-chained audit log verification at report time: '
                               f'{"VALID" if chain.get("valid") else "BROKEN at sequence " + str(chain.get("broken_sequence"))}'
                               f' ({chain.get("records_checked", 0)} records checked).'), BODY),
              Spacer(1, 10),
              Paragraph('The SHA-256 of this PDF is recorded by DFIP when it is generated and returned with every download '
                        '(X-DFIP-Report-SHA256 header), so any later modification of the file can be detected.', NOTE)]

    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
                      title=f'{report_id} {cid}', author='DFIP').build(story)
