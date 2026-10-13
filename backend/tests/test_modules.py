"""Analysis modules: run planning, the module context, safe tool execution and evidence sources."""
import os
import time
from pathlib import Path

import pytest

from app.forensic.modules import MODULES, ORDER, PROFILES, REGISTRY, plan, resolve_request
from app.forensic.modules.base import MAX_SUMMARY_WARNINGS, Cancelled, Module, ModuleContext, run_tool
from app.forensic.source import BlobRef, DirectorySource, offset_of, volume_id


# ------------------------------------------------------------------ a minimal in-memory stand-in for MongoDB
class _Col:
    def __init__(self):
        self.docs = []

    @staticmethod
    def _match(doc, q):
        return all(doc.get(k) == v for k, v in q.items())

    def insert_many(self, docs, ordered=True):
        self.docs.extend(dict(d) for d in docs)

    def insert_one(self, doc):
        self.docs.append(dict(doc))

    def delete_many(self, q):
        self.docs = [d for d in self.docs if not self._match(d, q)]

    def find_one(self, q, projection=None):
        return next((d for d in self.docs if self._match(d, q)), None)

    def update_one(self, q, update, upsert=False):
        doc = self.find_one(q)
        if doc is None:
            if not upsert:
                return
            doc = dict(q)
            self.docs.append(doc)
        for path, value in update.get('$set', {}).items():
            *parents, leaf = path.split('.')
            node = doc
            for p in parents:
                node = node.setdefault(p, {})
            node[leaf] = value
        for path in update.get('$unset', {}):
            doc.pop(path, None)

    def update_many(self, q, update):
        for doc in self.docs:
            if self._match(doc, q):
                for path in update.get('$unset', {}):
                    doc.pop(path, None)


class FakeDB(dict):
    def __missing__(self, name):
        self[name] = _Col()
        return self[name]


def _ctx(db, module=None, **kw):
    module = module or REGISTRY['yara']
    return ModuleContext(db=db, evidence={'case_id': 'CASE-1', 'evidence_id': 'EVID-1'}, job_id='JOB-1', run_id='run-1',
                         module=module, image=Path('/dev/null'), work=Path('/tmp'), **kw)


# ------------------------------------------------------------------ planning
def test_order_respects_requirements():
    for i, m in enumerate(MODULES):
        assert all(ORDER.index(r) < i for r in m.requires)


def test_profiles_and_requests():
    assert resolve_request() == PROFILES['standard']
    assert resolve_request('quick') == ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone', 'network', 'memory']
    # Standard adds file processing (hashes, types, hash sets, YARA) on every file; full also indexes file contents.
    assert PROFILES['standard'] == [m for m in ORDER if m not in ('containers', 'ocr', 'content', 'unallocated', 'found_data')]
    assert PROFILES['full'] == ORDER
    assert resolve_request(modules=['yara', 'yara']) == ['yara']
    with pytest.raises(ValueError):
        resolve_request('everything')
    with pytest.raises(ValueError):
        resolve_request(modules=['nope'])


def _done(*names):
    return {n: {'status': 'COMPLETED', 'version': REGISTRY[n].version} for n in names}


def test_plan_adds_missing_prerequisites():
    assert plan(['yara'], {}) == ['tz_probe', 'fs_index', 'fileproc', 'yara']  # YARA chooses files by their real type
    assert plan(['hash_match'], {}) == ['tz_probe', 'fs_index', 'fileproc', 'hash_match']
    assert plan(['found_data'], {}) == ['tz_probe', 'fs_index', 'fileproc', 'content', 'found_data']  # follows adds nothing
    assert plan(['unallocated'], {}) == ['tz_probe', 'fs_index', 'unallocated']
    assert plan(['artifacts'], {}) == ['tz_probe', 'fs_index', 'artifacts']
    assert plan(['computer'], {}) == ['computer']  # reads its hives directly


def test_plan_reruns_only_what_is_needed():
    status = _done(*ORDER)
    assert plan(['yara'], status) == ['yara']                       # nothing depends on yara
    assert plan(['hash_match'], status) == ['hash_match']           # a hash set changed: only matching runs again
    # Synced cloud files are linked to file hashes (chat_cloud follows fileproc, containers and email).
    assert plan(['fileproc'], status) == ['fileproc', 'containers', 'chat_cloud', 'media', 'ocr', 'executables', 'reputation', 'clamav', 'hash_match',
                                          'yara', 'content', 'found_data']
    # Modules that follow another (read its output when it ran) are refreshed when it re-runs.
    assert plan(['containers'], status) == ['containers', 'chat_cloud', 'media', 'ocr', 'executables', 'reputation', 'clamav', 'hash_match', 'yara',
                                            'content', 'found_data']
    assert plan(['email'], status) == ['email', 'chat_cloud', 'media', 'ocr', 'executables', 'reputation', 'clamav', 'hash_match', 'yara', 'content',
                                       'found_data']  # attachments
    assert plan(['executables'], status) == ['executables', 'reputation']  # VirusTotal verdicts are kept on the program records
    assert plan(['browser_depth'], status) == ['browser_depth']
    assert plan(['unallocated'], status) == ['unallocated', 'found_data']
    # Event logs read the accounts (computer) and add to the USB devices (artifacts): both refresh them. SRUM names users
    # through the accounts too.
    assert plan(['artifacts'], status) == ['artifacts', 'eventlogs']
    assert plan(['computer'], status) == ['computer', 'eventlogs', 'user_activity']
    assert plan(['user_activity'], status) == ['user_activity']
    assert plan(['ntfs'], status) == ['ntfs']
    assert plan(['eventlogs'], status) == ['eventlogs']
    assert plan(['content'], status) == ['content', 'found_data']
    # Dependents are refreshed.
    assert plan(['fs_index'], status) == ['fs_index', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies', 'browser_depth', 'fileproc',
                                          'containers', 'email', 'chat_cloud', 'media', 'ocr', 'executables', 'reputation', 'clamav', 'hash_match', 'yara',
                                          'content', 'unallocated', 'found_data']
    # A new time zone re-indexes the file system (FAT times) and refreshes what was built on the index.
    assert plan(['tz_probe'], status) == ['tz_probe', 'fs_index', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies', 'browser_depth',
                                          'fileproc', 'containers', 'email', 'chat_cloud', 'media', 'ocr', 'executables', 'reputation', 'clamav',
                                          'hash_match', 'yara', 'content', 'unallocated', 'found_data']
    # On evidence analysed with the standard profile, the content modules are not added by a re-run.
    standard = _done(*PROFILES['standard'])
    assert plan(['fs_index'], standard) == ['fs_index', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies', 'browser_depth', 'fileproc',
                                            'email', 'chat_cloud', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara']
    assert plan(['fs_index'], _done('tz_probe', 'fs_index')) == ['fs_index']  # dependents that never ran are not added


def test_plan_treats_older_module_versions_as_missing():
    status = _done('tz_probe', 'fs_index', 'artifacts')
    status['fs_index']['version'] = 'old'
    assert plan(['artifacts'], status) == ['fs_index', 'artifacts']


# ------------------------------------------------------------------ module context
def test_insert_tags_every_document_with_its_module_and_run():
    db = FakeDB()
    ctx = _ctx(db)
    ctx.insert('forensic_artifacts', [{'evidence_id': 'EVID-1', 'type': 'X'}])
    doc = db['forensic_artifacts'].docs[0]
    assert (doc['pipeline'], doc['pipeline_module'], doc['module_run_id'], doc['analysis_job_id']) == (True, 'yara', 'run-1', 'JOB-1')


def test_clear_removes_only_the_modules_own_output():
    db = FakeDB()
    _ctx(db, REGISTRY['yara']).insert('forensic_artifacts', [{'evidence_id': 'EVID-1', 'type': 'MALWARE_INDICATOR'}])
    _ctx(db, REGISTRY['artifacts']).insert('forensic_artifacts', [{'evidence_id': 'EVID-1', 'type': 'BROWSER_HISTORY'}])
    REGISTRY['yara'].clear(db, 'EVID-1')
    assert [d['type'] for d in db['forensic_artifacts'].docs] == ['BROWSER_HISTORY']


def test_clear_unsets_the_fields_a_module_adds_to_others_documents():
    db = FakeDB()
    _ctx(db, REGISTRY['fs_index']).insert('fs_entries', [{'evidence_id': 'EVID-1', 'path': '/a.txt'}])
    db['fs_entries'].docs[0].update(sha256='ab' * 32, mime='text/plain', hash_status='KNOWN_GOOD', hash_sets=['HS-0001'])
    REGISTRY['hash_match'].clear(db, 'EVID-1')
    doc = db['fs_entries'].docs[0]
    assert 'hash_status' not in doc and 'hash_sets' not in doc and doc['sha256'] == 'ab' * 32
    REGISTRY['fileproc'].clear(db, 'EVID-1')
    assert db['fs_entries'].docs == [doc] and 'sha256' not in doc and 'mime' not in doc and doc['path'] == '/a.txt'


def test_warnings_are_all_stored_but_capped_on_the_summary():
    db = FakeDB()
    ctx = _ctx(db)
    for i in range(MAX_SUMMARY_WARNINGS + 25):
        ctx.warn(f'w{i}')
    assert len(ctx.warnings) == MAX_SUMMARY_WARNINGS and ctx.warnings_total == MAX_SUMMARY_WARNINGS + 25
    assert len(db['pipeline_warnings'].docs) == MAX_SUMMARY_WARNINGS + 25


def test_progress_never_moves_backwards():
    seen = []
    ctx = _ctx(FakeDB(), progress_cb=lambda p, s: seen.append(p), band=(20, 40))
    for f in (0.5, 0.2, 1.0, 0.9):
        ctx.progress(f)
    assert seen == [30, 30, 40, 40]


def test_facts_are_shared_per_evidence():
    db = FakeDB()
    ctx = _ctx(db, REGISTRY['fs_index'])
    ctx.set_fact('offsets', [2048])
    assert _ctx(db, REGISTRY['artifacts']).fact('fs_index', 'offsets') == [2048]
    REGISTRY['fs_index'].clear(db, 'EVID-1')
    assert ctx.fact('fs_index', 'offsets') is None


def test_checkpoint_raises_when_cancelled():
    ctx = _ctx(FakeDB(), cancel_check=lambda: True)
    with pytest.raises(Cancelled):
        ctx.checkpoint()


# ------------------------------------------------------------------ external tools
def _alive(pid):
    try:
        with open(f'/proc/{pid}/status') as f:
            return 'State:\tZ' not in f.read()
    except FileNotFoundError:
        return False


def test_run_tool_captures_output_and_reports_failures():
    r = run_tool(['sh', '-c', 'echo hello; echo oops >&2; exit 3'], timeout=10)
    assert (r['status'], r['returncode'], r['stdout'].strip(), r['stderr'].strip()) == ('FAILED', 3, 'hello', 'oops')
    assert run_tool(['no-such-tool-dfip'], timeout=5)['status'] == 'TOOL_UNAVAILABLE'


def test_run_tool_writes_large_output_to_a_file(tmp_path):
    out = tmp_path / 'out.txt'
    r = run_tool(['sh', '-c', 'seq 1 100000'], timeout=10, stdout_path=out)
    assert r['status'] == 'COMPLETED' and r['stdout'] == '' and out.read_text().splitlines()[-1] == '100000'


def test_run_tool_timeout_kills_the_whole_process_group(tmp_path):
    pidfile = tmp_path / 'child.pid'
    t0 = time.monotonic()
    r = run_tool(['sh', '-c', f'sleep 60 & echo $! > {pidfile}; wait'], timeout=1)
    assert r['status'] == 'TIMEOUT' and time.monotonic() - t0 < 10
    child = int(pidfile.read_text())
    time.sleep(0.3)
    assert not _alive(child), 'the background child of the tool must be killed too'


def test_run_tool_cancellation_kills_the_tool(tmp_path):
    pidfile = tmp_path / 'child.pid'
    calls = []

    def stop():
        calls.append(1)
        return len(calls) > 1  # cancelled on the second poll

    with pytest.raises(Cancelled):
        run_tool(['sh', '-c', f'sleep 60 & echo $! > {pidfile}; wait'], timeout=120, should_stop=stop)
    time.sleep(0.3)
    assert not _alive(int(pidfile.read_text()))


def test_run_tool_applies_a_memory_limit():
    # 64 MiB address space is far too small to allocate 200 MB, so the tool fails instead of exhausting the host.
    r = run_tool(['python3', '-c', 'b = bytearray(200 * 1024 * 1024)'], timeout=20, memory_bytes=64 << 20)
    assert r['status'] == 'FAILED'


# ------------------------------------------------------------------ evidence sources
def test_volume_ids():
    assert volume_id(2048) == 'p2048' and volume_id(0) == volume_id(None) == 'p0'
    assert offset_of('p2048') == 2048
    with pytest.raises(ValueError):
        offset_of('pkg')


def test_directory_source(tmp_path):
    (tmp_path / 'Users' / 'alice').mkdir(parents=True)
    (tmp_path / 'Users' / 'alice' / 'notes.txt').write_bytes(b'0123456789')
    src = DirectorySource(tmp_path)
    assert src.volumes() == ['pkg']
    entries = {e['path']: e for e in src.walk()}
    assert entries['/Users/alice']['is_dir'] and entries['/Users/alice/notes.txt']['size'] == 10
    ref = BlobRef('EVID-1', 'pkg', path='/Users/alice/notes.txt')
    assert src.read_range(ref, 2, 3) == b'234' and src.read_range(ref, 50, 3) == b''
    with pytest.raises(ValueError):
        src.open(BlobRef('EVID-1', 'pkg', path='/../../etc/passwd'))


def test_directory_source_ignores_symlinks(tmp_path):
    (tmp_path / 'secret').write_text('x')
    pkg = tmp_path / 'pkg'
    pkg.mkdir()
    os.symlink(tmp_path / 'secret', pkg / 'link')
    src = DirectorySource(pkg)
    assert not [e for e in src.walk() if e['path'] == '/link']
    with pytest.raises((FileNotFoundError, ValueError)):
        src.open(BlobRef('EVID-1', 'pkg', path='/link'))


def test_every_module_is_described():
    for m in MODULES:
        assert isinstance(m, Module) and m.name and m.label and m.description and isinstance(m.collections, tuple)


def test_artifact_prefilter_selects_every_known_artifact_path():
    import re
    from app.forensic.modules.artifacts import _CANDIDATES, _mongo_pattern
    pattern = _mongo_pattern(_CANDIDATES)
    assert '(?P<' not in pattern  # MongoDB rejects the same group name twice
    rx = re.compile(pattern, re.I)
    for path in ('/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History',
                 '/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History-journal',
                 '/Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k2x8.default-release/places.sqlite',
                 '/Windows/System32/config/SYSTEM', '/Windows/INF/setupapi.dev.log',
                 '/$Recycle.Bin/S-1-5-21-1-2-3-1001/$I3K9D2A.csv', '/$Recycle.Bin/S-1-5-21-1-2-3-1001/$R3K9D2A.csv',
                 '/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/a.csv.lnk', '/Windows/Prefetch/X.EXE-1A2B3C4D.pf'):
        assert rx.search(path), path
    assert not rx.search('/Users/alice/Documents/notes.txt')
