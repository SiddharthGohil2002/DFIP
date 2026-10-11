"""Full analysis of one evidence image, run as a background (Celery) job.

Stages: integrity re-verification -> (E01 only) verified raw working copy -> partition table (mmls) -> per-filesystem
listing (fls bodyfile) feeding the file index and MACB timeline -> extraction and
parsing of browser history and USB artifacts -> YARA on extracted user scripts
and executables -> case-level patterns and anomalies.

Re-running replaces this evidence item's previous pipeline output, so results
never double up. Everything written is tagged with the job ID for provenance.
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import settings
from .artifact_locator import ArtifactCollector, extract
from .browser_artifacts import PARSERS as BROWSER_PARSERS
from .filesystem import iter_bodyfile, write_bodyfile
from .hashing import sha256_file
from .timeline import activity_events, browser_events, macb_events, usb_events
from .tools import filesystem_stats, parse_mmls, recover_file, scan_yara
from .usb import merge_usb_sources, parse_setupapi, parse_system_hive
from .windows_activity import parse_lnk, parse_prefetch, parse_recycle_index_file
from .working_image import analysis_image, needs_working_copy

BATCH = 5000
# Windows activity artifacts: how many of each kind one analysis extracts (a real disk can hold thousands).
MAX_ACTIVITY_ITEMS = {'PREFETCH': 2048, 'LNK_RECENT': 5000, 'RECYCLE_BIN_INFO': 5000}
MAX_SUMMARY_ARTIFACTS = 200
RULES_FILE = Path(__file__).resolve().parents[2] / 'rules' / 'default.yar'
SCAN_CANDIDATE_RE = re.compile(r'^/(?:Users|Documents and Settings)/.+\.(?:ps1|bat|cmd|vbs|js|hta|exe|dll|scr)$', re.I)
MAX_SCAN_FILES = 200
MAX_SCAN_BYTES = 20 * 1024 * 1024


class Cancelled(Exception):
    pass


def _filesystem_type(stats_stdout: str):
    m = re.search(r'File System Type:\s*(.+)', stats_stdout or '')
    return m.group(1).strip() if m else None


def _select_offsets(mmls: dict) -> list[int]:
    offsets = [p['start'] for p in mmls.get('partitions', [])
               if not p.get('is_meta') and not p.get('is_unallocated') and 'extended' not in p.get('description', '').lower()]
    # No partition table (a bare filesystem image): the filesystem starts at sector 0.
    return offsets or [0]


class AnalysisPipeline:
    def __init__(self, db, evidence: dict, job_id: str, progress=None, is_cancelled=None):
        self.db = db
        self.e = evidence
        self.case_id = evidence['case_id']
        self.eid = evidence['evidence_id']
        self.job_id = job_id
        self.progress = progress or (lambda p, s: None)
        self.is_cancelled = is_cancelled or (lambda: False)
        self.original = Path(evidence['storage_path'])
        self.image = self.original  # what the Sleuth Kit reads; the raw working copy for E01 (set in run)
        self.work = Path(settings.storage_path).resolve() / 'analysis' / 'pipeline' / self.eid / job_id
        self.summary = {'evidence_id': self.eid, 'case_id': self.case_id, 'job_id': job_id, 'engine': 'DFIP Analysis Pipeline',
                        'partitions': [], 'filesystems': [], 'counts': {}, 'artifacts': [], 'warnings': []}

    # -- helpers ---------------------------------------------------------------
    def _checkpoint(self, pct, stage):
        if self.is_cancelled():
            raise Cancelled()
        self.progress(pct, stage)

    def _tag(self, doc):
        doc.update(pipeline=True, analysis_job_id=self.job_id)
        return doc

    def _count(self, key, n=1):
        self.summary['counts'][key] = self.summary['counts'].get(key, 0) + n

    def _insert(self, collection, docs):
        if docs:
            self.db[collection].insert_many([self._tag(d) for d in docs], ordered=False)

    # -- stages ----------------------------------------------------------------
    def run(self) -> dict:
        self._checkpoint(5, 'verifying-integrity')
        self._verify_integrity()
        self._clear_previous()
        self.work.mkdir(parents=True, exist_ok=True)
        if needs_working_copy(self.e):
            self._checkpoint(8, 'preparing-e01-working-copy')
        self.image = analysis_image(self.e, create=True, db=self.db, actor=f'DFIP analysis job {self.job_id}')

        self._checkpoint(10, 'reading-partition-table')
        mmls = parse_mmls(self.image)
        self.summary['partitions'] = mmls.get('partitions', [])
        offsets = _select_offsets(mmls)

        collector = ArtifactCollector()
        for i, offset in enumerate(offsets):
            self._checkpoint(15 + int(45 * i / len(offsets)), f'indexing-filesystem@{offset}')
            self._index_filesystem(offset, collector)

        self._checkpoint(65, 'extracting-artifacts')
        self._process_artifacts(collector.resolved())

        self._checkpoint(80, 'yara-scan')
        self._yara_scan()

        # Tags point at records this run replaced; re-link them by natural key (kept out of the counts).
        self._checkpoint(88, 'relinking-tags')
        from ..services.tags import relink_evidence
        self.summary['tags'] = relink_evidence(self.db, self.eid)

        self._checkpoint(90, 'case-analytics')
        from ..analysis.services import compute_anomalies, compute_patterns
        self.summary['counts']['patterns'] = len(compute_patterns(self.db, self.case_id))
        anomalies, method, _ = compute_anomalies(self.db, self.case_id)
        # IsolationForest scores every event; only those it isolates count as flagged.
        self.summary['counts']['anomalies_flagged'] = (sum(1 for a in anomalies if a.get('is_anomaly'))
                                                       if method == 'ISOLATION_FOREST' else len(anomalies))
        self.summary['anomaly_method'] = method
        return self.summary

    def _verify_integrity(self):
        if not self.original.exists():
            raise FileNotFoundError('Original evidence object is unavailable')
        digest = sha256_file(self.original)
        ok = digest == self.e['sha256']
        now = datetime.now(timezone.utc)
        self.db['chain_of_custody'].insert_one({
            'evidence_id': self.eid, 'case_id': self.case_id, 'timestamp': now, 'user_id': 'system',
            'user_name': f'DFIP analysis job {self.job_id}', 'action': 'ANALYSIS_INTEGRITY_CHECK',
            'sha256': digest, 'status': 'VERIFIED' if ok else 'INTEGRITY_FAILED'})
        self.summary['integrity'] = {'expected_sha256': self.e['sha256'], 'computed_sha256': digest, 'verified': ok}
        if not ok:
            raise ValueError('Evidence SHA-256 no longer matches the acquisition hash; analysis refused')

    def _clear_previous(self):
        q = {'evidence_id': self.eid, 'pipeline': True}
        for col in ('fs_entries', 'timeline_events', 'forensic_artifacts', 'usb_artifacts'):
            self.db[col].delete_many(q)

    def _index_filesystem(self, offset: int, collector: ArtifactCollector):
        stats = filesystem_stats(self.image, offset)
        fs_type = _filesystem_type(stats.get('stdout', ''))
        info = {'partition_offset': offset, 'filesystem_type': fs_type, 'fsstat_status': stats.get('status')}
        if stats.get('status') != 'COMPLETED':
            info['error'] = (stats.get('stderr') or '').strip()[:500]
            self.summary['filesystems'].append(info)
            self.summary['warnings'].append(f'No readable filesystem at sector offset {offset}')
            return
        bodyfile = self.work / f'fls-offset-{offset}.body'
        r = write_bodyfile(self.image, offset, bodyfile)
        info.update(bodyfile=str(bodyfile), fls_status=r.get('status'))
        if r.get('status') != 'COMPLETED':
            info['error'] = r.get('stderr', '')[:500]
            self.summary['filesystems'].append(info)
            return
        entries, events = [], []
        files = deleted = 0
        for entry in iter_bodyfile(bodyfile):
            if entry['fn_attr']:
                # NTFS $FILE_NAME times duplicate the file's own entry; they stay in the
                # bodyfile for mactime but are not indexed or counted as separate files.
                continue
            collector.observe(entry, offset)
            if not entry['is_virtual']:
                files += 1
                deleted += entry['deleted']
            entries.append(dict(entry, case_id=self.case_id, evidence_id=self.eid,
                                partition_offset=offset, filesystem_type=fs_type))
            events.extend(macb_events(entry, self.case_id, self.eid, offset))
            if len(entries) >= BATCH:
                self._insert('fs_entries', entries)
                entries = []
            if len(events) >= BATCH:
                self._insert('timeline_events', events)
                self._count('timeline_events', len(events))
                events = []
        self._insert('fs_entries', entries)
        self._insert('timeline_events', events)
        self._count('timeline_events', len(events))
        self._count('files', files)
        self._count('deleted_files', deleted)
        info.update(files=files, deleted_files=deleted)
        self.summary['filesystems'].append(info)

    def _register_extracted(self, item: dict, result: dict) -> str:
        aid = str(uuid.uuid4())
        self._insert('forensic_artifacts', [{
            'artifact_id': aid, 'case_id': self.case_id, 'evidence_id': self.eid, 'type': 'EXTRACTED_FILE',
            'artifact_kind': item['kind'], 'timestamp': datetime.now(timezone.utc),
            'path': result['local_path'], 'filename': Path(result['local_path']).name,
            'original_path': item['path'], 'inode': item['inode'], 'offset': item['partition_offset'],
            'size': result['size'], 'sha256': result['sha256'], 'sidecars': result['sidecars'],
            'source': 'SLEUTH_KIT_ICAT'}])
        self.summary['artifacts_total'] = self.summary.get('artifacts_total', 0) + 1
        if len(self.summary['artifacts']) < MAX_SUMMARY_ARTIFACTS:
            self.summary['artifacts'].append({'kind': item['kind'], 'path': item['path'], 'sha256': result['sha256'],
                                              'artifact_id': aid})
        return aid

    def _process_artifacts(self, items: list[dict]):
        hive_results, setupapi_items, activity = [], [], []
        for key in ('programs_run', 'recent_files', 'recycle_bin_items'):
            self._count(key, 0)
        seen: dict[str, int] = {}
        for n, item in enumerate(items):
            cap = MAX_ACTIVITY_ITEMS.get(item['kind'])
            if cap is not None:
                seen[item['kind']] = seen.get(item['kind'], 0) + 1
                if seen[item['kind']] > cap:
                    if seen[item['kind']] == cap + 1:
                        self.summary['warnings'].append(f'Only the first {cap} {item["kind"]} files were analysed')
                    continue
            dest = self.work / 'extracted' / f'{n:03d}-{item["kind"].lower()}'
            result = extract(self.image, item, dest)
            if result.get('status') != 'COMPLETED':
                self.summary['warnings'].append(f'Could not extract {item["path"]}: {result.get("error")}')
                continue
            aid = self._register_extracted(item, result)
            local = Path(result['local_path'])
            if item['kind'] in BROWSER_PARSERS:
                self._parse_browser(item, local, aid)
            elif item['kind'] == 'SYSTEM_HIVE':
                hive_results.append((item, aid, parse_system_hive(local)))
            elif item['kind'] == 'SETUPAPI_LOG':
                setupapi_items.append((item, aid, local))
            elif item['kind'] in MAX_ACTIVITY_ITEMS:
                row = self._activity_record(item, local, aid)
                if row:
                    activity.append(row)
        self._parse_usb(hive_results, setupapi_items)
        self._store_activity(activity)

    def _activity_record(self, item, local: Path, parent_id: str) -> dict | None:
        """One Windows activity record from an extracted Prefetch, Recent shortcut or Recycle Bin $I file."""
        parser = {'PREFETCH': parse_prefetch, 'LNK_RECENT': parse_lnk, 'RECYCLE_BIN_INFO': parse_recycle_index_file}[item['kind']]
        parsed = parser(local)
        if parsed.get('status') != 'COMPLETED':
            self.summary['warnings'].append(f'{item["path"]}: {parsed.get("error")}')
            return None
        if parsed.get('warning'):
            self.summary['warnings'].append(f'{item["path"]}: {parsed["warning"]}')
        fields = {k: v for k, v in parsed.items() if k not in ('status', 'warning')}
        name = item['path'].rsplit('/', 1)[-1]
        iso = lambda t: t.isoformat() if hasattr(t, 'isoformat') else t
        row = {'artifact_id': str(uuid.uuid4()), 'case_id': self.case_id, 'evidence_id': self.eid,
               'source_path': item['path'], 'source_file': item['path'], 'parent_artifact_id': parent_id,
               'partition_offset': item['partition_offset'], 'timestamp': datetime.now(timezone.utc), **fields}
        if item['kind'] == 'PREFETCH':
            row.update(type='PROGRAM_RUN', source='PREFETCH', pf_name=name, pf_modified=iso(item.get('fs_mtime')))
        elif item['kind'] == 'LNK_RECENT':
            row.update(type='RECENT_FILE', source='LNK', lnk_name=name,
                       lnk_created=iso(item.get('fs_crtime')), lnk_modified=iso(item.get('fs_mtime')))
        else:
            data = item.get('recycle_data') or {}
            row.update(type='RECYCLE_BIN_ITEM', source='RECYCLE_BIN', sid=item.get('sid'), index_name=name,
                       original_name=(row.get('original_path') or '').replace('/', '\\').rsplit('\\', 1)[-1] or None,
                       data_present=bool(data), data_path=data.get('path'), data_inode=data.get('inode'),
                       data_size=data.get('size'), data_is_dir=data.get('is_dir'))
        return row

    def _store_activity(self, rows: list[dict]):
        if not rows:
            return
        self._insert('forensic_artifacts', rows)
        events = activity_events(rows)
        self._insert('timeline_events', events)
        self._count('programs_run', sum(r['type'] == 'PROGRAM_RUN' for r in rows))
        self._count('recent_files', sum(r['type'] == 'RECENT_FILE' for r in rows))
        self._count('recycle_bin_items', sum(r['type'] == 'RECYCLE_BIN_ITEM' for r in rows))
        self._count('timeline_events', len(events))

    def _parse_browser(self, item, local: Path, parent_id: str):
        parsed = BROWSER_PARSERS[item['kind']](local, self.case_id, self.eid)
        rows = []
        for key in ('history', 'downloads', 'cookies'):
            for row in parsed.get(key, []):
                rows.append(dict(row, browser=item.get('browser'), source_path=item['path'],
                                 source_file=item['path'], parent_artifact_id=parent_id,
                                 timestamp=datetime.now(timezone.utc)))
        if parsed.get('errors'):
            self.summary['warnings'].extend(f'{item["path"]}: {e}' for e in parsed['errors'])
        self._insert('forensic_artifacts', rows)
        events = browser_events(rows)
        self._insert('timeline_events', events)
        self._count('browser_history', sum(r['type'] == 'BROWSER_HISTORY' for r in rows))
        self._count('browser_downloads', sum(r['type'] == 'BROWSER_DOWNLOAD' for r in rows))
        self._count('timeline_events', len(events))

    def _parse_usb(self, hive_results, setupapi_items):
        if not hive_results and not setupapi_items:
            return
        devices, bias, sources = [], None, []
        for item, aid, parsed in hive_results:
            sources.append(aid)
            if parsed['status'] != 'COMPLETED':
                self.summary['warnings'].extend(f'{item["path"]}: {e}' for e in parsed['errors'])
                continue
            devices.extend(parsed['devices'])
            if bias is None:
                bias = parsed.get('timezone_bias_minutes')
        entries = []
        for item, aid, local in setupapi_items:
            sources.append(aid)
            parsed = parse_setupapi(local, bias)
            entries.extend(parsed['entries'])
            if bias is None and parsed['entries']:
                self.summary['warnings'].append('setupapi.dev.log times are system local time (no SYSTEM hive time zone found)')
        merged = merge_usb_sources(devices, entries)
        now = datetime.now(timezone.utc)
        docs = [dict(d, case_id=self.case_id, evidence_id=self.eid, source_artifact_ids=sources, created_at=now)
                for d in merged]
        self._insert('usb_artifacts', [dict(d) for d in docs])
        events = usb_events(merged, self.case_id, self.eid)
        self._insert('timeline_events', events)
        self._count('usb_devices', len(docs))
        self._count('timeline_events', len(events))

    def _yara_scan(self):
        """Extracts user-profile scripts/executables (bounded) and scans them with DFIP's YARA rules."""
        candidates = list(self.db['fs_entries'].find(
            {'evidence_id': self.eid, 'pipeline': True, 'deleted': False, 'is_dir': False,
             'path': {'$regex': SCAN_CANDIDATE_RE.pattern, '$options': 'i'}, 'size': {'$lte': MAX_SCAN_BYTES}},
            {'path': 1, 'inode': 1, 'partition_offset': 1}).limit(MAX_SCAN_FILES))
        if not candidates or not RULES_FILE.is_file():
            return
        scan_dir = self.work / 'yara-scan'
        by_local = {}
        for n, c in enumerate(candidates):
            local = scan_dir / f'{n:04d}' / c['path'].rsplit('/', 1)[-1]
            if recover_file(self.image, c['inode'], local, c['partition_offset']).get('status') == 'COMPLETED':
                by_local[str(local)] = c
        r = scan_yara(RULES_FILE, scan_dir)
        if not r.get('available'):
            self.summary['warnings'].append('YARA is not installed; malware signature scan skipped')
            return
        hits = []
        for line in (r.get('stdout') or '').splitlines():
            rule, _, target = line.partition(' ')
            c = by_local.get(target.strip())
            if not c:
                continue
            hits.append({'artifact_id': str(uuid.uuid4()), 'case_id': self.case_id, 'evidence_id': self.eid,
                         'type': 'MALWARE_INDICATOR', 'rule': rule, 'original_path': c['path'], 'inode': c['inode'],
                         'description': f'YARA rule {rule} matched {c["path"]}',
                         'timestamp': datetime.now(timezone.utc), 'source': 'YARA'})
        self._insert('forensic_artifacts', hits)
        self._count('files_scanned', len(by_local))
        self._count('yara_matches', len(hits))
