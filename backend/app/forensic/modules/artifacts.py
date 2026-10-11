"""Well-known Windows artifacts: browser history and downloads, USB device history and Windows activity.

Candidates are found in the file index written by `fs_index` (so this module can re-run on its own), copied out
with icat, and parsed. Each extracted copy is registered as an EXTRACTED_FILE artifact with its SHA-256.
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..artifact_locator import RECYCLE_DATA, SQLITE_SIDECARS, TARGETS, ArtifactCollector, extract
from ..browser_artifacts import PARSERS as BROWSER_PARSERS
from ..source import volume_id
from ..timeline import activity_events, browser_events, usb_events
from ..usb import merge_usb_sources, parse_setupapi, parse_system_hive
from ..windows_activity import parse_lnk, parse_prefetch, parse_recycle_index_file
from .base import Module

# Windows activity artifacts: how many of each kind one analysis extracts (a real disk can hold thousands).
MAX_ACTIVITY_ITEMS = {'PREFETCH': 2048, 'LNK_RECENT': 5000, 'RECYCLE_BIN_INFO': 5000}
MAX_SUMMARY_ARTIFACTS = 200

# One case-insensitive pattern that pre-selects every path the collector could care about, so the module reads
# only those index entries instead of the whole file system.
_CANDIDATES = '|'.join([rx.pattern for _, rx in TARGETS] + [RECYCLE_DATA.pattern]
                       + [re.escape(s) + '$' for s in SQLITE_SIDECARS])


def _mongo_pattern(pattern: str) -> str:
    """The pre-filter only needs to match: named groups (repeated across TARGETS) become plain groups."""
    return re.sub(r'\(\?P<\w+>', '(?:', pattern)


class ArtifactsModule(Module):
    name = 'artifacts'
    label = 'Browser, USB and Windows activity'
    description = 'Browser history and downloads, USB device history, programs run, recently opened files and the Recycle Bin.'
    version = '2'  # 2: Opera and Vivaldi history
    requires = ('fs_index',)
    weight = 30
    collections = ('forensic_artifacts', 'usb_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        self.artifacts: list[dict] = []
        self.artifacts_total = 0
        for key in ('programs_run', 'recent_files', 'recycle_bin_items', 'timeline_events'):
            ctx.count(key, 0)
        collector = ArtifactCollector()
        cursor = ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_virtual': False,
             'path': {'$regex': _mongo_pattern(_CANDIDATES), '$options': 'i'}},
            {'path': 1, 'inode': 1, 'size': 1, 'is_dir': 1, 'deleted': 1, 'is_virtual': 1, 'mtime': 1, 'crtime': 1,
             'partition_offset': 1}).sort([('partition_offset', 1), ('path', 1)])
        for entry in cursor:
            collector.observe(entry, entry['partition_offset'])
        self._process(collector.resolved())
        ctx.set_fact('extracted', self.artifacts)
        ctx.set_fact('extracted_total', self.artifacts_total)

    # -- extraction ----------------------------------------------------------------
    def _register_extracted(self, item: dict, result: dict) -> str:
        ctx = self.ctx
        aid = str(uuid.uuid4())
        ctx.insert('forensic_artifacts', [{
            'artifact_id': aid, 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': 'EXTRACTED_FILE',
            'artifact_kind': item['kind'], 'timestamp': datetime.now(timezone.utc),
            'path': result['local_path'], 'filename': Path(result['local_path']).name,
            'original_path': item['path'], 'inode': item['inode'], 'offset': item['partition_offset'],
            'volume_id': volume_id(item['partition_offset']),
            'size': result['size'], 'sha256': result['sha256'], 'sidecars': result['sidecars'],
            'source': 'SLEUTH_KIT_ICAT'}])
        self.artifacts_total += 1
        if len(self.artifacts) < MAX_SUMMARY_ARTIFACTS:
            self.artifacts.append({'kind': item['kind'], 'path': item['path'], 'sha256': result['sha256'], 'artifact_id': aid})
        return aid

    def _process(self, items: list[dict]):
        ctx = self.ctx
        hive_results, setupapi_items, activity = [], [], []
        seen: dict[str, int] = {}
        for n, item in enumerate(items):
            ctx.progress(n / max(1, len(items)), item['kind'].lower())
            cap = MAX_ACTIVITY_ITEMS.get(item['kind'])
            if cap is not None:
                seen[item['kind']] = seen.get(item['kind'], 0) + 1
                if seen[item['kind']] > cap:
                    if seen[item['kind']] == cap + 1:
                        ctx.warn(f'Only the first {cap} {item["kind"]} files were analysed')
                    continue
            dest = ctx.work / 'extracted' / f'{n:03d}-{item["kind"].lower()}'
            result = extract(ctx.image, item, dest)
            if result.get('status') != 'COMPLETED':
                ctx.warn(f'Could not extract {item["path"]}: {result.get("error")}')
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

    # -- Windows activity ----------------------------------------------------------
    def _activity_record(self, item, local: Path, parent_id: str) -> dict | None:
        """One Windows activity record from an extracted Prefetch, Recent shortcut or Recycle Bin $I file."""
        ctx = self.ctx
        parser = {'PREFETCH': parse_prefetch, 'LNK_RECENT': parse_lnk, 'RECYCLE_BIN_INFO': parse_recycle_index_file}[item['kind']]
        parsed = parser(local)
        if parsed.get('status') != 'COMPLETED':
            ctx.warn(f'{item["path"]}: {parsed.get("error")}')
            return None
        if parsed.get('warning'):
            ctx.warn(f'{item["path"]}: {parsed["warning"]}')
        fields = {k: v for k, v in parsed.items() if k not in ('status', 'warning')}
        name = item['path'].rsplit('/', 1)[-1]
        iso = lambda t: t.isoformat() if hasattr(t, 'isoformat') else t
        row = {'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid,
               'source_path': item['path'], 'source_file': item['path'], 'parent_artifact_id': parent_id,
               'partition_offset': item['partition_offset'], 'volume_id': volume_id(item['partition_offset']),
               'timestamp': datetime.now(timezone.utc), **fields}
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
        ctx = self.ctx
        if not rows:
            return
        ctx.insert('forensic_artifacts', rows)
        events = activity_events(rows)
        ctx.insert('timeline_events', events)
        ctx.count('programs_run', sum(r['type'] == 'PROGRAM_RUN' for r in rows))
        ctx.count('recent_files', sum(r['type'] == 'RECENT_FILE' for r in rows))
        ctx.count('recycle_bin_items', sum(r['type'] == 'RECYCLE_BIN_ITEM' for r in rows))
        ctx.count('timeline_events', len(events))

    # -- browsers ------------------------------------------------------------------
    def _parse_browser(self, item, local: Path, parent_id: str):
        ctx = self.ctx
        parsed = BROWSER_PARSERS[item['kind']](local, ctx.case_id, ctx.eid)
        rows = []
        for key in ('history', 'downloads', 'cookies'):
            for row in parsed.get(key, []):
                rows.append(dict(row, browser=item.get('browser'), source_path=item['path'],
                                 source_file=item['path'], parent_artifact_id=parent_id,
                                 timestamp=datetime.now(timezone.utc)))
        for e in parsed.get('errors') or []:
            ctx.warn(f'{item["path"]}: {e}')
        ctx.insert('forensic_artifacts', rows)
        events = browser_events(rows)
        ctx.insert('timeline_events', events)
        ctx.count('browser_history', sum(r['type'] == 'BROWSER_HISTORY' for r in rows))
        ctx.count('browser_downloads', sum(r['type'] == 'BROWSER_DOWNLOAD' for r in rows))
        ctx.count('timeline_events', len(events))

    # -- USB -------------------------------------------------------------------------
    def _parse_usb(self, hive_results, setupapi_items):
        ctx = self.ctx
        if not hive_results and not setupapi_items:
            return
        devices, bias, sources = [], None, []
        for item, aid, parsed in hive_results:
            sources.append(aid)
            if parsed['status'] != 'COMPLETED':
                for e in parsed['errors']:
                    ctx.warn(f'{item["path"]}: {e}')
                continue
            devices.extend(parsed['devices'])
            if bias is None:
                bias = parsed.get('timezone_bias_minutes')
        entries = []
        # setupapi.dev.log is in local time: convert with the computer's time zone (daylight saving included).
        zone = ctx.fact('tz_probe', 'zone') if ctx.fact('tz_probe', 'source') in ('registry', 'override') else None
        for item, aid, local in setupapi_items:
            sources.append(aid)
            parsed = parse_setupapi(local, bias, zone=zone)
            entries.extend(parsed['entries'])
            if zone is None and bias is None and parsed['entries']:
                ctx.warn('setupapi.dev.log times are system local time (no SYSTEM hive time zone found)')
        merged = merge_usb_sources(devices, entries)
        now = datetime.now(timezone.utc)
        docs = [dict(d, case_id=ctx.case_id, evidence_id=ctx.eid, source_artifact_ids=sources, created_at=now)
                for d in merged]
        ctx.insert('usb_artifacts', [dict(d) for d in docs])
        events = usb_events(merged, ctx.case_id, ctx.eid)
        ctx.insert('timeline_events', events)
        ctx.count('usb_devices', len(docs))
        ctx.count('timeline_events', len(events))
