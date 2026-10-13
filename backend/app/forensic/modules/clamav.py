"""ClamAV scan: files on the evidence (by content type: programs, scripts, documents, archives, email and unknown data;
deleted files, archive members and email attachments included) scanned with clamscan and the databases an administrator
provided (Administration -> Malware rules). Without a database the module records that and does nothing."""
from __future__ import annotations
import re
import shutil
import uuid
from datetime import datetime, timezone

from ..rulesets import clamav_databases, clamav_dir
from ..source import open_entry
from .base import Module
from .fileproc import _inode_order

CATEGORIES = ('executable', 'script', 'document', 'archive', 'email', 'other', 'text', 'database', 'shortcut')
MAX_FILE_BYTES = 64 << 20
MAX_FILES = 50_000
BATCH = 1000
FOUND = re.compile(r'^(?P<path>.+?): (?P<sig>\S.*?) FOUND$')


class ClamavModule(Module):
    name = 'clamav'
    label = 'ClamAV scan'
    description = ('Scans programs, scripts, documents, archives, email and unknown files (deleted ones, archive members and email '
                   'attachments included) with ClamAV and the signature databases imported in Administration.')
    requires = ('fileproc',)
    follows = ('containers', 'email')
    weight = 10
    collections = ('forensic_artifacts',)

    def run(self, ctx):
        ctx.count('clamav_files_scanned', 0)
        ctx.count('clamav_detections', 0)
        dbs = clamav_databases()
        ctx.set_fact('databases', [{k: v for k, v in d.items() if k != 'modified'} for d in dbs])
        if not dbs:
            ctx.set_fact('status', 'no database: import one in Administration, Malware rules')
            return
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'size': {'$gt': 0, '$lte': MAX_FILE_BYTES}, 'hash_error': None,
             'file_category': {'$in': list(CATEGORIES)}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'deleted': 1, 'container': 1, 'file_category': 1, 'sha256': 1}))
        entries.sort(key=lambda e: (bool(e.get('container')), _inode_order(e)))
        if len(entries) > MAX_FILES:
            ctx.warn(f'Only the first {MAX_FILES:,} of {len(entries):,} files were scanned with ClamAV')
            entries = entries[:MAX_FILES]
        src = ctx.source()
        work = ctx.work / 'clamav'
        hits, scanned = [], 0
        for start in range(0, len(entries), BATCH):
            ctx.progress(start / max(1, len(entries)), f'{start:,} of {len(entries):,}')
            ctx.checkpoint()
            batch, local = entries[start:start + BATCH], {}
            work.mkdir(parents=True, exist_ok=True)
            for i, e in enumerate(batch):
                p = work / f'{start + i:06d}'
                try:
                    blob = open_entry(src, ctx.eid, e)
                    with p.open('wb') as f:
                        for off in range(0, blob.size, 1 << 20):
                            f.write(blob.read(off, min(1 << 20, blob.size - off)))
                    local[str(p)] = e
                except Exception as exc:
                    ctx.warn(f'{e["path"]}: not scanned with ClamAV: {str(exc)[:200]}')
            listing = work / 'files.txt'
            listing.write_text('\n'.join(local) + '\n', encoding='utf-8')
            r = ctx.run_tool(['clamscan', '--no-summary', '--infected', '--stdout', f'--database={clamav_dir()}', '--max-filesize=64M',
                              '--max-scansize=256M', '--max-recursion=8', '-f', str(listing)], timeout=3600, memory_bytes=8 << 30,
                             max_output=5_000_000)
            if r.get('returncode') not in (0, 1):
                ctx.warn(f'clamscan failed: {(r.get("stderr") or r.get("status") or "").strip()[:300]}')
            else:
                scanned += len(local)
            for line in (r.get('stdout') or '').splitlines():
                m = FOUND.match(line.strip())
                e = local.get(m.group('path')) if m else None
                if not e:
                    continue
                sig = m.group('sig')
                hits.append({'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': 'MALWARE_INDICATOR',
                             'rule': sig, 'engine': 'ClamAV', 'original_path': e['path'], 'inode': e.get('inode'),
                             'volume_id': e.get('volume_id'), 'deleted': bool(e.get('deleted')), 'file_category': e.get('file_category'),
                             'sha256': e.get('sha256'), 'member': bool(e.get('container')),
                             'description': f'ClamAV signature {sig} matched {e["path"]}' + (' (deleted)' if e.get('deleted') else ''),
                             'timestamp': datetime.now(timezone.utc), 'source': 'CLAMAV'})
            shutil.rmtree(work, ignore_errors=True)
        ctx.insert('forensic_artifacts', hits)
        ctx.count('clamav_files_scanned', scanned)
        ctx.count('clamav_detections', len(hits))
        ctx.set_fact('status', f'scanned {scanned:,} files')
