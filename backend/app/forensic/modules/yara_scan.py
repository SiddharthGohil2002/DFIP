"""YARA scan of user-profile scripts and executables (bounded), with DFIP's rule file."""
from __future__ import annotations
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..source import volume_id
from ..tools import TOOLS, recover_file
from .base import Module

RULES_FILE = Path(__file__).resolve().parents[3] / 'rules' / 'default.yar'
SCAN_CANDIDATE_RE = re.compile(r'^/(?:Users|Documents and Settings)/.+\.(?:ps1|bat|cmd|vbs|js|hta|exe|dll|scr)$', re.I)
MAX_SCAN_FILES = 200
MAX_SCAN_BYTES = 20 * 1024 * 1024
YARA_TIMEOUT = 900


class YaraModule(Module):
    name = 'yara'
    label = 'YARA scan'
    description = "Scans scripts and executables in user profiles with DFIP's YARA rules."
    requires = ('fs_index',)
    weight = 10
    collections = ('forensic_artifacts',)

    def run(self, ctx):
        ctx.count('files_scanned', 0)
        ctx.count('yara_matches', 0)
        candidates = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'deleted': False, 'is_dir': False,
             'path': {'$regex': SCAN_CANDIDATE_RE.pattern, '$options': 'i'}, 'size': {'$lte': MAX_SCAN_BYTES}},
            {'path': 1, 'inode': 1, 'partition_offset': 1}).limit(MAX_SCAN_FILES))
        if not candidates or not RULES_FILE.is_file():
            return
        scan_dir = ctx.work / 'yara-scan'
        by_local = {}
        for n, c in enumerate(candidates):
            ctx.progress(n / len(candidates) * 0.5, 'extracting')
            local = scan_dir / f'{n:04d}' / c['path'].rsplit('/', 1)[-1]
            if recover_file(ctx.image, c['inode'], local, c['partition_offset']).get('status') == 'COMPLETED':
                by_local[str(local)] = c
        yara = shutil.which(TOOLS['yara'])
        if not yara:
            ctx.warn('YARA is not installed; malware signature scan skipped')
            return
        ctx.progress(0.5, 'scanning')
        r = ctx.run_tool([yara, '-r', '-w', str(RULES_FILE), str(scan_dir)], timeout=YARA_TIMEOUT)
        if r['status'] != 'COMPLETED':
            ctx.warn(f'YARA scan did not complete ({r["status"]}): {(r.get("stderr") or "")[:300]}')
        hits = []
        for line in (r.get('stdout') or '').splitlines():
            rule, _, target = line.partition(' ')
            c = by_local.get(target.strip())
            if not c:
                continue
            hits.append({'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid,
                         'type': 'MALWARE_INDICATOR', 'rule': rule, 'original_path': c['path'], 'inode': c['inode'],
                         'volume_id': volume_id(c['partition_offset']),
                         'description': f'YARA rule {rule} matched {c["path"]}',
                         'timestamp': datetime.now(timezone.utc), 'source': 'YARA'})
        ctx.insert('forensic_artifacts', hits)
        ctx.count('files_scanned', len(by_local))
        ctx.count('yara_matches', len(hits))
