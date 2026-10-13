"""YARA scan, in-process (yara-python), of every executable, script, document and archive on the evidence.

Candidates are chosen by their real content type (from the fileproc module), not their name, so a renamed
executable is scanned too; deleted files are scanned as their content is on the disk now. DFIP's own rules and every
enabled rule set an administrator added (Administration -> Malware rules) are used, each set in its own namespace.
Matches are leads for review, not conclusions.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..rulesets import compile_rules
from ..source import open_entry
from .base import Module

RULES_FILE = Path(__file__).resolve().parents[3] / 'rules' / 'default.yar'
CATEGORIES = ('executable', 'script', 'document', 'archive')
MAX_FILE_BYTES = 32 << 20
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 8 << 30
MATCH_TIMEOUT = 60  # seconds per file


class YaraModule(Module):
    name = 'yara'
    label = 'YARA scan'
    description = "Scans every executable, script, document and archive (chosen by content, deleted ones included) with DFIP's YARA rules."
    version = '4'  # 2: in-process, chosen by content type, all users and deleted files; 3: archive members; 4: rule sets
    requires = ('fileproc',)
    follows = ('containers', 'email', 'network')  # archive members and email attachments are scanned too
    kinds = ('disk', 'logical', 'capture')  # files carried in a capture too
    weight = 10
    collections = ('forensic_artifacts',)

    def run(self, ctx):
        ctx.count('files_scanned', 0)
        ctx.count('yara_matches', 0)
        sets = list(ctx.db['yara_rulesets'].find({'enabled': True}, {'set_id': 1, 'name': 1, 'sha256': 1, 'rules': 1}))
        names = {s['set_id']: s['name'] for s in sets}
        rules = compile_rules(RULES_FILE, sets)
        ctx.set_fact('rulesets', [{'set_id': s['set_id'], 'name': s['name'], 'sha256': s.get('sha256'), 'rules': len(s.get('rules') or [])}
                                  for s in sets])
        if rules is None:
            ctx.warn('No YARA rules; the scan was skipped')
            return
        candidates = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'file_category': {'$in': list(CATEGORIES)}, 'size': {'$gt': 0}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'deleted': 1, 'file_category': 1, 'container': 1}).sort('path', 1))
        skipped = [c for c in candidates if c['size'] > MAX_FILE_BYTES]
        candidates = [c for c in candidates if c['size'] <= MAX_FILE_BYTES]
        if skipped:
            ctx.warn(f'{len(skipped)} file(s) larger than {MAX_FILE_BYTES >> 20} MiB were not scanned with YARA')
        if len(candidates) > MAX_FILES:
            ctx.warn(f'{len(candidates):,} files could be scanned with YARA; only the first {MAX_FILES:,} (by path) were')
            candidates = candidates[:MAX_FILES]
        src = ctx.source()
        scanned, total_bytes, hits = 0, 0, []
        for n, c in enumerate(candidates):
            if total_bytes + c['size'] > MAX_TOTAL_BYTES:
                ctx.warn(f'YARA scan stopped after {total_bytes >> 20} MiB ({scanned} files); the rest was not scanned')
                break
            if n % 25 == 0:
                ctx.progress(n / max(1, len(candidates)))
            try:
                data = open_entry(src, ctx.eid, c).read(0, c['size'])
                matches = rules.match(data=data, timeout=MATCH_TIMEOUT)
            except Exception as exc:
                ctx.warn(f'{c["path"]}: not scanned with YARA: {exc}')
                continue
            scanned += 1
            total_bytes += len(data)
            for m in matches:
                hits.append({'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid,
                             'type': 'MALWARE_INDICATOR', 'rule': m.rule, 'engine': 'YARA', 'ruleset': names.get(m.namespace, 'DFIP'),
                             'ruleset_id': m.namespace if m.namespace in names else None, 'original_path': c['path'], 'inode': c['inode'],
                             'volume_id': c.get('volume_id'), 'deleted': bool(c.get('deleted')), 'file_category': c.get('file_category'),
                             'description': f'YARA rule {m.rule} matched {c["path"]}' + (' (deleted)' if c.get('deleted') else ''),
                             'timestamp': datetime.now(timezone.utc), 'source': 'YARA'})
        ctx.insert('forensic_artifacts', hits)
        ctx.count('files_scanned', scanned)
        ctx.count('yara_matches', len(hits))
