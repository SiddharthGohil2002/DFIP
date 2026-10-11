"""Every file's hashes compared with the imported hash sets (known good, known bad, notable)."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pymongo import UpdateOne

from ..hashsets import lookup
from .base import Module

PRIORITY = {'KNOWN_BAD': 3, 'NOTABLE': 2, 'KNOWN_GOOD': 1}


class HashMatchModule(Module):
    name = 'hash_match'
    label = 'Hash sets'
    description = 'Compares every file hash with the imported hash sets: known-good files can be hidden, known-bad and notable files are flagged.'
    requires = ('fileproc',)
    follows = ('containers', 'email')  # archive members and email attachments are matched too
    weight = 3
    collections = ('forensic_artifacts',)
    fields = {'fs_entries': ('hash_sets', 'hash_status')}

    def run(self, ctx):
        for key in ('known_bad_files', 'notable_files', 'known_good_files'):
            ctx.count(key, 0)
        sets = [s for s in ctx.db['hash_sets'].find({'status': 'READY'}) if Path(s.get('path') or '').is_file()]
        ctx.set_fact('sets', [{'set_id': s['set_id'], 'name': s['name'], 'kind': s['kind']} for s in sets])
        if not sets:
            return
        entries = list(ctx.db['fs_entries'].find({'evidence_id': ctx.eid, 'pipeline': True, 'sha256': {'$type': 'string'}},
                                                 {'path': 1, 'inode': 1, 'volume_id': 1, 'deleted': 1, 'md5': 1, 'sha1': 1, 'sha256': 1}))
        hits: dict = {}
        for n, s in enumerate(sets):
            ctx.progress(n / len(sets), s['set_id'])
            for algo in s.get('algorithms') or []:
                found = lookup(Path(s['path']), algo, [e.get(algo) for e in entries])
                for e in entries:
                    if e.get(algo) in found:
                        mine = hits.setdefault(e['_id'], {})
                        mine.setdefault(s['set_id'], {'set_id': s['set_id'], 'name': s['name'], 'kind': s['kind'], 'algorithm': algo})
        now = datetime.now(timezone.utc)
        ops, indicators = [], []
        by_id = {e['_id']: e for e in entries}
        for eid_, matched in hits.items():
            sets_hit = sorted(matched.values(), key=lambda m: -PRIORITY[m['kind']])
            status = sets_hit[0]['kind']
            ops.append(UpdateOne({'_id': eid_}, {'$set': {'hash_sets': sets_hit, 'hash_status': status}}))
            ctx.count({'KNOWN_BAD': 'known_bad_files', 'NOTABLE': 'notable_files', 'KNOWN_GOOD': 'known_good_files'}[status])
            if status in ('KNOWN_BAD', 'NOTABLE'):
                e = by_id[eid_]
                indicators.append({
                    'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': 'HASH_SET_MATCH',
                    'kind': status, 'original_path': e.get('path'), 'inode': e.get('inode'), 'volume_id': e.get('volume_id'),
                    'deleted': bool(e.get('deleted')), 'sha256': e.get('sha256'), 'sets': sets_hit, 'timestamp': now,
                    'description': f'{e.get("path")} is in the {status.replace("_", "-").lower()} hash set '
                                   f'{", ".join(m["name"] for m in sets_hit if m["kind"] == status)}',
                    'source': 'HASH_SET'})
        if ops:
            ctx.db['fs_entries'].bulk_write(ops, ordered=False)
        ctx.insert('forensic_artifacts', indicators)
