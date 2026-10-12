"""Volume Shadow Copies (module `shadow_copies`): every NTFS volume's snapshots, and what changed since each one.

For each snapshot (oldest first) its file system is read in-process (libvshadow under pytsk3, see forensic/vss.py)
and compared with the file index of the volume as it is now: files deleted, changed or added since. The records
point at the old version in the snapshot (volume id `p<start>/vss<n>`), which the file viewer reads and an
investigator can recover. Each snapshot's creation time goes on the timeline.
"""
from __future__ import annotations
import hashlib

from .. import vss
from ..source import TskImageSource, shadow_volume_id
from .base import Module

MAX_STORES = 32             # Windows keeps up to 64; the newest are compared first
MAX_WALK = 2_000_000        # entries read per snapshot
MAX_RECORDS = 200_000       # differences kept per snapshot
BATCH = 5000


class ShadowCopiesModule(Module):
    name = 'shadow_copies'
    label = 'Volume Shadow Copies'
    description = ("Windows' snapshots of each NTFS volume: when each was made, and the files deleted, changed or added "
                   'since, with the old versions readable and recoverable.')
    requires = ('fs_index',)
    weight = 10
    collections = ('shadow_files', 'timeline_events')

    def run(self, ctx):
        for key in ('shadow_copies', 'shadow_deleted', 'shadow_changed', 'shadow_added'):
            ctx.count(key, 0)
        volumes = [f for f in ctx.fact('fs_index', 'filesystems', []) or []
                   if (f.get('filesystem_type') or '').upper().startswith('NTFS') and not f.get('error')]
        found = []
        src = TskImageSource(ctx.image)
        for i, fs in enumerate(volumes):
            offset = fs['partition_offset']
            try:
                stores = vss.stores(ctx.image, offset)
            except Exception as exc:
                ctx.warn(f'Shadow copies of the volume at sector {offset} could not be read: {exc}')
                continue
            if not stores:
                continue
            if len(stores) > MAX_STORES:
                ctx.warn(f'The volume at sector {offset} has {len(stores)} shadow copies; the newest {MAX_STORES} were compared')
            current = self._current(ctx, fs['volume_id'])
            for k, store in enumerate(stores):
                ctx.progress((i + k / len(stores)) / max(1, len(volumes)), f'{fs["volume_id"]} shadow copy {store["store"]}')
                info = dict(store, volume_id=shadow_volume_id(offset, store['store']), parent_volume_id=fs['volume_id'],
                            partition_offset=offset)
                if k >= len(stores) - MAX_STORES:
                    info['counts'] = self._compare(ctx, src, info, current)
                else:
                    info['counts'] = None
                found.append(info)
                ctx.count('shadow_copies')
                ctx.insert('timeline_events', [{
                    'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': store['created'], 'type': 'SHADOW_COPY_CREATED',
                    'path': info['volume_id'], 'volume_id': info['volume_id'], 'source': 'VSS',
                    'description': f'Shadow copy {store["store"]} of the NTFS volume at sector {offset} created ({store["identifier"]})'}])
        ctx.set_fact('stores', found)

    @staticmethod
    def _current(ctx, volume_id: str) -> dict:
        q = {'evidence_id': ctx.eid, 'volume_id': volume_id, 'deleted': False, 'is_virtual': {'$ne': True},
             'container': {'$exists': False}}
        fields = {'path': 1, 'inode': 1, 'size': 1, 'mtime': 1, 'is_dir': 1}
        return {e['path'].lower(): e for e in ctx.db['fs_entries'].find(q, fields)}

    def _compare(self, ctx, src, info: dict, current: dict) -> dict:
        counts = dict.fromkeys(vss.CHANGES, 0)
        kept = dict.fromkeys(vss.CHANGES, 0)
        walked = [0]

        def snapshot():
            for entry in src.walk(info['volume_id'], times=True):
                walked[0] += 1
                if walked[0] > MAX_WALK:
                    ctx.warn(f'Shadow copy {info["store"]} of {info["parent_volume_id"]}: only the first {MAX_WALK:,} entries were compared')
                    return
                if walked[0] % 20_000 == 0:
                    ctx.checkpoint()
                yield entry

        batch = []
        for change, old, now in vss.compare(snapshot(), current):
            counts[change] += 1
            if kept[change] >= MAX_RECORDS:
                continue
            kept[change] += 1
            batch.append(self._record(ctx, info, change, old, now))
            if len(batch) >= BATCH:
                ctx.insert('shadow_files', batch)
                batch = []
        ctx.insert('shadow_files', batch)
        for change, n in counts.items():
            if n > kept[change]:
                ctx.warn(f'Shadow copy {info["store"]} of {info["parent_volume_id"]}: {n:,} files {change.lower().replace("_", " ")}, '
                         f'the first {kept[change]:,} were kept')
        ctx.count('shadow_deleted', counts['DELETED_SINCE'])
        ctx.count('shadow_changed', counts['CHANGED_SINCE'])
        ctx.count('shadow_added', counts['ADDED_SINCE'])
        return {'deleted_since': counts['DELETED_SINCE'], 'changed_since': counts['CHANGED_SINCE'],
                'added_since': counts['ADDED_SINCE'], 'entries': walked[0]}

    @staticmethod
    def _record(ctx, info, change, old, now) -> dict:
        path = (old or now)['path']
        doc = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'change': change, 'path': path, 'name': path.rsplit('/', 1)[-1],
               'is_dir': bool((old or now).get('is_dir')), 'store': info['store'], 'store_identifier': info['identifier'],
               'store_created': info['created'], 'volume_id': info['volume_id'], 'parent_volume_id': info['parent_volume_id'],
               'partition_offset': info['partition_offset'],
               'nk': hashlib.sha1(f'{info["identifier"]}|{change}|{path.lower()}'.encode()).hexdigest()}
        if old is not None:
            doc.update(inode=old['inode'], size=old.get('size'), **{k: vss.to_datetime(old.get(k)) for k in ('mtime', 'atime', 'ctime', 'crtime')})
        if now is not None:
            doc['current'] = {'entry_id': str(now['_id']), 'inode': now.get('inode'), 'size': now.get('size'), 'mtime': now.get('mtime')}
        return doc
