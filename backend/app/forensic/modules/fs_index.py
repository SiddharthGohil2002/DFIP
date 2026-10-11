"""File system index: partition table (mmls), then each file system's full listing (fls bodyfile), including
deleted entries, feeding the file index (fs_entries) and the MACB file timeline."""
from __future__ import annotations
import re
import shutil

from ..filesystem import iter_bodyfile
from ..source import volume_id
from ..timeline import macb_events
from ..tools import TOOLS, filesystem_stats, parse_mmls
from .base import Module

BATCH = 5000
FLS_TIMEOUT = 6 * 3600


def filesystem_type(stats_stdout: str):
    m = re.search(r'File System Type:\s*(.+)', stats_stdout or '')
    return m.group(1).strip() if m else None


def select_offsets(mmls: dict) -> list[int]:
    offsets = [p['start'] for p in mmls.get('partitions', [])
               if not p.get('is_meta') and not p.get('is_unallocated') and 'extended' not in p.get('description', '').lower()]
    # No partition table (a bare filesystem image): the filesystem starts at sector 0.
    return offsets or [0]


class FsIndexModule(Module):
    name = 'fs_index'
    label = 'File system index'
    description = 'Partition table, every file and folder including deleted entries, and the file timeline (MACB).'
    weight = 45
    collections = ('fs_entries', 'timeline_events')

    def run(self, ctx):
        mmls = parse_mmls(ctx.image)
        offsets = select_offsets(mmls)
        ctx.set_fact('partitions', mmls.get('partitions', []))
        ctx.set_fact('offsets', offsets)
        filesystems = []
        for i, offset in enumerate(offsets):
            ctx.progress(i / len(offsets), str(offset))
            filesystems.append(self._index(ctx, offset, i, len(offsets)))
        ctx.set_fact('filesystems', filesystems)
        for key in ('files', 'deleted_files', 'timeline_events'):
            ctx.count(key, 0)

    def _index(self, ctx, offset: int, i: int, n: int) -> dict:
        stats = filesystem_stats(ctx.image, offset)
        fs_type = filesystem_type(stats.get('stdout', ''))
        vid = volume_id(offset)
        info = {'partition_offset': offset, 'volume_id': vid, 'filesystem_type': fs_type, 'fsstat_status': stats.get('status')}
        if stats.get('status') != 'COMPLETED':
            info['error'] = (stats.get('stderr') or '').strip()[:500]
            ctx.warn(f'No readable filesystem at sector offset {offset}')
            return info
        bodyfile = ctx.work / f'fls-offset-{offset}.body'
        fls = shutil.which(TOOLS['sleuthkit_fls']) or TOOLS['sleuthkit_fls']
        argv = [fls, '-r', '-m', '/'] + (['-o', str(offset)] if offset else []) + [str(ctx.image)]
        r = ctx.run_tool(argv, timeout=FLS_TIMEOUT, stdout_path=bodyfile)
        info.update(bodyfile=str(bodyfile), fls_status=r.get('status'))
        if r.get('status') != 'COMPLETED':
            info['error'] = (r.get('stderr') or r.get('status') or '')[:500]
            ctx.warn(f'Listing the filesystem at sector offset {offset} failed: {info["error"]}')
            return info
        entries, events = [], []
        files = deleted = 0
        for k, entry in enumerate(iter_bodyfile(bodyfile)):
            if entry['fn_attr']:
                # NTFS $FILE_NAME times duplicate the file's own entry; they stay in the
                # bodyfile for mactime but are not indexed or counted as separate files.
                continue
            if not entry['is_virtual']:
                files += 1
                deleted += entry['deleted']
            entries.append(dict(entry, case_id=ctx.case_id, evidence_id=ctx.eid, partition_offset=offset,
                                volume_id=vid, filesystem_type=fs_type))
            events.extend(macb_events(entry, ctx.case_id, ctx.eid, offset))
            if len(entries) >= BATCH:
                ctx.insert('fs_entries', entries)
                entries = []
                ctx.checkpoint()
            if len(events) >= BATCH:
                ctx.insert('timeline_events', events)
                ctx.count('timeline_events', len(events))
                events = []
        ctx.insert('fs_entries', entries)
        ctx.insert('timeline_events', events)
        ctx.count('timeline_events', len(events))
        ctx.count('files', files)
        ctx.count('deleted_files', deleted)
        info.update(files=files, deleted_files=deleted)
        return info
