"""NTFS internals for every NTFS volume of the evidence: files whose times look altered (timestomping), alternate data
streams (Zone.Identifier "Mark of the Web" decoded: where a file was downloaded from), and the USN change journal
(every file created, changed, renamed and deleted that the journal still holds, with the paths resolved through the MFT).
See app/forensic/ntfs.py for how each is read.
"""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone

from .. import ntfs
from ..source import volume_id
from ..timeline import _with_nk
from .base import Module

MAX_USN = 1_000_000
MAX_TIMELINE = 200_000
BATCH = 1000
TEXT_PREVIEW = 2000
# Journal records that become timeline events: the closing record of each change (it holds every reason of it).
TIMELINE_REASONS = {'FILE_CREATE': 'created', 'FILE_DELETE': 'deleted', 'RENAME_NEW_NAME': 'renamed', 'DATA_OVERWRITE': 'overwritten',
                    'BASIC_INFO_CHANGE': 'times or attributes changed', 'STREAM_CHANGE': 'alternate data stream added or removed'}
# Alternate data streams Windows itself writes for its own purposes.
KNOWN_STREAMS = {'zone.identifier': 'Mark of the Web', 'smartscreen': 'SmartScreen check', 'encryptable': 'Thumbs.db marker',
                 '{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}': 'Thumbnail cache (Windows XP)', 'wofcompresseddata': 'Compressed (WOF)',
                 'afp_afpinfo': 'macOS metadata', 'afp_resource': 'macOS resource fork'}


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join('' if p is None else str(p) for p in parts).encode()).hexdigest()


class NtfsModule(Module):
    name = 'ntfs'
    label = 'NTFS: timestomping, alternate data streams and USN journal'
    description = ('For NTFS volumes: files whose $STANDARD_INFORMATION times look altered compared with their $FILE_NAME times, '
                   'alternate data streams (including where downloaded files came from) and the USN change journal.')
    requires = ('fs_index',)
    weight = 10
    collections = ('forensic_artifacts', 'usn_records', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        for key in ('ntfs_volumes', 'mft_entries', 'timestomp_suspects', 'timestomp_possible', 'alternate_streams', 'downloaded_files',
                    'usn_records', 'timeline_events'):
            ctx.count(key, 0)
        volumes = [f for f in ctx.fact('fs_index', 'filesystems', []) or []
                   if (f.get('filesystem_type') or '').upper().startswith('NTFS') and f.get('fsstat_status') == 'COMPLETED']
        self.events, self.timeline_capped = [], False
        infos = []
        for n, v in enumerate(volumes):
            ctx.progress(n / max(1, len(volumes)), f'ntfs@{v["partition_offset"]}')
            try:
                infos.append(self._volume(v))
            except Exception as exc:  # one unreadable volume must not lose the others
                ctx.warn(f'NTFS volume at sector offset {v["partition_offset"]} could not be read: {str(exc)[:200]}')
        events = _with_nk(self.events)
        for i in range(0, len(events), BATCH):
            ctx.insert('timeline_events', events[i:i + BATCH])
        ctx.count('timeline_events', len(events))
        ctx.count('ntfs_volumes', len(infos))
        ctx.set_fact('volumes', infos)

    def _event(self, when, kind, description, path, **extra):
        if when is None:
            return
        if len(self.events) >= MAX_TIMELINE:
            if not self.timeline_capped:
                self.timeline_capped = True
                self.ctx.warn(f'Only the first {MAX_TIMELINE:,} NTFS events were put on the timeline')
            return
        self.events.append({'case_id': self.ctx.case_id, 'evidence_id': self.ctx.eid, 'timestamp': when, 'type': kind,
                            'description': description, 'path': path, 'source': 'NTFS', **extra})

    def _volume(self, v):
        ctx = self.ctx
        offset = v['partition_offset']
        vid = volume_id(offset)
        vol, fobj = ntfs.open_volume(ctx.image, offset * 512)
        try:
            streams_fs = {e['path']: e for e in ctx.db['fs_entries'].find(
                {'evidence_id': ctx.eid, 'volume_id': vid, 'path': {'$regex': ':[^/]+$'}}, {'path': 1, 'inode': 1})}
            base = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'partition_offset': offset, 'volume_id': vid,
                    'timestamp': datetime.now(timezone.utc)}
            rows, paths, n = [], {}, 0
            for e in ntfs.entries(vol):
                n += 1
                if n % 5000 == 0:
                    ctx.checkpoint()
                path = '/' + ntfs.windows_path(e['path_hint']).lstrip('/') if e['path_hint'] else None
                paths[e['entry']] = (e['sequence'], path or e['name'])
                if path and path.startswith('/$'):  # the file system's own files ($Extend/$UsnJrnl:$J ...)
                    continue
                level, reasons = ntfs.timestomp_reasons(e['si_raw'], e['fn'], e['path_hint'])
                if level:
                    rows.append(self._timestomp(base, e, path, level, reasons))
                for s in e['streams']:
                    rows.append(self._stream(base, e, path, s, streams_fs))
                if len(rows) >= BATCH:
                    ctx.insert('forensic_artifacts', rows)
                    rows = []
            ctx.insert('forensic_artifacts', rows)
            ctx.count('mft_entries', n)
            usn = self._journal(vol, base, paths)
            return {'partition_offset': offset, 'volume_id': vid, 'serial_number': f'{vol.serial_number:016X}' if vol.serial_number else None,
                    'name': vol.name or None, 'mft_entries': n, 'usn_records': usn, 'cluster_size': vol.cluster_block_size}
        finally:
            vol.close()
            fobj.close()

    def _timestomp(self, base, e, path, level, reasons):
        self.ctx.count('timestomp_suspects' if level == 'strong' else 'timestomp_possible')
        si, fn = e['si'], e['fn']
        row = dict(base, artifact_id=str(uuid.uuid4()), type='TIMESTOMP_SUSPECT', source='NTFS_MFT', level=level, reasons=reasons,
                   path=path, name=e['name'], entry=e['entry'], sequence=e['sequence'], allocated=e['allocated'],
                   si_created=si['created'], si_modified=si['modified'], si_changed=si['changed'], si_accessed=si['accessed'],
                   fn_created=fn['created'], fn_modified=fn['modified'], fn_changed=fn['changed'], fn_accessed=fn['accessed'],
                   nk=_nk('TIMESTOMP_SUSPECT', base['volume_id'], e['entry'], e['sequence']))
        when = si['changed'] if si['changed'] and fn['created'] and si['changed'] >= fn['created'] else fn['created']
        self._event(when, 'TIMESTOMP_SUSPECT',
                    f'Times possibly altered ({level}): {path} shows created {si["created"]:%Y-%m-%d %H:%M:%S}, '
                    f'but its name was created {fn["created"]:%Y-%m-%d %H:%M:%S}', path, entry=e['entry'])
        return row

    def _stream(self, base, e, path, s, streams_fs):
        ctx = self.ctx
        ctx.count('alternate_streams')
        head, sha = b'', None
        try:
            head, sha = ntfs.read_stream(s['stream'])
        except Exception as exc:
            ctx.warn(f'{path}:{s["name"]}: could not be read: {exc}')
        text = None
        for enc in ('utf-8', 'utf-16'):
            try:
                t = head.decode(enc)
                if t and sum(c.isprintable() or c in '\r\n\t' for c in t) >= 0.95 * len(t):
                    text = t[:TEXT_PREVIEW]
                    break
            except UnicodeDecodeError:
                continue
        full = f'{path}:{s["name"]}' if path else None
        fs = streams_fs.get(full) or {}
        kind = KNOWN_STREAMS.get((s['name'] or '').lower())
        row = dict(base, artifact_id=str(uuid.uuid4()), type='ALTERNATE_STREAM', source='NTFS_MFT', path=full, file_path=path,
                   stream=s['name'], size=s['size'], sha256=sha, text=text, kind=kind, entry=e['entry'], allocated=e['allocated'],
                   inode=fs.get('inode'), is_dir=e['is_dir'], nk=_nk('ALTERNATE_STREAM', base['volume_id'], e['entry'], s['name']))
        if (s['name'] or '').lower() == 'zone.identifier' and text:
            zone = ntfs.zone_identifier(text)
            row['zone'] = zone
            ctx.count('downloaded_files')
            src = zone.get('HostUrl') or zone.get('ReferrerUrl')
            self._event(e['si']['created'], 'FILE_DOWNLOADED',
                        f'File downloaded ({zone.get("ZoneName", "zone " + str(zone.get("ZoneId")))}): {path}' + (f' from {src}' if src else ''),
                        path, url=src)
        return row

    def _journal(self, vol, base, paths):
        """The USN journal's records, with each one's path resolved through its parent folder's MFT entry."""
        ctx = self.ctx
        batch, n, old_names = [], 0, {}

        def folder(entry, seq):
            known = paths.get(entry)
            if entry == 5:
                return ''
            if known and known[0] == seq:
                return known[1]
            return None

        for r in ntfs.usn_records(vol, MAX_USN):
            n += 1
            parent = folder(r['parent_entry'], r['parent_sequence'])
            path = f'{parent}/{r["name"]}' if parent is not None else None
            doc = dict(base, usn=r['usn'], time=r['time'], entry=r['entry'], sequence=r['sequence'], parent_entry=r['parent_entry'],
                       parent_sequence=r['parent_sequence'], name=r['name'], path=path, reasons=r['reasons'], reason_flags=r['reason_flags'],
                       file_attributes=r['file_attributes'], version=r['version'], source_info=r['source_info'],
                       nk=_nk('USN', base['volume_id'], r['usn']))
            doc.pop('timestamp', None)
            batch.append(doc)
            key = (r['entry'], r['sequence'])
            if 'RENAME_OLD_NAME' in r['reasons']:
                old_names[key] = r['name']
            if 'CLOSE' in r['reasons']:
                changes = [TIMELINE_REASONS[x] for x in r['reasons'] if x in TIMELINE_REASONS]
                if changes:
                    shown = path or f'{r["name"]} (in folder MFT entry {r["parent_entry"]})'
                    extra = f', was {old_names.pop(key)}' if 'RENAME_NEW_NAME' in r['reasons'] and key in old_names else ''
                    self._event(r['time'], 'USN_CHANGE', f'File {", ".join(changes)} (USN journal): {shown}{extra}', path,
                                entry=r['entry'], usn=r['usn'])
            if len(batch) >= BATCH:
                ctx.insert('usn_records', batch)
                batch = []
                ctx.checkpoint()
        ctx.insert('usn_records', batch)
        ctx.count('usn_records', n)
        if n >= MAX_USN:
            ctx.warn(f'Only the first {MAX_USN:,} USN journal records were read')
        return n
