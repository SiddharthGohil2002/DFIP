"""Pictures and videos: a thumbnail of every picture, camera and location metadata, when it was taken, and for videos their
details and keyframes. See app/forensic/media.py.

Pictures and videos are chosen by their real type (file processing): renamed files, deleted files (as their content is on
the disk now), archive members and email attachments are included. Thumbnails and keyframes are written under
storage/analysis/media/<evidence>/ by the SHA-256 of the file they show; results go on the file-index entry (`media`).
"""
from __future__ import annotations
import re
import shutil

from pymongo import UpdateOne

from .. import media as md
from ..source import open_entry
from ..timeline import _with_nk
from .base import Module
from .fileproc import _inode_order

MAX_PICTURES = 50_000
MAX_VIDEOS = 2_000
MAX_PICTURE_BYTES = 200 << 20
MAX_VIDEO_BYTES = 2 << 30
BATCH = md.EXIF_BATCH


def media_root():
    from pathlib import Path
    from ...core.config import settings
    return Path(settings.storage_path).resolve() / 'analysis' / 'media'


def copy_out(src, eid, e, dest, limit) -> bool:
    """Copies a file-index entry's content (a file on the evidence or a stored member) to dest; False when over limit."""
    blob = open_entry(src, eid, e)
    if blob.size > limit:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('wb') as f:
        for start in range(0, blob.size, 1 << 20):
            f.write(blob.read(start, min(1 << 20, blob.size - start)))
    return True


def _ext(name: str) -> str:
    m = re.search(r'\.([A-Za-z0-9]{1,5})$', name or '')
    return f'.{m.group(1).lower()}' if m else ''


class MediaModule(Module):
    name = 'media'
    label = 'Pictures and videos'
    description = ('A thumbnail of every picture, camera and GPS metadata (EXIF), when each picture was taken, and the length, '
                   'format and keyframes of every video (deleted files, archive members and email attachments included).')
    requires = ('fileproc',)
    follows = ('containers', 'email', 'network')  # pictures inside archives and attached to emails
    kinds = ('disk', 'logical', 'capture')  # files carried in a capture too
    weight = 15
    collections = ('timeline_events',)
    fields = {'fs_entries': ('media',)}

    def clear(self, db, evidence_id: str):
        super().clear(db, evidence_id)
        shutil.rmtree(media_root() / evidence_id, ignore_errors=True)

    def run(self, ctx):
        self.ctx = ctx
        counts = dict.fromkeys(('pictures', 'videos', 'pictures_with_gps', 'thumbnails', 'media_unreadable', 'timeline_events'), 0)
        entries = [e for e in ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'size': {'$gt': 0}, 'file_category': {'$in': ['image', 'video']},
             'hash_error': None, 'encryption': None},
            {'path': 1, 'name': 1, 'inode': 1, 'volume_id': 1, 'size': 1, 'deleted': 1, 'sha256': 1, 'file_category': 1, 'container': 1,
             'mime': 1}) if e.get('sha256')]
        entries.sort(key=lambda e: (bool(e.get('container')), _inode_order(e)))
        pictures = [e for e in entries if e['file_category'] == 'image'][:MAX_PICTURES]
        videos = [e for e in entries if e['file_category'] == 'video'][:MAX_VIDEOS]
        for kind, cap, n in (('pictures', MAX_PICTURES, len([e for e in entries if e['file_category'] == 'image'])),
                             ('videos', MAX_VIDEOS, len([e for e in entries if e['file_category'] == 'video']))):
            if n > cap:
                ctx.warn(f'Only the first {cap:,} of {n:,} {kind} were processed')
        tz = ctx.fact('tz_probe', 'zone') if ctx.fact('tz_probe', 'source') in ('registry', 'override') else None
        self.out = media_root() / ctx.eid
        self.src = ctx.source()
        work = ctx.work / 'media'
        todo = pictures + videos
        events = []
        for start in range(0, len(todo), BATCH):
            ctx.progress(start / max(1, len(todo)), f'{start:,} of {len(todo):,}')
            batch = todo[start:start + BATCH]
            local = {}
            for i, e in enumerate(batch):
                dest = work / f'{start + i:06d}{_ext(e.get("name") or e["path"])}'
                limit = MAX_PICTURE_BYTES if e['file_category'] == 'image' else MAX_VIDEO_BYTES
                try:
                    if copy_out(self.src, ctx.eid, e, dest, limit):
                        local[e['_id']] = dest
                    else:
                        ctx.warn(f'{e["path"]}: over {limit >> 20} MiB, not processed')
                except Exception as exc:
                    ctx.warn(f'{e["path"]}: could not be read: {str(exc)[:200]}')
            meta = md.exif_batch(list(local.values()), ctx.run_tool, work)
            ops = []
            for e in batch:
                p = local.get(e['_id'])
                if p is None:
                    continue
                ctx.checkpoint()
                doc = self._one(e, p, meta.get(str(p)) or {}, tz, counts)
                ops.append(UpdateOne({'_id': e['_id']}, {'$set': {'media': doc}}))
                ev = self._event(e, doc)
                if ev:
                    events.append(ev)
            if ops:
                ctx.db['fs_entries'].bulk_write(ops, ordered=False)
            shutil.rmtree(work, ignore_errors=True)
        events = _with_nk(events)
        for i in range(0, len(events), 1000):
            ctx.insert('timeline_events', events[i:i + 1000])
        counts['timeline_events'] = len(events)
        for k, v in counts.items():
            ctx.count(k, v)

    def _one(self, e, path, meta, tz, counts) -> dict:
        ctx = self.ctx
        kind = 'picture' if e['file_category'] == 'image' else 'video'
        doc = {'kind': kind, **md.metadata(meta)}
        sha = e['sha256']
        try:
            if kind == 'picture':
                thumb = self.out / f'{sha}.jpg'
                info = md.thumbnail(path, thumb) if not thumb.exists() else {
                    'width': meta.get('ImageWidth'), 'height': meta.get('ImageHeight'), 'format': meta.get('FileType')}
                doc.update(info, thumb=thumb.name)
                counts['thumbnails'] += 1
            else:
                v = md.probe(path, ctx.run_tool)
                doc['video'] = {k: x for k, x in v.items() if k not in ('width', 'height')}
                doc.update(width=v.get('width'), height=v.get('height'), format=meta.get('FileType') or (v.get('container') or '').split(',')[0])
                frames = md.keyframes(path, self.out, sha, v.get('duration'), ctx.run_tool)
                doc['frames'] = frames
                if frames:
                    doc['thumb'] = frames[0]['file']
                    counts['thumbnails'] += 1
                if v.get('recorded'):
                    doc.update(taken=v['recorded'], taken_basis='creation time in the video (UTC)')
                loc = md.iso6709(v.get('location'))
                if loc:
                    doc['gps'] = loc
        except ValueError as exc:
            doc['error'] = str(exc)[:300]
            counts['media_unreadable'] += 1
            ctx.warn(f'{e["path"]}: {doc["error"]}')
        if 'taken' not in doc:
            doc.update(md.taken_time(meta, tz))
        gps = md.gps_of(dict(meta)) if 'gps' not in doc else doc['gps']
        if gps:
            doc['gps'] = gps
            counts['pictures_with_gps'] += kind == 'picture'
        counts['pictures' if kind == 'picture' else 'videos'] += 1
        return doc

    def _event(self, e, doc):
        when = doc.get('taken')
        if not when:
            return None
        ctx = self.ctx
        kind = 'PICTURE_TAKEN' if doc['kind'] == 'picture' else 'VIDEO_RECORDED'
        what = 'Picture taken' if doc['kind'] == 'picture' else 'Video recorded'
        where = f' at {doc["gps"]["lat"]:.5f}, {doc["gps"]["lon"]:.5f}' if doc.get('gps') else ''
        cam = f' ({doc["camera"]})' if doc.get('camera') else ''
        gone = ' [deleted]' if e.get('deleted') else ''
        return {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': when, 'type': kind, 'path': e['path'],
                'description': f'{what}{cam}{where}{gone}: {e["path"]}'[:1000], 'source': 'MEDIA', 'source_file': e['path'],
                'inode': e.get('inode'), 'volume_id': e.get('volume_id')}
