"""Archives and embedded files: the members of every container on the evidence, as file-index entries.

Each member becomes an `fs_entries` record whose path is the container's path, '!/', and the member's name
(for example /Users/alice/Documents/export-backup.zip!/payroll-export.csv), with a `container` field saying
where it came from. Extracted members are hashed and typed like any other file, so hash sets, YARA, content
search and found data cover them too; a container found inside a container is opened as well (two levels).
"""
from __future__ import annotations
import shutil

from ..containers import MAX_DEPTH, Budget, kind_for, read_container
from ..source import BlobRef, TskImageSource, members_root, open_entry
from .base import Module
from .fileproc import _inode_order, process_blob

CANDIDATE_CATEGORIES = ('archive', 'document')


class MembersModule(Module):
    name = 'containers'
    label = 'Archives and embedded files'
    description = ('Members of ZIP, 7z, RAR, tar and other archives, pictures and objects embedded in Office documents, and PDF '
                   'attachments (two levels deep), hashed and typed like other files. Encrypted members are listed.')
    requires = ('fileproc',)
    weight = 20
    collections = ('fs_entries',)          # only its own member records (pipeline_module='containers')
    fields = {'fs_entries': ('archive',)}  # what each container holds, on the container's record

    def clear(self, db, evidence_id: str):
        super().clear(db, evidence_id)
        shutil.rmtree(members_root() / evidence_id, ignore_errors=True)

    def run(self, ctx):
        import magic
        self.mime_of, self.describe = magic.Magic(mime=True), magic.Magic()
        self.ctx = ctx
        self.src = TskImageSource(ctx.image)
        self.budget = Budget()
        self.out_dir = members_root() / ctx.eid / ctx.run_id
        self.counts = dict.fromkeys(('containers_opened', 'members_found', 'members_extracted', 'members_encrypted',
                                     'members_not_extracted'), 0)
        entries = [e for e in ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'container': {'$exists': False}, 'size': {'$gt': 0},
             'file_category': {'$in': list(CANDIDATE_CATEGORIES)}},
            {'path': 1, 'inode': 1, 'volume_id': 1, 'partition_offset': 1, 'deleted': 1, 'size': 1, 'mime': 1, 'encryption': 1})
            if kind_for(e)]
        entries.sort(key=_inode_order)
        for n, e in enumerate(entries):
            ctx.progress(n / max(1, len(entries)), e['path'][-60:])
            self.budget.start_container()
            try:
                blob = self.src.open(BlobRef(ctx.eid, e.get('volume_id') or 'p0', inode=e['inode']))
            except Exception as exc:
                ctx.warn(f'{e["path"]}: could not be read: {exc}')
                continue
            summary = self._open(e, blob, kind_for(e), depth=1, top=e)
            ctx.db['fs_entries'].update_one({'_id': e['_id']}, {'$set': {'archive': summary}})
        for k, v in self.counts.items():
            ctx.count(k, v)

    def _open(self, parent: dict, blob, kind: str, depth: int, top: dict) -> dict:
        ctx = self.ctx
        try:
            members, names_encrypted = read_container(kind, blob, self.out_dir, self.budget, ctx.run_tool, ctx.work)
        except Exception as exc:
            ctx.warn(f'{parent["path"]}: could not be opened as {kind}: {str(exc)[:200]}')
            return {'kind': kind, 'error': str(exc)[:300]}
        self.counts['containers_opened'] += 1
        if names_encrypted:
            ctx.warn(f'{parent["path"]}: the archive is encrypted, including its member names; nothing could be listed')
        docs = []
        for m in members:
            doc = {
                'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'path': f'{parent["path"]}!/{m.name}',
                'name': m.name.rsplit('/', 1)[-1], 'inode': top.get('inode'), 'volume_id': top.get('volume_id'),
                'partition_offset': top.get('partition_offset'), 'is_dir': False, 'is_virtual': False,
                'deleted': bool(top.get('deleted')), 'size': m.size, 'mtime': None, 'atime': None, 'ctime': None, 'crtime': None,
                'container': {'kind': kind, 'parent': parent['path'], 'member': m.name, 'depth': depth, 'encrypted': m.encrypted,
                              'packed_size': m.packed, 'modified': m.modified,
                              'store': str(m.store.relative_to(members_root())) if m.store else None, 'note': m.note},
            }
            self.counts['members_found'] += 1
            if m.store:
                self.counts['members_extracted'] += 1
                doc.update(process_blob(open_entry(self.src, ctx.eid, doc), doc['name'], f'member of {parent["path"]}',
                                        self.mime_of, self.describe, checkpoint=ctx.checkpoint,
                                        warn=lambda msg, p=doc['path']: ctx.warn(f'{p}: {msg}')))
                nested = kind_for(doc)
                if nested and depth < MAX_DEPTH:
                    doc['archive'] = self._open(doc, open_entry(self.src, ctx.eid, doc), nested, depth + 1, top)
                elif nested:
                    doc['archive'] = {'kind': nested, 'note': f'inside {depth} containers: not opened'}
            else:
                self.counts['members_encrypted' if m.encrypted else 'members_not_extracted'] += 1
                doc['hash_basis'] = f'not extracted: {m.note}'
                if m.encrypted:
                    doc['encryption'] = {'kind': 'ZIP' if kind == 'zip' else 'ARCHIVE',
                                         'detail': 'Encrypted archive member: listed, content not extracted'}
            docs.append(doc)
        ctx.insert('fs_entries', docs)
        return {'kind': kind, 'members': len(members), 'extracted': sum(1 for m in members if m.store),
                'encrypted': sum(1 for m in members if m.encrypted), 'names_encrypted': names_encrypted,
                'not_extracted': sum(1 for m in members if not m.store and not m.encrypted)}
