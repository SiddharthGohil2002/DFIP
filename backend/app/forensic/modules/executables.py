"""Windows programs: every PE file's structure, version information and signature, why it stands out, and for the programs
that stand out most, the capabilities capa finds. See app/forensic/pe.py. Programs are chosen by their content (file
processing), so renamed ones, deleted ones, archive members and email attachments are read too. Nothing is run."""
from __future__ import annotations
import hashlib
import shutil
import uuid
from datetime import datetime, timezone

from .. import pe
from ..source import open_entry
from .base import Module
from .fileproc import _inode_order

MAX_PROGRAMS = 20_000
MAX_CAPA = 10        # programs capa reads per analysis (it takes seconds each); the rest on request
CAPA_MIN_SCORE = 3   # at least one high-severity reason, or several lesser ones
MAX_IMPORT_NAMES = 2_000


def nk(path, inode) -> str:
    return hashlib.sha1(f'EXECUTABLE|{path}|{inode}'.encode()).hexdigest()


class ExecutablesModule(Module):
    name = 'executables'
    label = 'Programs (executables)'
    description = ('Every Windows program (PE file): sections and their entropy, imports, version information, compile time and '
                   'Authenticode signature; packed, renamed and masquerading programs and suspicious imports flagged; capa '
                   'capabilities (with ATT&CK techniques) for those that stand out.')
    requires = ('fileproc',)
    follows = ('containers', 'email')  # programs inside archives and attached to emails
    weight = 10
    collections = ('forensic_artifacts',)

    def run(self, ctx):
        counts = dict.fromkeys(('programs', 'programs_flagged', 'programs_signed_valid', 'programs_signed_untrusted', 'programs_unsigned',
                                'programs_packed', 'capa_runs', 'not_pe'), 0)
        entries = list(ctx.db['fs_entries'].find(
            {'evidence_id': ctx.eid, 'pipeline': True, 'is_dir': False, 'file_category': 'executable', 'size': {'$gt': 0}, 'hash_error': None},
            {'path': 1, 'name': 1, 'inode': 1, 'volume_id': 1, 'partition_offset': 1, 'size': 1, 'deleted': 1, 'container': 1, 'sha256': 1,
             'sha1': 1, 'md5': 1, 'hash_status': 1, 'mime': 1}))
        entries.sort(key=lambda e: (bool(e.get('container')), _inode_order(e)))
        if len(entries) > MAX_PROGRAMS:
            ctx.warn(f'Only the first {MAX_PROGRAMS:,} of {len(entries):,} programs were analysed')
            entries = entries[:MAX_PROGRAMS]
        src = ctx.source()
        docs = []
        for n, e in enumerate(entries):
            ctx.progress(n / max(1, len(entries)) * 0.7, e['path'][-60:])
            ctx.checkpoint()
            if (e.get('size') or 0) > pe.MAX_BYTES:
                ctx.warn(f'{e["path"]}: over {pe.MAX_BYTES >> 20} MiB, not analysed')
                continue
            try:
                blob = open_entry(src, ctx.eid, e)
                data = blob.read(0, blob.size)
                info = pe.analyse(data)
            except ValueError:
                counts['not_pe'] += 1
                continue
            except Exception as exc:
                ctx.warn(f'{e["path"]}: could not be analysed: {str(exc)[:200]}')
                continue
            sig = pe.signature(data)
            flags = pe.assess(info, sig, e['path'])
            n_imports = 0
            for dll in list(info['imports']):
                left = MAX_IMPORT_NAMES - n_imports
                info['imports'][dll] = info['imports'][dll][:max(0, left)]
                n_imports += len(info['imports'][dll])
            doc = {'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': 'EXECUTABLE',
                   'path': e['path'], 'name': e.get('name') or e['path'].rsplit('/', 1)[-1], 'inode': e.get('inode'),
                   'volume_id': e.get('volume_id'), 'partition_offset': e.get('partition_offset'), 'deleted': bool(e.get('deleted')),
                   'container': (e.get('container') or {}).get('kind'), 'entry_id': str(e['_id']), 'size': e.get('size'),
                   'sha256': e.get('sha256'), 'sha1': e.get('sha1'), 'md5': e.get('md5'), 'hash_status': e.get('hash_status'),
                   'pe': info, 'signature': sig, 'api_groups': pe.api_groups(info['imports']), 'flags': flags,
                   'score': pe.score(flags), 'capa': None, 'timestamp': datetime.now(timezone.utc), 'source': 'PE',
                   'nk': nk(e['path'], e.get('inode'))}
            docs.append(doc)
            counts['programs'] += 1
            counts['programs_flagged'] += bool(flags and doc['score'] >= CAPA_MIN_SCORE)
            counts['programs_packed'] += any(f['code'] == 'PACKED' for f in flags)
            status = sig.get('status')
            counts['programs_signed_valid' if status == 'valid' else 'programs_unsigned' if status == 'unsigned' else 'programs_signed_untrusted'] += 1
        # capa on the programs that stand out most.
        by_id = {str(e['_id']): e for e in entries}
        top = sorted((d for d in docs if d['score'] >= CAPA_MIN_SCORE), key=lambda d: -d['score'])[:MAX_CAPA]
        work = ctx.work / 'capa'
        for i, d in enumerate(top):
            ctx.progress(0.7 + 0.3 * i / max(1, len(top)), f'capa {d["name"]}')
            ctx.checkpoint()
            local = work / f'{i:02d}.bin'
            try:
                blob = open_entry(src, ctx.eid, by_id[d['entry_id']])
                work.mkdir(parents=True, exist_ok=True)
                local.write_bytes(blob.read(0, blob.size))
                d['capa'] = pe.run_capa(local, ctx.run_tool)
                d['capa']['ran'] = 'automatically'
                counts['capa_runs'] += 1
            except Exception as exc:
                ctx.warn(f'{d["path"]}: capa could not run: {str(exc)[:200]}')
            finally:
                shutil.rmtree(work, ignore_errors=True)
        for i in range(0, len(docs), 500):
            ctx.insert('forensic_artifacts', docs[i:i + 500])
        for k, v in counts.items():
            ctx.count(k, v)
