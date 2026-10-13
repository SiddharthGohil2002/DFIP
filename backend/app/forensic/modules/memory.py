"""Memory images (module `memory`, for MEMORY evidence): Volatility 3 reads the Windows version and the capture time
(windows.info), the processes with their tree, paths and command lines (windows.pstree, windows.cmdline), network
connections (windows.netscan), code injected into processes (windows.malware.malfind), services (windows.svcscan)
and the DLLs of the processes that stand out (windows.dlllist). Each plugin is a separate Volatility process under a
time and memory limit. Parsers and checks are in forensic/memory.py; the command and symbols in forensic/volatility.py.
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ...core.config import settings
from .. import memory as mem
from .. import volatility as vol
from .base import Module


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join(str(p) for p in parts).encode()).hexdigest()


class MemoryModule(Module):
    name = 'memory'
    label = 'Memory image'
    description = ('Windows memory images read with Volatility 3: processes (tree, paths, command lines), network connections, code '
                   'injected into processes (malfind), services, and the DLLs of the processes that stand out.')
    kinds = ('memory',)
    weight = 40
    collections = ('forensic_artifacts', 'timeline_events')

    def run(self, ctx):
        self.ctx = ctx
        self.image = Path(ctx.image)
        self.work = ctx.work / 'memory'
        self.work.mkdir(parents=True, exist_ok=True)
        for key in ('memory_processes', 'memory_processes_notable', 'memory_connections', 'memory_injections', 'memory_services',
                    'memory_dlls', 'timeline_events'):
            ctx.count(key, 0)
        ctx.progress(0.02, 'windows.info')
        data, err = self._vol('info', fatal=True)
        if data is None:
            raise ValueError(self._unreadable(err))
        info = mem.info(data)
        steps = [('pstree', 0.15), ('cmdline', 0.3), ('netscan', 0.45), ('malfind', 0.65), ('svcscan', 0.8)]
        out = {}
        for name, at in steps:
            ctx.checkpoint()
            ctx.progress(at, mem.PLUGINS[name])
            out[name] = self._vol(name)[0] or []
        procs = mem.processes(out['pstree'], out['cmdline'])
        conns = mem.connections(out['netscan'])
        injected = mem.injections(out['malfind'])
        svcs = mem.services(out['svcscan'])
        mem.assess(procs, conns, injected, svcs)
        pids = mem.notable_pids(procs)
        dlls = []
        if pids:
            ctx.checkpoint()
            ctx.progress(0.9, mem.PLUGINS['dlllist'])
            dlls = mem.dlls(self._vol('dlllist', ['--pid', *map(str, pids)])[0] or [])[:mem.MAX_DLLS]
            mem.assess_dlls(dlls, procs)
        self._store(info, procs, conns, injected, svcs, dlls)

    def _vol(self, name: str, args: list[str] | None = None, fatal: bool = False):
        """One plugin's rows, or (None, why) when Volatility could not run it."""
        ctx, plugin = self.ctx, mem.PLUGINS[name]
        out = self.work / f'{name}.json'
        r = ctx.run_tool(vol.argv(self.image, plugin, args), timeout=settings.memory_plugin_timeout, stdout_path=out,
                         memory_bytes=vol.TOOL_MEMORY, env=vol.env())
        text = out.read_text(encoding='utf-8', errors='replace') if out.exists() else ''
        if r.get('status') == 'COMPLETED':
            try:
                return json.loads(text or '[]'), None
            except ValueError:
                why = 'its output could not be read'
        else:
            why = 'it ran past the time limit' if r.get('status') == 'TIMEOUT' else mem.failure(text, r.get('stderr') or '')
        if not fatal:
            ctx.warn(f'{plugin}: Volatility could not list this: {why}')
        return None, why

    def _unreadable(self, why: str) -> str:
        """Why nothing could be read, with what to do about it."""
        if 'symbols' in why:
            return ('Volatility found the Windows kernel in this memory image, but not its symbols. Add the Windows symbol pack '
                    '(Administration > System > Memory analysis symbols), or allow downloads from Microsoft\'s symbol server '
                    '(MEMORY_SYMBOL_SERVER=true), then run the analysis again.')
        banners, _ = self._vol_raw('banners.Banners')
        linux = [b.get('Banner') for b in banners or [] if isinstance(b, dict) and str(b.get('Banner') or '').startswith('Linux version')]
        if linux:
            return (f'This is a Linux memory image ({linux[0][:160]}). Reading it needs the symbol table (ISF) of that exact kernel '
                    'in the symbols folder; DFIP lists processes, connections and injected code of Windows memory images.')
        return (f'Volatility could not read this as a Windows memory image: {why}. It reads raw captures, complete Windows crash '
                'dumps, LiME captures and VMware .vmem files; the capture may also be incomplete or damaged.')

    def _vol_raw(self, plugin: str):
        out = self.work / 'banners.json'
        r = self.ctx.run_tool(vol.argv(self.image, plugin), timeout=settings.memory_plugin_timeout, stdout_path=out,
                              memory_bytes=vol.TOOL_MEMORY, env=vol.env())
        try:
            return (json.loads(out.read_text(encoding='utf-8') or '[]') if r.get('status') == 'COMPLETED' else None), None
        except (OSError, ValueError):
            return None, None

    def _store(self, info, procs, conns, injected, svcs, dlls):
        ctx = self.ctx
        now = datetime.now(timezone.utc)
        name = ctx.evidence.get('filename') or self.image.name

        def base(t, nk, **f):
            return dict({'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': t, 'timestamp': now,
                         'source': 'VOLATILITY', 'nk': nk}, **f)
        notable = [p for p in procs if p['notable']]
        summary = {'processes': len(procs), 'processes_notable': len(notable), 'connections': len(conns),
                   'connections_external': sum(1 for c in conns if c['external']), 'injections': len(injected), 'services': len(svcs),
                   'services_notable': sum(1 for s in svcs if s['notable']), 'dlls': len(dlls)}
        docs = [base('MEMORY_INFO', _nk('INFO', ctx.eid), **{k: v for k, v in info.items() if k != 'variables'}, variables=info['variables'],
                     container=(ctx.evidence.get('memory') or {}).get('container'), volatility=vol.version(),
                     symbol_server=settings.memory_symbol_server, **summary)]
        docs += [base('MEMORY_PROCESS', _nk('PROC', p['pid'], p['created'], p['offset']), **p) for p in procs]
        docs += [base('MEMORY_CONNECTION', _nk('CONN', c['proto'], c['local_addr'], c['local_port'], c['foreign_addr'], c['foreign_port'], c['pid'],
                                               c['created'], c['offset']), **c) for c in conns]
        docs += [base('MEMORY_INJECTION', _nk('INJ', i['pid'], i['start']), **i) for i in injected]
        docs += [base('MEMORY_SERVICE', _nk('SVC', s['name'], s['offset']), **s) for s in svcs]
        docs += [base('MEMORY_DLL', _nk('DLL', d['pid'], d['base']), **d) for d in dlls]
        by_pid = {p['pid']: p for p in procs}
        # Code no file backs is a malware indicator, listed with the signature matches.
        for i in injected:
            p = by_pid.get(i['pid']) or {}
            where = p.get('path') or i.get('process') or f'PID {i["pid"]}'
            docs.append(base('MALWARE_INDICATOR', _nk('MALFIND', i['pid'], i['start']), engine='Volatility malfind', rule='Injected code',
                             original_path=where, process=i.get('process'), pid=i['pid'], region=f'{i["start"]}-{i["end"]}',
                             protection=i.get('protection'), mz=i['mz'], memory_image=name, deleted=False,
                             description=f'{i.get("process")} (PID {i["pid"]}): executable memory no file backs at {i["start"]}'
                                         + (', starting with a program header (MZ)' if i['mz'] else '') + f' (malfind, {name})'))
        events = []

        def event(t, typ, description, **f):
            if t:
                events.append({'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': t, 'type': typ, 'description': description[:1000],
                               'source': 'VOLATILITY', **f})
        event(info.get('system_time'), 'MEMORY_CAPTURED', f'Memory of the computer captured ({name}, {info.get("windows") or "Windows"})')
        for p in procs:
            label = f'{p["name"]} (PID {p["pid"]}' + (f', started by {p["parent_name"]}' if p.get('parent_name') else '') + ')'
            event(p['created'], 'MEMORY_PROCESS_STARTED', f'Process started: {label}' + (f': {p["cmdline"]}' if p.get('cmdline') else ''),
                  pid=p['pid'], notable=p['notable'])
            event(p['exited'], 'MEMORY_PROCESS_EXITED', f'Process exited: {label}', pid=p['pid'])
        for c in conns:
            if c['foreign_addr'] and c['foreign_addr'] not in ('*', '0.0.0.0', '::'):
                event(c['created'], 'MEMORY_CONNECTION', f'{c.get("owner") or "PID " + str(c["pid"])} {c["proto"]} {c["local_addr"]}:{c["local_port"]} → '
                                                         f'{c["foreign_addr"]}:{c["foreign_port"]} ({c.get("state") or "no state"})',
                      pid=c['pid'], host=c['foreign_addr'])
        ctx.insert('forensic_artifacts', docs)
        ctx.insert('timeline_events', events)
        ctx.count('memory_processes', len(procs))
        ctx.count('memory_processes_notable', len(notable))
        ctx.count('memory_connections', len(conns))
        ctx.count('memory_injections', len(injected))
        ctx.count('memory_services', len(svcs))
        ctx.count('memory_dlls', len(dlls))
        ctx.count('timeline_events', len(events))
        ctx.set_fact('memory', {'windows': info.get('windows'), 'build': info.get('build'), 'system_time': info.get('system_time'), **summary})
