"""Network captures (module `network`, for pcap and pcapng evidence): the capture's span, conversations, DNS lookups,
HTTP requests, TLS server names, and the files HTTP carried, which become members of the capture in the file index
(so hash sets, YARA, ClamAV, programs, pictures and content search cover them). Parsers are in forensic/network.py.
"""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import magic

from .. import network as net
from ..source import members_root
from .base import Module
from .fileproc import process_blob

TSHARK_TIMEOUT = 6 * 3600
MAX_EVENTS = 100_000


def _nk(*parts) -> str:
    return hashlib.sha1('|'.join(str(p) for p in parts).encode()).hexdigest()


class NetworkModule(Module):
    name = 'network'
    label = 'Network capture'
    description = ('Conversations, DNS lookups, HTTP requests, TLS server names and the files HTTP carried (uploads included), '
                   'read from a pcap or pcapng capture with tshark.')
    kinds = ('capture',)
    weight = 20
    collections = ('forensic_artifacts', 'timeline_events', 'fs_entries')

    def run(self, ctx):
        self.ctx = ctx
        cap = Path(ctx.image)
        self.capname = ctx.evidence.get('filename') or cap.name
        work = ctx.work / 'network'
        work.mkdir(parents=True, exist_ok=True)
        for key in ('packets', 'conversations', 'dns_queries', 'http_requests', 'tls_server_names', 'capture_files', 'timeline_events'):
            ctx.count(key, 0)
        r = self._tshark(net.fields_argv(cap, net.FRAME_FIELDS, occurrence='f'), work / 'frames.tsv')
        if r.get('status') != 'COMPLETED':
            raise ValueError(f'tshark could not read the capture: {(r.get("stderr") or r.get("status") or "")[-500:]}')
        convs, totals = net.conversations(work / 'frames.tsv')
        info = ctx.run_tool(['capinfos', '-t', '-E', '-I', str(cap)], timeout=600)
        kind = re.search(r'File type:\s*(.+)', info.get('stdout') or '')
        encap = re.search(r'File encapsulation:\s*(.+)', info.get('stdout') or '')
        if totals['capped']:
            ctx.warn(f'Only the first {net.MAX_CONVERSATIONS:,} conversations were kept')
        now = datetime.now(timezone.utc)
        base = lambda t, nk, **f: dict({'artifact_id': str(uuid.uuid4()), 'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'type': t,
                                         'timestamp': now, 'source': 'TSHARK', 'nk': nk}, **f)
        docs = [base('CAPTURE_INFO', _nk('CAPTURE', ctx.eid), file_type=kind.group(1).strip() if kind else None,
                     encapsulation=encap.group(1).strip() if encap else None, packets=totals['packets'], bytes=totals['bytes'],
                     first=totals['first'], last=totals['last'], conversations=len(convs))]
        docs += [base('NET_CONVERSATION', _nk('CONV', c['protocol'], c['client'], c['client_port'], c['server'], c['server_port'], c['first']), **c)
                 for c in convs]
        ctx.count('packets', totals['packets'])
        ctx.count('conversations', len(convs))
        events = []

        def event(t, typ, description, **f):
            if t and len(events) < MAX_EVENTS:
                events.append({'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'timestamp': t, 'type': typ, 'description': description[:1000],
                               'source': 'TSHARK', **f})

        # DNS.
        self._tshark(net.fields_argv(cap, net.DNS_FIELDS, 'dns'), work / 'dns.tsv')
        for q in net.dns(work / 'dns.tsv'):
            docs.append(base('DNS_QUERY', _nk('DNS', q['time'], q['client'], q['name'], q['query_type']), **q))
            event(q['time'], 'DNS_QUERY', f'{q["client"]} looked up {q["name"]} ({q["query_type"]})' + (f': {", ".join(q["answers"])}' if q['answers'] else ''),
                  host=q['name'])
            ctx.count('dns_queries')
        # TLS server names.
        self._tshark(net.fields_argv(cap, net.TLS_FIELDS, 'tls.handshake.type==1'), work / 'tls.tsv')
        for h in net.tls(work / 'tls.tsv'):
            docs.append(base('TLS_HANDSHAKE', _nk('TLS', h['time'], h['client'], h['server'], h['server_port']), **h))
            event(h['time'], 'TLS_HANDSHAKE', f'{h["client"]} opened TLS to {h["server_name"] or h["server"]} ({h["server"]}:{h["server_port"]})',
                  host=h['server_name'])
            ctx.count('tls_server_names', 1 if h['server_name'] else 0)
        # HTTP requests, their responses, and the files they carried.
        self._tshark(net.fields_argv(cap, net.HTTP_REQ_FIELDS, 'http.request'), work / 'http.tsv')
        requests = {r['frame']: r for r in net.http_requests(work / 'http.tsv')}
        self._tshark(net.fields_argv(cap, ['http.request_in', 'http.response.code', 'http.content_type', 'http.content_length_header'],
                                     'http.response'), work / 'responses.tsv')
        for row in net.rows(work / 'responses.tsv', ['in', 'code', 'type', 'length']):
            req = requests.get(int(row['in'])) if row['in'].isdigit() else None
            if req:
                req.update(response_code=int(row['code']) if row['code'].isdigit() else None, response_type=row['type'] or None,
                           response_length=int(row['length']) if row['length'].isdigit() else None)
        self._tshark(net.ek_argv(cap, net.HTTP_BODY_FIELDS, 'http.file_data'), work / 'bodies.json')
        files = self._files(work / 'bodies.json', requests)
        for req in requests.values():
            req.setdefault('files', [])
            docs.append(base('HTTP_REQUEST', _nk('HTTP', req['frame'], req['time']), **req))
            uploads = [f for f in req['files'] if f['direction'] == 'request']
            event(req['time'], 'HTTP_REQUEST', f'{req["client"]} {req["method"]} {req["url"] or req["uri"]}'
                  + (f' → {req["response_code"]}' if req.get('response_code') else '')
                  + (f' (uploaded {", ".join(f["name"] for f in uploads if f.get("part"))})' if any(f.get('part') for f in uploads) else ''),
                  host=req['host'], url=req['url'])
            ctx.count('http_requests')
        # The names each server address went by (DNS answers, TLS server names, HTTP hosts), for the conversations.
        names = {}
        for d in docs:
            if d['type'] == 'DNS_QUERY':
                for a in d['answers']:
                    names.setdefault(a, set()).add(d['name'])
            elif d['type'] == 'TLS_HANDSHAKE' and d.get('server_name'):
                names.setdefault(d['server'], set()).add(d['server_name'])
            elif d['type'] == 'HTTP_REQUEST' and d.get('host'):
                names.setdefault(d['server'], set()).add(d['host'].rsplit(':', 1)[0] if d['host'].count(':') == 1 else d['host'])
        for d in docs:
            if d['type'] == 'NET_CONVERSATION':
                d['server_names'] = sorted(names.get(d['server'], ()))[:20]
        ctx.insert('fs_entries', files)
        ctx.count('capture_files', len(files))
        ctx.insert('forensic_artifacts', docs)
        ctx.insert('timeline_events', events)
        ctx.count('timeline_events', len(events))
        ctx.set_fact('capture', {'packets': totals['packets'], 'first': totals['first'], 'last': totals['last'],
                                 'file_type': kind.group(1).strip() if kind else None})

    def _tshark(self, argv, out: Path):
        r = self.ctx.run_tool(argv, timeout=TSHARK_TIMEOUT, stdout_path=out)
        if r.get('status') != 'COMPLETED':
            self.ctx.warn(f'{" ".join(argv[4:8])}: tshark {r.get("status")}: {(r.get("stderr") or "")[-300:]}')
        return r

    def _files(self, bodies: Path, requests: dict) -> list[dict]:
        """Each HTTP body (and each file of a multipart upload) saved under its SHA-256 and indexed as a member of the capture."""
        ctx = self.ctx
        store = members_root() / 'capture' / ctx.eid
        store.mkdir(parents=True, exist_ok=True)
        mime_of, describe = magic.Magic(mime=True), magic.Magic()
        out = []

        def keep(data: bytes, path: str, name: str, member: str, depth: int, modified, note: str | None):
            sha = hashlib.sha256(data).hexdigest()
            dest = store / sha
            if not dest.exists():
                dest.write_bytes(data)
            doc = {'case_id': ctx.case_id, 'evidence_id': ctx.eid, 'path': path, 'name': name, 'inode': None, 'volume_id': 'capture',
                   'partition_offset': 0, 'is_dir': False, 'is_virtual': False, 'deleted': False, 'size': len(data), 'mtime': modified,
                   'atime': None, 'ctime': None, 'crtime': None,
                   'container': {'kind': 'capture', 'parent': self.capname, 'member': member, 'depth': depth, 'encrypted': False,
                                 'packed_size': None, 'modified': modified, 'store': str(dest.relative_to(members_root())), 'note': note}}
            from ..source import open_entry
            doc.update(process_blob(open_entry(None, ctx.eid, doc), name, 'file carried in the capture', mime_of, describe,
                                    checkpoint=ctx.checkpoint, warn=lambda w: ctx.warn(f'{path}: {w}')))
            out.append(doc)
            return doc

        for b in net.http_bodies(bodies):
            req = requests.get(b['request_frame'])
            host = (req or {}).get('host') or 'unknown-host'
            name = net.body_name(b['uri'], b['content_type'], b['direction'])
            member = f'http/{b["frame"]}/{name}'
            path = f'{self.capname}!/{host}{(b["uri"] or "/").split("?", 1)[0]}' + ('' if b['direction'] == 'response' else ' (request body)')
            doc = keep(b['data'], path, name, member, 1, b['time'], 'uploaded' if b['direction'] == 'request' else None)
            ref = {'direction': b['direction'], 'name': name, 'path': path, 'sha256': doc.get('sha256'), 'size': len(b['data']),
                   'content_type': b['content_type'], 'part': False}
            for p in net.multipart_parts(b['data'], b['content_type']):
                part = keep(p['data'], f'{path}!/{p["name"]}', p['name'], f'{member}/{p["name"]}', 2, b['time'], 'uploaded file')
                if req is not None:
                    req.setdefault('files', []).append({'direction': 'request', 'name': p['name'], 'path': part['path'], 'sha256': part.get('sha256'),
                                                        'size': len(p['data']), 'content_type': p['content_type'], 'part': True})
            if req is not None:
                req.setdefault('files', []).append(ref)
            ctx.checkpoint()
        return out
