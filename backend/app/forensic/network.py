"""Network captures (pcap, pcapng) read with tshark: conversations, DNS, HTTP requests and the files they carried, and the
server names TLS clients asked for. Nothing in a capture is replayed, rendered or contacted.

tshark is run through run_tool (no shell, limits, timeout); each pass writes its output to a file that is read line by
line, so large captures stream. HTTP bodies come from tshark's per-packet JSON (EK) as hex, with the request's method,
URL and content type; a multipart/form-data body (an upload) is split into its parts, each kept as a file of its own.
"""
from __future__ import annotations
import email.parser
import email.policy
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

MAX_CONVERSATIONS = 200_000
MAX_BODY = 64 << 20
# Read with the first occurrence of each field: the outer header (an ICMP error or a tunnel carries inner ones).
FRAME_FIELDS = ['frame.time_epoch', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'ip.proto', 'ipv6.nxt', 'tcp.srcport', 'tcp.dstport',
                'udp.srcport', 'udp.dstport', '_ws.col.Protocol']
DNS_FIELDS = ['frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'dns.id', 'dns.flags.response', 'dns.flags.rcode', 'dns.qry.name',
              'dns.qry.type', 'dns.a', 'dns.aaaa', 'dns.cname']
TLS_FIELDS = ['frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'tls.handshake.extensions_server_name',
              'tls.handshake.version']
HTTP_REQ_FIELDS = ['frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.stream',
                   'http.request.method', 'http.host', 'http.request.uri', 'http.request.full_uri', 'http.user_agent', 'http.content_type',
                   'http.content_length_header']
HTTP_BODY_FIELDS = ['frame.number', 'frame.time_epoch', 'tcp.stream', 'http.request.method', 'http.request.uri', 'http.request.full_uri',
                    'http.response.code', 'http.request_in', 'http.content_type', 'http.file_data']
DNS_TYPES = {'1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA', '12': 'PTR', '15': 'MX', '16': 'TXT', '28': 'AAAA', '33': 'SRV', '65': 'HTTPS'}


def fields_argv(capture: Path, fields: list[str], display_filter: str | None = None, occurrence: str = 'a') -> list[str]:
    argv = ['tshark', '-n', '-r', str(capture)] + (['-Y', display_filter] if display_filter else []) + \
        ['-T', 'fields', '-E', 'separator=/t', '-E', f'occurrence={occurrence}', '-E', 'aggregator=,', '-E', 'quote=n']
    for f in fields:
        argv += ['-e', f]
    return argv


def ek_argv(capture: Path, fields: list[str], display_filter: str) -> list[str]:
    argv = ['tshark', '-n', '-r', str(capture), '-Y', display_filter, '-T', 'ek']
    for f in fields:
        argv += ['-e', f]
    return argv


def rows(path: Path, fields: list[str]):
    with Path(path).open(encoding='utf-8', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < len(fields):
                parts += [''] * (len(fields) - len(parts))
            yield dict(zip(fields, parts))


def when(epoch: str):
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _ip(r, side):
    v = r.get(f'ip.{side}') or r.get(f'ipv6.{side}') or ''
    return v.split(',', 1)[0] or None  # the outer header's address


def conversations(path: Path) -> tuple[list[dict], dict]:
    """Conversations (protocol, the two ends, packets, bytes each way, first and last) and the capture's totals."""
    convs, totals = {}, {'packets': 0, 'bytes': 0, 'first': None, 'last': None}
    capped = False
    for r in rows(path, FRAME_FIELDS):
        t, size = when(r['frame.time_epoch']), int(r['frame.len'] or 0)
        totals['packets'] += 1
        totals['bytes'] += size
        if t:
            totals['first'] = t if totals['first'] is None or t < totals['first'] else totals['first']
            totals['last'] = t if totals['last'] is None or t > totals['last'] else totals['last']
        src, dst = _ip(r, 'src'), _ip(r, 'dst')
        if not src or not dst:
            continue
        proto = {'6': 'TCP', '17': 'UDP'}.get(r['ip.proto'] or r['ipv6.nxt'], 'IP')
        sp = r['tcp.srcport'] if proto == 'TCP' else r['udp.srcport'] if proto == 'UDP' else ''
        dp = r['tcp.dstport'] if proto == 'TCP' else r['udp.dstport'] if proto == 'UDP' else ''
        a, b = (src, sp), (dst, dp)
        key = (proto,) + ((a, b) if a <= b else (b, a))
        c = convs.get(key)
        if c is None:
            if len(convs) >= MAX_CONVERSATIONS:
                capped = True
                continue
            # The side that sent the first packet is the one that started it.
            c = convs[key] = {'protocol': proto, 'client': src, 'client_port': int(sp) if sp.isdigit() else None, 'server': dst,
                              'server_port': int(dp) if dp.isdigit() else None, 'packets': 0, 'bytes': 0, 'bytes_from_client': 0,
                              'bytes_from_server': 0, 'first': t, 'last': t, 'protocols': set()}
        c['packets'] += 1
        c['bytes'] += size
        c['bytes_from_client' if src == c['client'] and (sp == str(c['client_port'] or '')) else 'bytes_from_server'] += size
        c['last'] = t or c['last']
        if r['_ws.col.Protocol']:
            c['protocols'].add(r['_ws.col.Protocol'])
    out = []
    for c in convs.values():
        c['protocols'] = sorted(c['protocols'])
        out.append(c)
    totals['capped'] = capped
    return out, totals


def dns(path: Path) -> list[dict]:
    """DNS lookups: each query with its answers (matched by transaction id and client)."""
    queries, out = {}, []
    for r in rows(path, DNS_FIELDS):
        client = _ip(r, 'dst') if r['dns.flags.response'] in ('1', 'True') else _ip(r, 'src')
        key = (r['dns.id'], client, r['dns.qry.name'])
        if r['dns.flags.response'] in ('1', 'True'):
            q = queries.get(key)
            if q is None:
                q = queries[key] = {'time': when(r['frame.time_epoch']), 'client': client, 'server': _ip(r, 'src'), 'name': r['dns.qry.name'],
                                    'query_type': DNS_TYPES.get(r['dns.qry.type'], r['dns.qry.type']), 'answers': [], 'rcode': None, 'answered': False}
                out.append(q)
            q['answers'] = [x for x in (r['dns.a'].split(',') + r['dns.aaaa'].split(',') + r['dns.cname'].split(',')) if x]
            q['rcode'] = int(r['dns.flags.rcode']) if r['dns.flags.rcode'].isdigit() else None
            q['answered'] = True
        else:
            q = {'time': when(r['frame.time_epoch']), 'client': client, 'server': _ip(r, 'dst'), 'name': r['dns.qry.name'],
                 'query_type': DNS_TYPES.get(r['dns.qry.type'], r['dns.qry.type']), 'answers': [], 'rcode': None, 'answered': False}
            queries[key] = q
            out.append(q)
    return out


def tls(path: Path) -> list[dict]:
    out = []
    for r in rows(path, TLS_FIELDS):
        out.append({'time': when(r['frame.time_epoch']), 'client': _ip(r, 'src'), 'server': _ip(r, 'dst'),
                    'server_port': int(r['tcp.dstport']) if r['tcp.dstport'].isdigit() else None,
                    'server_name': r['tls.handshake.extensions_server_name'] or None, 'version': r['tls.handshake.version'] or None})
    return out


def http_requests(path: Path) -> list[dict]:
    out = []
    for r in rows(path, HTTP_REQ_FIELDS):
        out.append({'frame': int(r['frame.number']), 'time': when(r['frame.time_epoch']), 'client': _ip(r, 'src'), 'server': _ip(r, 'dst'),
                    'server_port': int(r['tcp.dstport']) if r['tcp.dstport'].isdigit() else None,
                    'stream': int(r['tcp.stream']) if r['tcp.stream'].isdigit() else None, 'method': r['http.request.method'],
                    'host': r['http.host'] or None, 'uri': r['http.request.uri'], 'url': r['http.request.full_uri'] or None,
                    'user_agent': r['http.user_agent'] or None, 'content_type': r['http.content_type'] or None,
                    'content_length': int(r['http.content_length_header']) if r['http.content_length_header'].isdigit() else None})
    return out


def http_bodies(path: Path):
    """HTTP message bodies from tshark's EK output: {frame, time, direction, uri, url, request_frame, code, content_type, data}."""
    with Path(path).open(encoding='utf-8', errors='replace') as f:
        for line in f:
            if not line.startswith('{"timestamp"'):
                continue
            try:
                layers = json.loads(line).get('layers') or {}
            except ValueError:
                continue
            g = lambda k: (layers.get(k) or [None])[0]
            hexdata = g('http_file_data') or ''
            try:
                data = bytes.fromhex(hexdata.replace(':', ''))
            except ValueError:
                continue
            if not data:
                continue
            is_request = g('http_request_method') is not None
            yield {'frame': int(g('frame_number') or 0), 'time': when(g('frame_time_epoch')), 'direction': 'request' if is_request else 'response',
                   'method': g('http_request_method'), 'uri': g('http_request_uri'), 'url': g('http_request_full_uri'),
                   'request_frame': int(g('http_request_in')) if g('http_request_in') else int(g('frame_number') or 0) if is_request else None,
                   'code': int(g('http_response_code')) if g('http_response_code') else None, 'content_type': g('http_content_type'),
                   'data': data[:MAX_BODY]}


def body_name(uri: str | None, content_type: str | None, direction: str) -> str:
    """A file name for an HTTP body: the URL's last path part, else what it is."""
    path = (uri or '').split('?', 1)[0].rstrip('/')
    name = re.sub(r'[^\w.\- ]+', '_', path.rsplit('/', 1)[-1])[:120] if path else ''
    if not name:
        name = 'index' if direction == 'response' else 'body'
    return name if direction == 'response' else f'{name} (request body)'


def multipart_parts(data: bytes, content_type: str | None) -> list[dict]:
    """The files of a multipart/form-data body (an upload): [{name, field, content_type, data}]."""
    if not content_type or 'multipart/' not in content_type.lower():
        return []
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + data)
    out = []
    for part in msg.iter_parts() if msg.is_multipart() else []:
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b''
        if filename:
            out.append({'name': re.sub(r'[\\/]+', '_', filename)[:200], 'field': part.get_param('name', header='content-disposition'),
                        'content_type': part.get_content_type(), 'data': payload})
    return out
