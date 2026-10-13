"""Indicators of compromise of a case, for sharing: files that malware signatures, known-bad hash sets or VirusTotal flag,
programs that stand out, and where files were uploaded to (from network captures). Exported as a STIX 2.1 bundle (built
and checked with stix2) or a MISP event. Each indicator says why it was included and which records it rests on."""
from __future__ import annotations
import ipaddress
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..database import get_db

TLP = ('clear', 'green', 'amber', 'red')
MALICIOUS, ANOMALOUS = 'malicious-activity', 'anomalous-activity'
MAX_PER_SOURCE = 5000


def _hostname(host: str | None) -> str | None:
    """The name or address in an HTTP Host header (without the port)."""
    return urlsplit('//' + host).hostname if host else None


def _host_kind(host: str) -> str:
    try:
        return 'ipv6' if ipaddress.ip_address(host.strip('[]')).version == 6 else 'ipv4'
    except ValueError:
        return 'domain'


class _Collector:
    def __init__(self):
        self.items: dict[tuple, dict] = {}

    def add(self, kind: str, value: str, reason: str, verdict: str, ref: dict, first_seen=None, **extra):
        if not value:
            return
        key = (kind, value.lower() if kind != 'url' else value)
        it = self.items.setdefault(key, {'kind': kind, 'value': value, 'verdict': verdict, 'reasons': [], 'refs': [], 'first_seen': None})
        if reason not in it['reasons']:
            it['reasons'].append(reason)
        if len(it['refs']) < 20:
            it['refs'].append(ref)
        if verdict == MALICIOUS:
            it['verdict'] = MALICIOUS
        for k, v in extra.items():
            if v and not it.get(k):
                it[k] = v
        if isinstance(first_seen, datetime) and (it['first_seen'] is None or first_seen < it['first_seen']):
            it['first_seen'] = first_seen


def collect(case_id: str) -> list[dict]:
    """The case's indicators, malicious ones first, each with its reasons and the records behind it."""
    db = get_db()
    art, fs = db['forensic_artifacts'], db['fs_entries']
    C = _Collector()

    def ref(d: dict, col: str = 'forensic_artifacts') -> dict:
        return {'collection': col, 'id': str(d['_id']), 'type': d.get('type'), 'evidence_id': d.get('evidence_id')}

    def file_hashes(d: dict) -> dict:
        if d.get('sha256'):
            return {k: d.get(k) for k in ('sha256', 'sha1', 'md5')}
        e = fs.find_one({'evidence_id': d.get('evidence_id'), 'inode': d.get('inode'), 'volume_id': d.get('volume_id'),
                         'path': d.get('original_path') or d.get('path')}, {'sha256': 1, 'sha1': 1, 'md5': 1})
        return {k: (e or {}).get(k) for k in ('sha256', 'sha1', 'md5')}

    def add_file(d: dict, reason: str, verdict: str):
        h = file_hashes(d)
        path = d.get('original_path') or d.get('path') or ''
        C.add('file', h.get('sha256'), reason, verdict, ref(d), d.get('timestamp'), sha1=h.get('sha1'), md5=h.get('md5'),
              name=path.rsplit('/', 1)[-1] or None, path=path or None)

    for d in art.find({'case_id': case_id, 'type': 'MALWARE_INDICATOR'}).limit(MAX_PER_SOURCE):
        add_file(d, f'{d.get("engine") or "YARA"} signature {d.get("rule")} matched {d.get("original_path")}', MALICIOUS)
    for d in art.find({'case_id': case_id, 'type': 'HASH_SET_MATCH', 'kind': 'KNOWN_BAD'}).limit(MAX_PER_SOURCE):
        sets = ', '.join(s['name'] for s in d.get('sets') or [] if s.get('kind') == 'KNOWN_BAD')
        add_file(d, f'in the known-bad hash set {sets}', MALICIOUS)
    for d in art.find({'case_id': case_id, 'type': 'EXECUTABLE', '$or': [{'score': {'$gte': 3}}, {'vt.malicious': {'$gt': 0}}]}).limit(MAX_PER_SOURCE):
        if (d.get('vt') or {}).get('malicious'):
            add_file(d, f'VirusTotal: {d["vt"]["malicious"]} engines flag it as malicious', MALICIOUS)
        if (d.get('score') or 0) >= 3:
            why = '; '.join(f.get('label') for f in d.get('flags') or [] if f.get('label'))
            add_file(d, f'program stands out: {why or "flagged"}', ANOMALOUS)
    for d in art.find({'case_id': case_id, 'type': 'THREAT_INTEL_HASH', 'data.virustotal.malicious': {'$gt': 0}}).limit(MAX_PER_SOURCE):
        h = (d.get('data') or {}).get('indicator') or ''
        if len(h) == 64:
            C.add('file', h, f'VirusTotal: {d["data"]["virustotal"]["malicious"]} engines flag it as malicious (looked up)', MALICIOUS, ref(d), d.get('timestamp'))
    for d in art.find({'case_id': case_id, 'type': 'HTTP_REQUEST', 'files': {'$elemMatch': {'direction': 'request', 'part': True}}}).limit(MAX_PER_SOURCE):
        names = ', '.join(f['name'] for f in d['files'] if f.get('part') and f.get('direction') == 'request' and f.get('name'))
        reason = f'{d.get("client")} uploaded {names or "a file"} to it (network capture {d.get("evidence_id")})'
        host = _hostname(d.get('host')) or urlsplit(d.get('url') or '').hostname
        if d.get('url'):
            C.add('url', d['url'], reason, ANOMALOUS, ref(d), d.get('time'))
        for h in {host, d.get('server')} - {None, ''}:
            C.add(_host_kind(h), h, reason, ANOMALOUS, ref(d), d.get('time'))
    out = sorted(C.items.values(), key=lambda x: (x['verdict'] != MALICIOUS, x['kind'], x['value']))
    for x in out:  # stored times are UTC (naive ones too)
        t = x['first_seen']
        x['first_seen'] = (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat() if t else None
    return out


def _quote(v: str) -> str:
    return v.replace('\\', '\\\\').replace("'", "\\'")


def _pattern(x: dict) -> str:
    if x['kind'] == 'file':
        parts = [f"file:hashes.'SHA-256' = '{x['value'].lower()}'"]
        parts += [f"file:hashes.'{label}' = '{x[k].lower()}'" for k, label in (('sha1', 'SHA-1'), ('md5', 'MD5')) if x.get(k)]
        return '[' + ' OR '.join(parts) + ']'
    obj = {'domain': 'domain-name', 'url': 'url', 'ipv4': 'ipv4-addr', 'ipv6': 'ipv6-addr'}[x['kind']]
    return f"[{obj}:value = '{_quote(x['value'])}']"


def stix_bundle(case: dict, items: list[dict], tlp: str, exported_by: dict) -> str:
    import stix2
    marking = {'clear': stix2.TLP_WHITE, 'green': stix2.TLP_GREEN, 'amber': stix2.TLP_AMBER, 'red': stix2.TLP_RED}[tlp]
    now = datetime.now(timezone.utc)
    org = stix2.Identity(name='DFIP', identity_class='system', description=f'Exported by {exported_by.get("name")}', object_marking_refs=[marking])
    objects = [org]
    for x in items:
        name = {'file': f'File {x.get("name") or x["value"][:16]}', 'url': f'URL {x["value"][:200]}', 'domain': f'Domain {x["value"]}',
                'ipv4': f'IP address {x["value"]}', 'ipv6': f'IP address {x["value"]}'}[x['kind']]
        objects.append(stix2.Indicator(
            name=name, description='; '.join(x['reasons'])[:4000], pattern=_pattern(x), pattern_type='stix',
            valid_from=datetime.fromisoformat(x['first_seen']) if x['first_seen'] else now, indicator_types=[x['verdict']], created_by_ref=org.id, object_marking_refs=[marking],
            labels=[f'dfip-case:{case["case_id"]}'],
            external_references=[{'source_name': 'DFIP', 'external_id': f'{case["case_id"]}:{r["collection"]}:{r["id"]}',
                                  'description': f'{r.get("type")} in {r.get("evidence_id")}'} for r in x['refs'][:5]]))
    report = stix2.Report(name=f'{case["case_id"]}: {case.get("name")} - indicators', published=now, report_types=['indicator'],
                          description=f'{len(items)} indicators from DFIP case {case["case_id"]}', created_by_ref=org.id,
                          object_refs=[o.id for o in objects[1:]] or [org.id], object_marking_refs=[marking])
    return stix2.Bundle(objects=objects + [report], allow_custom=False).serialize(pretty=True)


MISP_THREAT_LEVEL = {'malicious': '1', 'anomalous': '3'}  # 1 high, 3 low


def misp_event(case: dict, items: list[dict], tlp: str, exported_by: dict) -> dict:
    now = datetime.now(timezone.utc)
    ts = str(int(now.timestamp()))
    attrs = []

    def attr(type_: str, category: str, value: str, x: dict):
        attrs.append({'uuid': str(uuid.uuid4()), 'type': type_, 'category': category, 'value': value, 'to_ids': x['verdict'] == MALICIOUS,
                      'comment': '; '.join(x['reasons'])[:1000], 'timestamp': ts, 'distribution': '5', 'disable_correlation': False,
                      'Tag': [{'name': 'dfip:verdict="' + x['verdict'] + '"'}]})
    for x in items:
        if x['kind'] == 'file':
            attr('filename|sha256' if x.get('name') else 'sha256', 'Payload delivery', f'{x["name"]}|{x["value"]}' if x.get('name') else x['value'], x)
            for k in ('sha1', 'md5'):
                if x.get(k):
                    attr(k, 'Payload delivery', x[k], x)
        elif x['kind'] == 'url':
            attr('url', 'Network activity', x['value'], x)
        elif x['kind'] == 'domain':
            attr('domain', 'Network activity', x['value'], x)
        else:
            attr('ip-dst', 'Network activity', x['value'], x)
    malicious = any(x['verdict'] == MALICIOUS for x in items)
    return {'Event': {
        'uuid': str(uuid.uuid4()), 'info': f'{case["case_id"]}: {case.get("name")} - indicators from DFIP (exported by {exported_by.get("name")})', 'date': now.strftime('%Y-%m-%d'),
        'timestamp': ts, 'published': False, 'analysis': '1', 'distribution': '0',
        'threat_level_id': MISP_THREAT_LEVEL['malicious' if malicious else 'anomalous'],
        'Orgc': {'name': 'DFIP'}, 'Tag': [{'name': f'tlp:{"white" if tlp == "clear" else tlp}'}, {'name': f'dfip:case="{case["case_id"]}"'}],
        'Attribute': attrs,
    }}
