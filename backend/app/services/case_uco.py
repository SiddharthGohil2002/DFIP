"""The case as CASE/UCO JSON-LD (Cyber-investigation Analysis Standard Expression, ontology 1.4): the investigation, each
evidence item as a file with its size and hashes, its provenance record (exhibit number), the actions on it from the
chain of custody (registration, verification, analysis, recovery) with who did them and with which tool, recovered files
as files derived from the evidence, and approved findings as annotations of the evidence they rest on. The output is
checked with case_validate (case-utils) in the tests."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone

from ..database import get_db

CONTEXT = {
    'kb': 'urn:dfip:kb:',
    'case-investigation': 'https://ontology.caseontology.org/case/investigation/',
    'uco-action': 'https://ontology.unifiedcyberontology.org/uco/action/',
    'uco-core': 'https://ontology.unifiedcyberontology.org/uco/core/',
    'uco-identity': 'https://ontology.unifiedcyberontology.org/uco/identity/',
    'uco-observable': 'https://ontology.unifiedcyberontology.org/uco/observable/',
    'uco-tool': 'https://ontology.unifiedcyberontology.org/uco/tool/',
    'uco-types': 'https://ontology.unifiedcyberontology.org/uco/types/',
    'uco-vocabulary': 'https://ontology.unifiedcyberontology.org/uco/vocabulary/',
    'xsd': 'http://www.w3.org/2001/XMLSchema#',
}
NAMESPACE = uuid.UUID('6f1d3c52-8a4e-5b7d-9c0e-2d4f6a8b1c3e')  # deterministic node IRIs: the same record always gets the same one
HASHES = (('md5', 'MD5'), ('sha1', 'SHA1'), ('sha256', 'SHA256'), ('sha512', 'SHA512'))
ACTIONS = {'EVIDENCE_REGISTERED': 'Registered the evidence and computed its hashes', 'EVIDENCE_VERIFIED': 'Verified the evidence against its hashes',
           'ANALYSIS_INTEGRITY_CHECK': 'Checked the evidence before analysis', 'FILE_RECOVERED': 'Recovered a file from the evidence',
           'EVIDENCE_DELETED': 'Deleted the evidence', 'PACKAGE_UNPACKED': 'Unpacked the collected files'}


def _iri(kind: str, *parts) -> str:
    return f'kb:{kind}-' + str(uuid.uuid5(NAMESPACE, '|'.join(str(p) for p in parts)))


def _dt(v) -> dict | None:
    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            return None
    if not isinstance(v, datetime):
        return None
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return {'@type': 'xsd:dateTime', '@value': v.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}


def _file(iri: str, name: str | None, size, hashes: dict) -> dict:
    facets = [{'@id': _iri('file-facet', iri), '@type': 'uco-observable:FileFacet', **({'uco-observable:fileName': name} if name else {}),
               **({'uco-observable:sizeInBytes': {'@type': 'xsd:integer', '@value': int(size)}} if isinstance(size, int) else {})}]
    hs = [{'@id': _iri('hash', iri, k), '@type': 'uco-types:Hash', 'uco-types:hashMethod': label,
           'uco-types:hashValue': {'@type': 'xsd:hexBinary', '@value': hashes[k].upper()}} for k, label in HASHES if hashes.get(k)]
    if hs:
        facets.append({'@id': _iri('content-facet', iri), '@type': 'uco-observable:ContentDataFacet', 'uco-observable:hash': hs})
    return {'@id': iri, '@type': 'uco-observable:File', 'uco-core:hasFacet': facets}


def export(case_id: str, exported_by: dict) -> dict:
    db = get_db()
    case = db['cases'].find_one({'case_id': case_id})
    graph = []
    tool = {'@id': _iri('tool', 'DFIP'), '@type': 'uco-tool:Tool', 'uco-core:name': 'DFIP', 'uco-tool:version': '2.1.0',
            'uco-tool:toolType': 'Digital forensics platform'}
    graph.append(tool)
    people = {}

    def person(name: str | None) -> dict | None:
        if not name:
            return None
        if name not in people:
            people[name] = {'@id': _iri('identity', name), '@type': 'uco-identity:Identity', 'uco-core:name': name}
            graph.append(people[name])
        return {'@id': people[name]['@id']}

    files, records = {}, []
    for e in db['evidence'].find({'case_id': case_id}).sort('evidence_id', 1):
        f = _file(_iri('evidence', e['evidence_id']), e.get('filename'), e.get('size'), {k: e.get(k) for k, _ in HASHES})
        files[e['evidence_id']] = f
        graph.append(f)
        rec = {'@id': _iri('provenance', e['evidence_id']), '@type': 'case-investigation:ProvenanceRecord',
               'case-investigation:exhibitNumber': e['evidence_id'], 'uco-core:description': f'{e.get("filename")} ({e.get("format")})',
               'uco-core:object': [{'@id': f['@id']}]}
        records.append(rec)
        graph.append(rec)
    recovered = {}  # artifact_id: (recovered file, its record)
    for r in db['forensic_artifacts'].find({'case_id': case_id, 'type': 'RECOVERED_FILE', 'evidence_id': {'$in': list(files)}}).sort('timestamp', 1):
        f = _file(_iri('recovered', r['artifact_id']), r.get('filename'), r.get('size'), {'sha256': r.get('sha256')})
        recovered[r['artifact_id']] = (f, r)
        graph.append(f)
    actions, linked = [], set()
    for c in db['chain_of_custody'].find({'case_id': case_id}).sort('timestamp', 1):
        if c.get('evidence_id') not in files:
            continue
        a = {'@id': _iri('action', str(c['_id'])), '@type': 'case-investigation:InvestigativeAction',
             'uco-core:name': ACTIONS.get(c.get('action'), (c.get('action') or 'Action').replace('_', ' ').capitalize()),
             'uco-core:description': ' '.join(x for x in (c.get('action'), c.get('original_path') or c.get('reason') or c.get('detail'),
                                                          c.get('status') or c.get('result')) if x)[:2000],
             'uco-action:instrument': {'@id': tool['@id']}, 'uco-action:object': [{'@id': files[c['evidence_id']]['@id']}]}
        if c.get('action') == 'FILE_RECOVERED' and c.get('artifact_id') in recovered:
            a['uco-action:result'] = [{'@id': recovered[c['artifact_id']][0]['@id']}]
            linked.add(c['artifact_id'])
        when = _dt(c.get('timestamp'))
        if when:
            a['uco-action:startTime'] = when
            a['uco-action:endTime'] = when
        who = person(c.get('user_name'))
        if who:
            a['uco-action:performer'] = who
        actions.append(a)
        graph.append(a)
    for j in db['jobs'].find({'type': 'FORENSIC_ANALYSIS', 'payload.evidence_id': {'$in': list(files)}, 'status': 'COMPLETED'}).sort('created_at', 1):
        eid = j['payload']['evidence_id']
        a = {'@id': _iri('analysis', j['job_id']), '@type': 'case-investigation:InvestigativeAction',
             'uco-core:name': f'Forensic analysis ({(j.get("payload") or {}).get("profile") or "standard"} profile)',
             'uco-core:description': f'{j["job_id"]}: modules {", ".join((((j.get("result") or {}).get("summary") or {}).get("plan")) or [])}'[:2000],
             'uco-action:instrument': {'@id': tool['@id']}, 'uco-action:object': [{'@id': files[eid]['@id']}]}
        for k, prop in (('started_at', 'uco-action:startTime'), ('finished_at', 'uco-action:endTime')):
            if _dt(j.get(k)):
                a[prop] = _dt(j.get(k))
        actions.append(a)
        graph.append(a)
    for aid, (f, r) in recovered.items():  # recovered files without a custody record of their recovery
        if aid in linked:
            continue
        a = {'@id': _iri('recovery', aid), '@type': 'case-investigation:InvestigativeAction',
             'uco-core:name': 'Recovered a file from the evidence', 'uco-core:description': f'{r.get("original_path") or r.get("filename")} recovered from {r["evidence_id"]}',
             'uco-action:instrument': {'@id': tool['@id']}, 'uco-action:object': [{'@id': files[r['evidence_id']]['@id']}],
             'uco-action:result': [{'@id': f['@id']}]}
        if _dt(r.get('timestamp')):
            a['uco-action:startTime'] = a['uco-action:endTime'] = _dt(r.get('timestamp'))
        graph.append(a)
        actions.append(a)
    notes = []
    for f in db['findings'].find({'case_id': case_id, 'status': 'APPROVED'}).sort('created_at', 1):
        on = [{'@id': files[e]['@id']} for e in f.get('evidence_ids') or [] if e in files]
        if not on:
            continue
        n = {'@id': _iri('finding', str(f['_id'])), '@type': 'uco-core:Annotation', 'uco-core:name': f['title'],
             'uco-core:statement': f.get('description') or f['title'], 'uco-core:object': on,
             'uco-core:tag': [f'severity:{str(f.get("severity")).lower()}', 'approved']}
        graph.append(n)
        notes.append(n)
    inv = {'@id': _iri('investigation', case_id), '@type': 'case-investigation:Investigation', 'uco-core:name': f'{case_id}: {case.get("name")}',
           'case-investigation:focus': ['digital forensics'],
           'uco-core:object': [{'@id': x['@id']} for x in records + actions + notes]}
    if case.get('description'):
        inv['uco-core:description'] = case['description']
    graph.insert(0, inv)
    export_action = {'@id': _iri('export', case_id, datetime.now(timezone.utc).isoformat()), '@type': 'case-investigation:InvestigativeAction',
                     'uco-core:name': 'Exported the case as CASE/UCO', 'uco-action:instrument': {'@id': tool['@id']},
                     'uco-action:startTime': _dt(datetime.now(timezone.utc)), 'uco-action:object': [{'@id': inv['@id']}]}
    if person(exported_by.get('name')):
        export_action['uco-action:performer'] = person(exported_by.get('name'))
    graph.append(export_action)
    return {'@context': CONTEXT, '@graph': graph}
