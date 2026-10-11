"""Execution evidence: one row per program, merging every trace Windows keeps of programs that ran or were present.

  Prefetch    programs that ran: run count and up to eight last-run times (from the .pf file)
  UserAssist  programs a user started from Explorer: run count, focus time, last run (per user)
  BAM         Background Activity Moderator: last run per user (Windows 10 and later)
  Amcache     programs present or run: full path, SHA-1, size, version; its key's write time is about when Windows
              first recorded the program
  ShimCache   programs Windows checked for compatibility: path and the file's own modification time (it shows a
              program was on the disk, not that it ran)

Traces are matched by the program's file name (case-insensitive), so the same program at two paths is one row
with both paths; every source keeps its own entries and times.
"""
from __future__ import annotations
import re


def _name(path: str | None) -> str | None:
    if not path:
        return None
    return re.split(r'[\\/]', str(path).rstrip('\\/'))[-1] or None


def _latest(*values):
    vals = [v for v in values if v]
    return max(vals) if vals else None


def _earliest(*values):
    vals = [v for v in values if v]
    return min(vals) if vals else None


def merge(prefetch: list[dict], userassist: list[dict], bam: list[dict], amcache: list[dict], shimcache: list[dict]) -> list[dict]:
    rows: dict[str, dict] = {}

    def row(path, display=None):
        name = _name(path)
        if not name:
            return None
        key = name.lower()
        r = rows.setdefault(key, {'program': display or name, 'paths': set(), 'prefetch': [], 'userassist': [], 'bam': [],
                                  'amcache': [], 'shimcache': [], 'evidence_ids': set()})
        if display and r['program'].isupper():  # prefer a mixed-case name over Prefetch's upper case
            r['program'] = display
        return r

    for p in prefetch:
        r = row(p.get('executable_path') or p.get('executable'), p.get('executable'))
        if r is not None:
            r['paths'].add(p.get('executable_path'))
            runs = p.get('last_run_times') or []
            r['prefetch'].append({'run_count': p.get('run_count'), 'last_runs': runs, 'source': p.get('source_path'),
                                  'evidence_id': p.get('evidence_id')})
            r['evidence_ids'].add(p.get('evidence_id'))
    for u in userassist:
        r = row(u.get('program'), _name(u.get('program')))
        if r is not None:
            r['paths'].add(u.get('program'))
            r['userassist'].append({'run_count': u.get('run_count'), 'last_run': u.get('last_run'), 'focus_count': u.get('focus_count'),
                                    'focus_time_ms': u.get('focus_time_ms'), 'user': u.get('user'), 'evidence_id': u.get('evidence_id')})
            r['evidence_ids'].add(u.get('evidence_id'))
    for b in bam:
        r = row(b.get('path'), _name(b.get('path')))
        if r is not None:
            r['paths'].add(b.get('path'))
            r['bam'].append({'last_run': b.get('last_run'), 'user': b.get('user'), 'sid': b.get('sid'), 'evidence_id': b.get('evidence_id')})
            r['evidence_ids'].add(b.get('evidence_id'))
    for a in amcache:
        r = row(a.get('path'), a.get('name'))
        if r is not None:
            r['paths'].add(a.get('path'))
            r['amcache'].append({'sha1': a.get('sha1'), 'size': a.get('size'), 'version': a.get('version'), 'publisher': a.get('publisher'),
                                 'first_recorded': a.get('key_last_write'), 'link_date': a.get('link_date'), 'evidence_id': a.get('evidence_id')})
            r['evidence_ids'].add(a.get('evidence_id'))
    for s in shimcache:
        r = row(s.get('path'), _name(s.get('path')))
        if r is not None:
            r['paths'].add(s.get('path'))
            r['shimcache'].append({'last_modified': s.get('last_modified'), 'position': s.get('position'), 'evidence_id': s.get('evidence_id')})
            r['evidence_ids'].add(s.get('evidence_id'))
    out = []
    for r in rows.values():
        last_run = _latest(*[t for p in r['prefetch'] for t in p['last_runs'][:1]], *[u['last_run'] for u in r['userassist']],
                           *[b['last_run'] for b in r['bam']])
        first = _earliest(*[a['first_recorded'] for a in r['amcache']], *[t for p in r['prefetch'] for t in p['last_runs']],
                          *[u['last_run'] for u in r['userassist']], *[b['last_run'] for b in r['bam']])
        sources = [s for s in ('prefetch', 'userassist', 'bam', 'amcache', 'shimcache') if r[s]]
        out.append(dict(r, paths=sorted(p for p in r['paths'] if p), evidence_ids=sorted(e for e in r['evidence_ids'] if e),
                        sources=sources, ran=bool(r['prefetch'] or r['userassist'] or r['bam']), last_run=last_run,
                        first_seen=first, sha1=next((a['sha1'] for a in r['amcache'] if a.get('sha1')), None)))
    out.sort(key=lambda r: (r['last_run'] or '', r['first_seen'] or ''), reverse=True)
    return out
