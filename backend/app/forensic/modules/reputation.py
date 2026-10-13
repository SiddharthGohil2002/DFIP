"""Hash reputation: the SHA-256 of each program looked up on VirusTotal, only when the case's investigator turned automatic
lookups on for the case, and a VirusTotal key is configured. Only hashes leave DFIP (never a file, a name or a path);
requests are spaced to the configured rate, cached, and every response is kept with its time (see app/threatintel)."""
from __future__ import annotations
import time

from .base import Module

MAX_LOOKUPS = 100


class ReputationModule(Module):
    name = 'reputation'
    label = 'Hash reputation (VirusTotal)'
    description = ("Looks up each program's SHA-256 on VirusTotal when automatic lookups are on for the case (off unless an "
                   'investigator turns them on) and a key is configured; only hashes are sent.')
    requires = ('executables',)
    kinds = ('disk', 'logical', 'capture')  # files carried in a capture too
    weight = 3
    collections = ()
    fields = {'forensic_artifacts': ('vt',)}

    def run(self, ctx):
        from ...core.config import settings
        from ...threatintel.client import lookup_virustotal_hash
        ctx.count('reputation_lookups', 0)
        ctx.count('reputation_malicious', 0)
        case = ctx.db['cases'].find_one({'case_id': ctx.case_id}, {'threat_intel': 1}) or {}
        if not (case.get('threat_intel') or {}).get('auto_lookup'):
            ctx.set_fact('status', 'off for this case')
            return
        if not settings.virustotal_api_key:
            ctx.set_fact('status', 'no VirusTotal key configured')
            return
        programs = list(ctx.db['forensic_artifacts'].find({'evidence_id': ctx.eid, 'type': 'EXECUTABLE', 'sha256': {'$ne': None}},
                                                           {'sha256': 1, 'score': 1, 'path': 1}).sort('score', -1))
        hashes = list(dict.fromkeys(p['sha256'] for p in programs))
        if len(hashes) > MAX_LOOKUPS:
            ctx.warn(f'Only the {MAX_LOOKUPS} programs that stand out most were looked up on VirusTotal (of {len(hashes):,})')
            hashes = hashes[:MAX_LOOKUPS]
        gap = 60.0 / max(0.1, settings.virustotal_rate_per_minute)
        results, malicious, last = {}, 0, 0.0
        for i, h in enumerate(hashes):
            ctx.progress(i / max(1, len(hashes)), f'{i + 1} of {len(hashes)}')
            r = lookup_virustotal_hash(h, max_age_seconds=86_400, peek=True)
            if r is None:  # not cached: a real request, spaced to the rate limit
                wait = last + gap - time.monotonic()
                while wait > 0:
                    ctx.checkpoint()
                    time.sleep(min(wait, 1.0))
                    wait = last + gap - time.monotonic()
                last = time.monotonic()
                r = lookup_virustotal_hash(h, max_age_seconds=86_400)
                ctx.count('reputation_lookups')
            vt = {k: r.get(k) for k in ('status', 'malicious', 'suspicious', 'harmless', 'undetected', 'http_status', 'error')
                  if r.get(k) is not None}
            vt.update(queried_at=r.get('queried_at'), from_cache=bool(r.get('from_cache')),
                      link=f'https://www.virustotal.com/gui/file/{h}')
            results[h] = vt
            malicious += bool(vt.get('malicious'))
        for h, vt in results.items():
            ctx.db['forensic_artifacts'].update_many({'evidence_id': ctx.eid, 'type': 'EXECUTABLE', 'sha256': h}, {'$set': {'vt': vt}})
        ctx.count('reputation_malicious', malicious)
        ctx.set_fact('status', f'{len(results)} programs looked up')
