"""Analysis of one evidence image, run as a background (Celery) job.

A job first re-verifies the image's SHA-256 (and, for E01, prepares the verified raw working copy), then runs a
plan of analysis modules (see forensic/modules): the file system index, the well-known artifacts, the YARA
scan, and more as they are added. Each module replaces only its own previous output, so a single module can be
re-run without touching the rest. Two finalizers run at the end of every job: tags are re-linked to the records
that replaced the ones they pointed at, and the case-level patterns and anomalies are recomputed.

Everything written is tagged with the job ID and the module run ID for provenance; each module's status, counts
and warnings are kept on the evidence record (`modules`), and the job summary merges them.
"""
from __future__ import annotations
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import settings
from .modules import ORDER, PROFILES, REGISTRY, Cancelled, ModuleContext, plan, resolve_request
from .modules.base import MAX_SUMMARY_WARNINGS
from .working_image import analysis_image, changed_files, evidence_sha256, needs_working_copy

PIPELINE_COLLECTIONS = ('fs_entries', 'timeline_events', 'forensic_artifacts', 'usb_artifacts')
MODULE_WARNINGS_KEPT = 50
BAND = (8, 86)  # overall progress shared by the modules, by weight

__all__ = ['AnalysisPipeline', 'Cancelled']


class AnalysisPipeline:
    def __init__(self, db, evidence: dict, job_id: str, progress=None, is_cancelled=None, *,
                 profile: str | None = None, modules: list[str] | None = None, heartbeat=None, resume: bool = False):
        self.db = db
        self.e = evidence
        self.case_id = evidence['case_id']
        self.eid = evidence['evidence_id']
        self.job_id = job_id
        self.progress = progress or (lambda p, s: None)
        self.is_cancelled = is_cancelled or (lambda: False)
        self.heartbeat = heartbeat or (lambda: None)
        self.profile = profile
        self.requested = resolve_request(profile, modules)
        self.resume = resume
        self.original = Path(evidence['storage_path'])
        self.image = self.original  # what the Sleuth Kit reads; the raw working copy for E01 (set in run)
        self.root = Path(settings.storage_path).resolve() / 'analysis' / 'pipeline' / self.eid
        self.work = self.root / job_id
        self.summary = {'evidence_id': self.eid, 'case_id': self.case_id, 'job_id': job_id, 'engine': 'DFIP Analysis Pipeline'}
        self._pct = 0

    # -- helpers ---------------------------------------------------------------
    def _checkpoint(self, pct, stage):
        if self.is_cancelled():
            raise Cancelled()
        self._report(pct, stage)

    def _report(self, pct, stage):
        self._pct = max(self._pct, int(pct))
        self.progress(self._pct, stage)
        self.heartbeat()

    def _module_status(self) -> dict:
        doc = self.db['evidence'].find_one({'evidence_id': self.eid}, {'modules': 1}) or {}
        return doc.get('modules') or {}

    def _set_module(self, name: str, **fields):
        self.db['evidence'].update_one({'evidence_id': self.eid},
                                       {'$set': {f'modules.{name}.{k}': v for k, v in fields.items()}})

    def _legacy_output(self) -> bool:
        """Output written before analysis modules existed (no pipeline_module) must be replaced as a whole."""
        q = {'evidence_id': self.eid, 'pipeline': True, 'pipeline_module': {'$exists': False}}
        return any(self.db[c].find_one(q, {'_id': 1}) for c in PIPELINE_COLLECTIONS)

    # -- run ---------------------------------------------------------------------
    def run(self) -> dict:
        self._checkpoint(2, 'verifying-integrity')
        self._verify_integrity()
        self.work.mkdir(parents=True, exist_ok=True)
        if needs_working_copy(self.e):
            self._checkpoint(5, 'preparing-working-copy')
        self.image = analysis_image(self.e, create=True, db=self.db, actor=f'DFIP analysis job {self.job_id}')

        status = self._module_status()
        requested = self.requested
        if self._legacy_output():
            q = {'evidence_id': self.eid, 'pipeline': True, 'pipeline_module': {'$exists': False}}
            for c in PIPELINE_COLLECTIONS:
                self.db[c].delete_many(q)
            requested = list(dict.fromkeys(requested + PROFILES['standard']))
            status = {}
        run_plan = plan(requested, status)
        if self.resume:  # a redelivered job continues after the modules it already completed
            run_plan = [n for n in run_plan if not ((status.get(n) or {}).get('job_id') == self.job_id
                                                    and (status.get(n) or {}).get('status') == 'COMPLETED')]
        self.summary.update(profile=self.profile, requested=self.requested, plan=run_plan)
        for name in run_plan:
            self._set_module(name, status='QUEUED', job_id=self.job_id)

        total = sum(REGISTRY[n].weight for n in run_plan) or 1
        done = 0
        for name in run_plan:
            lo = BAND[0] + (BAND[1] - BAND[0]) * done / total
            done += REGISTRY[name].weight
            hi = BAND[0] + (BAND[1] - BAND[0]) * done / total
            self._run_module(name, (max(lo, self._pct), hi))

        # Tags point at records this run replaced; re-link them by natural key (kept out of the counts).
        self._checkpoint(88, 'relinking-tags')
        from ..services.tags import relink_evidence
        self.summary['tags'] = relink_evidence(self.db, self.eid)

        self._checkpoint(90, 'case-analytics')
        from ..analysis.services import compute_anomalies, compute_patterns
        analytics = {'patterns': len(compute_patterns(self.db, self.case_id))}
        anomalies, method, _ = compute_anomalies(self.db, self.case_id)
        # IsolationForest scores every event; only those it isolates count as flagged.
        analytics['anomalies_flagged'] = (sum(1 for a in anomalies if a.get('is_anomaly'))
                                          if method == 'ISOLATION_FOREST' else len(anomalies))
        self.summary['anomaly_method'] = method
        self._finish_summary(analytics)
        self._clean_work_dirs()
        return self.summary

    def _run_module(self, name: str, band):
        module = REGISTRY[name]
        run_id = str(uuid.uuid4())
        self._checkpoint(band[0], name)
        module.clear(self.db, self.eid)
        started = datetime.now(timezone.utc)
        self._set_module(name, status='RUNNING', job_id=self.job_id, run_id=run_id, version=module.version,
                         started_at=started, finished_at=None, error=None)
        ctx = ModuleContext(db=self.db, evidence=self.e, job_id=self.job_id, run_id=run_id, module=module,
                            image=self.image, work=self.work, progress_cb=self._report, cancel_check=self.is_cancelled,
                            heartbeat=self.heartbeat, band=band)
        try:
            module.run(ctx)
        except Cancelled:
            self._set_module(name, status='CANCELLED', finished_at=datetime.now(timezone.utc))
            raise
        except Exception as exc:
            self._set_module(name, status='FAILED', error=str(exc)[:1000], finished_at=datetime.now(timezone.utc))
            raise
        self._set_module(name, status='COMPLETED', counts=ctx.counts, warnings=ctx.warnings[:MODULE_WARNINGS_KEPT],
                         warnings_total=ctx.warnings_total, finished_at=datetime.now(timezone.utc))

    # -- results -------------------------------------------------------------------
    def _verify_integrity(self):
        digest = evidence_sha256(self.e)  # every file of an image set, in order
        ok = digest == self.e['sha256']
        now = datetime.now(timezone.utc)
        self.db['chain_of_custody'].insert_one({
            'evidence_id': self.eid, 'case_id': self.case_id, 'timestamp': now, 'user_id': 'system',
            'user_name': f'DFIP analysis job {self.job_id}', 'action': 'ANALYSIS_INTEGRITY_CHECK',
            'sha256': digest, 'status': 'VERIFIED' if ok else 'INTEGRITY_FAILED'})
        self.summary['integrity'] = {'expected_sha256': self.e['sha256'], 'computed_sha256': digest, 'verified': ok}
        if not ok:
            changed = changed_files(self.e)
            raise ValueError('Evidence SHA-256 no longer matches the acquisition hash; analysis refused'
                             + (f' ({", ".join(changed)} changed)' if changed else ''))

    def _finish_summary(self, analytics: dict):
        """Counts and warnings of every module's latest completed run, so a partial re-run reports the whole picture."""
        status = self._module_status()
        counts, warnings, total = {}, [], 0
        for name in ORDER:
            s = status.get(name) or {}
            if s.get('status') != 'COMPLETED':
                continue
            for k, v in (s.get('counts') or {}).items():
                counts[k] = counts.get(k, 0) + v
            warnings.extend(s.get('warnings') or [])
            total += s.get('warnings_total') or 0
        counts.update(analytics)
        facts = self.db['analysis_facts'].find_one({'evidence_id': self.eid}) or {}
        fs, art = facts.get('fs_index') or {}, facts.get('artifacts') or {}
        self.summary.update(
            counts=counts, partitions=fs.get('partitions', []), filesystems=fs.get('filesystems', []),
            artifacts=art.get('extracted', []), artifacts_total=art.get('extracted_total', 0),
            warnings=warnings[:MAX_SUMMARY_WARNINGS], warnings_total=total,
            modules={n: {k: (v.isoformat() if hasattr(v, 'isoformat') else v)
                         for k, v in (status.get(n) or {}).items() if k != 'warnings'} for n in ORDER if n in status})

    def _clean_work_dirs(self):
        """Removes earlier jobs' work folders that no module's current output refers to."""
        keep = {self.job_id} | {s.get('job_id') for s in self._module_status().values() if isinstance(s, dict)}
        if not self.root.is_dir():
            return
        for d in self.root.iterdir():
            if d.is_dir() and d.name not in keep:
                shutil.rmtree(d, ignore_errors=True)
