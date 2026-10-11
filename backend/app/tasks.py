"""Celery tasks for DFIP's forensic job pipeline.

Each task operates on a job document already written to the `jobs` collection by
api/jobs.py (status=QUEUED). Progress/stage/result fields on that document are
what the frontend polls, so the shape of updates here must match what the old
in-process JobQueue wrote, to avoid touching frontend or api/jobs.py.

Ground rule carried over from the rest of the platform: real evidence never gets
synthetic artifacts. The `demo` flag on the evidence record is checked ; only
records explicitly created as demo data take the synthetic path.
"""
from datetime import datetime, timedelta, timezone
import asyncio
import os
import socket
import time
import traceback
from pathlib import Path

from celery.utils.log import get_task_logger

from .celery_app import celery_app
from .database import get_db
from .core.config import settings

logger = get_task_logger(__name__)


def _set_job(job_id: str, **fields):
    fields['updated_at'] = datetime.now(timezone.utc)
    get_db()['jobs'].update_one({'job_id': job_id}, {'$set': fields})


def _mark_running(job_id: str):
    now = datetime.now(timezone.utc)
    get_db()['jobs'].update_one(
        {'job_id': job_id},
        {'$set': {'status': 'RUNNING', 'started_at': now, 'updated_at': now, 'stage': 'starting'},
         '$inc': {'attempts': 1}},
    )


def _notify(user_id: str, title: str, message: str, level: str = 'INFO'):
    try:
        from .services.notifications import create
        asyncio.run(create(user_id, title, message, level))
    except Exception:
        logger.warning('Notification delivery failed for job on user %s', user_id, exc_info=True)


HEARTBEAT_SECONDS = 15
STALE_AFTER = timedelta(minutes=10)   # a RUNNING job without a heartbeat for this long lost its worker


def _claim(job_id: str):
    """Atomically takes a queued job, or a running one whose worker stopped sending heartbeats.

    Returns (job, resumed) or (None, False) when another worker owns the job or it already finished. A message
    redelivered by the broker therefore never starts a second, concurrent run of the same job.
    """
    db = get_db()
    now = datetime.now(timezone.utc)
    worker = f'{socket.gethostname()}:{os.getpid()}'
    fields = {'status': 'RUNNING', 'updated_at': now, 'heartbeat_at': now, 'worker': worker}
    job = db['jobs'].find_one_and_update(
        {'job_id': job_id, 'status': 'QUEUED'},
        {'$set': dict(fields, started_at=now, stage='starting'), '$inc': {'attempts': 1}})
    if job:
        return job, False
    job = db['jobs'].find_one_and_update(
        {'job_id': job_id, 'status': 'RUNNING', 'heartbeat_at': {'$lt': now - STALE_AFTER}},
        {'$set': dict(fields, stage='resuming'), '$inc': {'attempts': 1}})
    return job, bool(job)


def _heartbeat(job_id: str):
    last = [0.0]

    def beat():
        if time.monotonic() - last[0] >= HEARTBEAT_SECONDS:
            last[0] = time.monotonic()
            get_db()['jobs'].update_one({'job_id': job_id, 'status': 'RUNNING'},
                                        {'$set': {'heartbeat_at': datetime.now(timezone.utc)}})
    return beat


def _is_cancelled(job_id: str) -> bool:
    job = get_db()['jobs'].find_one({'job_id': job_id}, {'status': 1})
    return bool(job and job.get('status') == 'CANCELLED')


@celery_app.task(bind=True, name='dfip.hash_verify', max_retries=2, default_retry_delay=10)
def hash_verify_task(self, job_id: str, evidence_id: str, created_by: str):
    from .forensic.hashing import sha256_file
    from .repositories.evidence import get_evidence

    if _is_cancelled(job_id):
        return {'job_id': job_id, 'status': 'CANCELLED'}

    _mark_running(job_id)
    db = get_db()
    try:
        _set_job(job_id, progress=15, stage='hashing')
        e = get_evidence(evidence_id)
        if not e:
            raise ValueError('Evidence not found')

        if e.get('demo'):
            status = 'VERIFIED'
            digest = e['sha256']
        else:
            p = Path(e['storage_path'])
            if not p.exists():
                raise FileNotFoundError('Original evidence object is unavailable')
            digest = sha256_file(p)
            status = 'VERIFIED' if digest == e['sha256'] else 'INTEGRITY_FAILED'

        db['evidence'].update_one(
            {'_id': e['_id']},
            {'$set': {'verification_status': status, 'verified_at': datetime.now(timezone.utc)}},
        )
        result = {'evidence_id': e['evidence_id'], 'status': status, 'sha256': digest}
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete',
                  result=result, finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Forensic job completed', f'{job_id} (HASH_VERIFY) completed successfully.')
        return result
    except Exception as exc:
        _set_job(job_id, status='FAILED', stage='failed', error=str(exc),
                  traceback=traceback.format_exc(limit=5), finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Forensic job failed', f'{job_id}: {exc}', 'ERROR')
        raise


@celery_app.task(bind=True, name='dfip.forensic_analysis', max_retries=1, default_retry_delay=30,
                 soft_time_limit=settings.analysis_time_limit, time_limit=settings.analysis_time_limit + 600)
def forensic_analysis_task(self, job_id: str, evidence_id: str, created_by: str):
    from .repositories.evidence import get_evidence
    from .forensic.engine import extract_demo_artifacts

    if _is_cancelled(job_id):
        return {'job_id': job_id, 'status': 'CANCELLED'}

    job, resumed = _claim(job_id)
    if not job:
        logger.warning('Job %s is owned by another worker or already finished; ignoring the duplicate delivery', job_id)
        return {'job_id': job_id, 'status': 'DUPLICATE_IGNORED'}
    payload = job.get('payload') or {}
    db = get_db()
    try:
        e = get_evidence(evidence_id)
        if not e:
            raise ValueError('Evidence not found')

        if e.get('demo'):
            # Synthetic path: only ever reachable for evidence explicitly
            # flagged as demo data at creation time (see api/evidence.py,
            # which always sets demo=False on real uploads).
            docs = extract_demo_artifacts(e['case_id'], e['evidence_id'])
            db['forensic_artifacts'].insert_many([dict(x, analysis_job_id=job_id) for x in docs])
            result = {'status': 'DEMO', 'engine': 'DFIP Demo Engine', 'warning': 'Synthetic data only'}
        else:
            from .forensic.pipeline import AnalysisPipeline, Cancelled

            def progress_cb(p, s):
                _set_job(job_id, progress=p, stage=s)

            db['evidence'].update_one({'_id': e['_id']}, {'$set': {'analysis_status': 'RUNNING', 'last_analysis_job': job_id}})
            try:
                result = AnalysisPipeline(db, e, job_id, progress=progress_cb, is_cancelled=lambda: _is_cancelled(job_id),
                                          profile=payload.get('profile'), modules=payload.get('modules'),
                                          heartbeat=_heartbeat(job_id), resume=resumed).run()
            except Cancelled:
                db['evidence'].update_one({'_id': e['_id']}, {'$set': {'analysis_status': 'CANCELLED'}})
                return {'job_id': job_id, 'status': 'CANCELLED'}
            except Exception:
                db['evidence'].update_one({'_id': e['_id']}, {'$set': {'analysis_status': 'FAILED'}})
                raise
            # One run record per evidence: the latest (earlier ones are in the job history).
            db['forensic_artifacts'].delete_many({'evidence_id': e['evidence_id'], 'type': 'ANALYSIS_RUN',
                                                  'source': 'DFIP_ANALYSIS_PIPELINE'})
            db['forensic_artifacts'].insert_one({
                'case_id': e['case_id'], 'evidence_id': e['evidence_id'], 'type': 'ANALYSIS_RUN',
                'timestamp': datetime.now(timezone.utc), 'data': result,
                'source': 'DFIP_ANALYSIS_PIPELINE', 'analysis_job_id': job_id,
            })
            db['evidence'].update_one({'_id': e['_id']}, {'$set': {
                'analysis_status': 'COMPLETED', 'analysis_summary': result['counts'],
                'analyzed_at': datetime.now(timezone.utc)}})

        summary = {'evidence_id': e['evidence_id'], 'case_id': e['case_id'], 'summary': result}
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete',
                  result=summary, finished_at=datetime.now(timezone.utc))
        if not payload.get('rematch'):  # re-matching after a hash set changed runs unasked; only new known-bad files are news
            _notify(created_by, 'Forensic job completed', f'{job_id} (FORENSIC_ANALYSIS) completed successfully.')
        bad = (result.get('counts') or {}).get('known_bad_files') or 0
        before = (((e.get('modules') or {}).get('hash_match') or {}).get('counts') or {}).get('known_bad_files') or 0
        if bad and (bad > before or not payload.get('rematch')):
            case = db['cases'].find_one({'case_id': e['case_id']}, {'investigator_id': 1}) or {}
            for user in {created_by, case.get('investigator_id')} - {None}:
                _notify(user, 'Known-bad files found', f'{e["evidence_id"]} ({e["case_id"]}): {bad} file(s) match a known-bad hash set.', 'WARNING')
        return summary
    except Exception as exc:
        _set_job(job_id, status='FAILED', stage='failed', error=str(exc),
                  traceback=traceback.format_exc(limit=5), finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Forensic job failed', f'{job_id}: {exc}', 'ERROR')
        raise


@celery_app.task(bind=True, name='dfip.hashset_import', max_retries=0)
def hashset_import_task(self, job_id: str, set_id: str, created_by: str):
    """Builds a hash set's lookup store from the uploaded file, then re-matches every processed evidence item."""
    from .forensic.hashsets import import_set, store_path
    job, _ = _claim(job_id)
    if not job:
        return {'job_id': job_id, 'status': 'DUPLICATE_IGNORED'}
    db = get_db()
    hs = db['hash_sets'].find_one({'set_id': set_id})
    try:
        if not hs:
            raise ValueError('Hash set not found')
        source = Path(hs['source_path'])
        dest = store_path(set_id)
        result = import_set(source, dest, progress=lambda f: _set_job(job_id, progress=int(5 + 85 * f), stage='importing'))
        total = sum(result['counts'].values())
        if not total:
            raise ValueError('No MD5, SHA-1 or SHA-256 hashes were found in the file')
        db['hash_sets'].update_one({'set_id': set_id}, {'$set': {
            'status': 'READY', 'path': str(dest), 'format': result['format'], 'counts': result['counts'], 'count': total,
            'invalid_lines': result['invalid'], 'algorithms': [a for a, n in result['counts'].items() if n],
            'ready_at': datetime.now(timezone.utc), 'error': None}})
        if hs.get('source_uploaded'):
            source.unlink(missing_ok=True)  # the store holds every hash; the upload is not kept
        _set_job(job_id, progress=92, stage='matching')
        rematched = _rematch_all(created_by)
        summary = {'set_id': set_id, 'format': result['format'], 'counts': result['counts'], 'invalid_lines': result['invalid'],
                   'rematch_jobs': rematched}
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete', result=summary, finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Hash set imported', f'{hs["name"]}: {total:,} hashes ({result["format"]}).')
        return summary
    except Exception as exc:
        db['hash_sets'].update_one({'set_id': set_id}, {'$set': {'status': 'FAILED', 'error': str(exc)[:500]}})
        _set_job(job_id, status='FAILED', stage='failed', error=str(exc), traceback=traceback.format_exc(limit=5),
                 finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Hash set import failed', f'{set_id}: {exc}', 'ERROR')
        raise


def _rematch_all(user_id: str) -> list[str]:
    """Queues the hash-set module for every evidence item whose files were hashed (and that is not being analysed)."""
    from .services.jobs import active_analysis, queue
    jobs = []
    for e in get_db()['evidence'].find({'modules.fileproc.status': 'COMPLETED'}, {'evidence_id': 1}):
        if not active_analysis(e['evidence_id']):
            jobs.append(queue.enqueue('FORENSIC_ANALYSIS', {'evidence_id': e['evidence_id'], 'profile': None,
                                                             'modules': ['hash_match'], 'rematch': True}, user_id))
    return jobs


TASKS_BY_TYPE = {
    'HASH_VERIFY': hash_verify_task,
    'FORENSIC_ANALYSIS': forensic_analysis_task,
    'HASHSET_IMPORT': hashset_import_task,
}
