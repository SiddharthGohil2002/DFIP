"""Celery tasks for DFIP's forensic job pipeline.

Each task operates on a job document already written to the `jobs` collection by
api/jobs.py (status=QUEUED). Progress/stage/result fields on that document are
what the frontend polls, so the shape of updates here must match what the old
in-process JobQueue wrote, to avoid touching frontend or api/jobs.py.

Ground rule carried over from the rest of the platform: real evidence never gets
synthetic artifacts. The `demo` flag on the evidence record is checked ; only
records explicitly created as demo data take the synthetic path.
"""
from datetime import datetime, timezone
import asyncio
import traceback
from pathlib import Path

from celery.utils.log import get_task_logger

from .celery_app import celery_app
from .database import get_db

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


@celery_app.task(bind=True, name='dfip.forensic_analysis', max_retries=1, default_retry_delay=30)
def forensic_analysis_task(self, job_id: str, evidence_id: str, created_by: str):
    from .repositories.evidence import get_evidence
    from .forensic.engine import ForensicEngine, extract_demo_artifacts

    if _is_cancelled(job_id):
        return {'job_id': job_id, 'status': 'CANCELLED'}

    _mark_running(job_id)
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
            _set_job(job_id, progress=10, stage='validating-evidence')
            path = Path(e['storage_path'])
            if not path.exists():
                raise FileNotFoundError('Original evidence object is unavailable')

            _set_job(job_id, progress=25, stage='forensic-examination')

            def progress_cb(p, s):
                _set_job(job_id, progress=p, stage=s)

            result = ForensicEngine().analyze(path, e['format'], progress=progress_cb)
            _set_job(job_id, progress=90, stage='persisting-artifacts')
            db['forensic_artifacts'].insert_one({
                'case_id': e['case_id'], 'evidence_id': e['evidence_id'], 'type': 'ANALYSIS_RUN',
                'timestamp': datetime.now(timezone.utc), 'data': result,
                'source': 'DFIP_ENGINE', 'analysis_job_id': job_id,
            })

        summary = {'evidence_id': e['evidence_id'], 'case_id': e['case_id'], 'summary': result}
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete',
                  result=summary, finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Forensic job completed', f'{job_id} (FORENSIC_ANALYSIS) completed successfully.')
        return summary
    except Exception as exc:
        _set_job(job_id, status='FAILED', stage='failed', error=str(exc),
                  traceback=traceback.format_exc(limit=5), finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Forensic job failed', f'{job_id}: {exc}', 'ERROR')
        raise


TASKS_BY_TYPE = {
    'HASH_VERIFY': hash_verify_task,
    'FORENSIC_ANALYSIS': forensic_analysis_task,
}
