"""Job creation and dispatch.

Job records live in MongoDB (status, progress, stage, result) so the frontend's
polling behavior is unchanged. Execution itself is delegated to Celery workers
(see app/tasks.py, app/celery_app.py) instead of the previous in-process
threading loop, so jobs survive API restarts and can be scaled across workers.
"""
from datetime import datetime, timezone
from ..database import get_db
from pymongo import ReturnDocument


class JobQueue:
    def enqueue(self, job_type, payload, user_id):
        from ..tasks import TASKS_BY_TYPE
        if job_type not in TASKS_BY_TYPE:
            raise ValueError(f'Unsupported job type: {job_type}')

        db = get_db()
        now = datetime.now(timezone.utc)
        # Atomic sequence based ID; collisions are prevented by a unique index.
        seq = db['job_sequences'].find_one_and_update(
            {'_id': 'jobs'}, {'$inc': {'value': 1}}, upsert=True, return_document=ReturnDocument.AFTER
        )
        n = int(seq.get('value', 1))
        job_id = f'JOB-{n:06d}'
        db['jobs'].insert_one({
            'job_id': job_id, 'type': job_type, 'payload': payload, 'status': 'QUEUED',
            'progress': 0, 'stage': 'queued', 'created_by': str(user_id),
            'created_at': now, 'updated_at': now,
        })

        task = TASKS_BY_TYPE[job_type]
        evidence_id = payload['evidence_id']
        async_result = task.delay(job_id, evidence_id, str(user_id))
        db['jobs'].update_one({'job_id': job_id}, {'$set': {'celery_task_id': async_result.id}})
        return job_id

    def cancel(self, job_id):
        """Best-effort cancellation. Celery tasks check `_is_cancelled` at their
        entry point, so a QUEUED job that hasn't started yet will not run its
        work. A task already RUNNING will finish its current step before the
        next checkpoint; forcefully killing worker processes mid-write to
        evidence records is deliberately avoided to prevent partial/corrupt
        forensic artifacts."""
        db = get_db()
        job = db['jobs'].find_one({'job_id': job_id})
        if not job:
            return None
        if job.get('status') in ('COMPLETED', 'FAILED', 'CANCELLED'):
            return job
        db['jobs'].update_one({'_id': job['_id']}, {'$set': {'status': 'CANCELLED', 'updated_at': datetime.now(timezone.utc)}})
        task_id = job.get('celery_task_id')
        if task_id:
            try:
                from ..celery_app import celery_app
                celery_app.control.revoke(task_id, terminate=False)
            except Exception:
                pass
        return db['jobs'].find_one({'_id': job['_id']})


queue = JobQueue()
