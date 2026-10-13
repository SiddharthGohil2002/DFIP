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
    from .forensic.working_image import evidence_sha256
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
            digest = evidence_sha256(e)  # every file of an image set, in order
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


def _rematch_all(user_id: str, module: str = 'hash_match', case_id: str | None = None) -> list[str]:
    """Queues one module (the hash-set match by default; YARA or ClamAV after their rules change, the reputation lookups when
    a case turns them on) for every evidence item whose files were hashed and that is not being analysed."""
    from .services.jobs import active_analysis, queue
    jobs = []
    q = {'modules.fileproc.status': 'COMPLETED', **({'case_id': case_id} if case_id else {})}
    for e in get_db()['evidence'].find(q, {'evidence_id': 1}):
        if not active_analysis(e['evidence_id']):
            jobs.append(queue.enqueue('FORENSIC_ANALYSIS', {'evidence_id': e['evidence_id'], 'profile': None,
                                                             'modules': [module], 'rematch': True}, user_id))
    return jobs


@celery_app.task(bind=True, name='dfip.clamav_update', max_retries=0)
def clamav_update_task(self, job_id: str, _subject, created_by: str):
    """Downloads or updates ClamAV's official databases with freshclam into storage/clamav, then rescans."""
    from .forensic.modules.base import run_tool
    from .forensic.rulesets import clamav_databases, clamav_dir
    job, _ = _claim(job_id)
    if not job:
        return {'job_id': job_id, 'status': 'DUPLICATE_IGNORED'}
    try:
        folder = clamav_dir()
        conf = folder / 'freshclam.conf'
        conf.write_text(f'DatabaseDirectory {folder}\nDatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\n'
                        f'ScriptedUpdates yes\nConnectTimeout 30\nReceiveTimeout 600\n', encoding='utf-8')
        _set_job(job_id, progress=10, stage='downloading')
        r = run_tool(['freshclam', f'--config-file={conf}', '--stdout', '--foreground'], timeout=3600, memory_bytes=8 << 30)
        conf.unlink(missing_ok=True)
        if r.get('returncode') != 0:
            raise ValueError(f'freshclam failed: {(r.get("stdout") or r.get("stderr") or r.get("status") or "")[-500:]}')
        dbs = [{k: v for k, v in d.items() if k != 'modified'} for d in clamav_databases()]
        summary = {'databases': dbs, 'rescan_jobs': _rematch_all(created_by, 'clamav')}
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete', result=summary, finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'ClamAV databases updated', ', '.join(f'{d["name"]} {d.get("version") or ""}'.strip() for d in dbs))
        return summary
    except Exception as exc:
        _set_job(job_id, status='FAILED', stage='failed', error=str(exc)[:2000], finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'ClamAV update failed', str(exc)[:300], 'ERROR')
        raise


@celery_app.task(bind=True, name='dfip.volume_decrypt', max_retries=0,
                 soft_time_limit=settings.analysis_time_limit, time_limit=settings.analysis_time_limit + 600)
def volume_decrypt_task(self, job_id: str, evidence_id: str, created_by: str):
    """Decrypts an encrypted volume with its stored key and registers the plaintext as evidence derived from the
    original (own SHA-256 and SHA-512, read-only, custody records on both), then analyses it."""
    from bson import ObjectId
    from .api.volumes import derived_dir, volumes_of
    from .forensic.disk_formats import ensure_space, write_raw
    from .forensic.volume_crypto import METHOD_LABELS, open_volume
    from .forensic.working_image import analysis_image
    from .repositories.evidence import get_evidence
    from .services.audit import log
    from .services.jobs import queue
    from .services.secrets import decrypt
    from .services.sequences import next_sequence
    from .websocket.manager import manager

    job, _ = _claim(job_id)
    if not job:
        return {'job_id': job_id, 'status': 'DUPLICATE_IGNORED'}
    db = get_db()
    partial = None
    try:
        vid, key_id = job['payload']['volume_id'], job['payload']['key_id']
        e = get_evidence(evidence_id)
        key = db['volume_keys'].find_one({'key_id': key_id, 'evidence_id': evidence_id})
        if not e or not key:
            raise ValueError('The evidence or the stored key no longer exists')
        vol = next((v for v in volumes_of(e) if v['volume_id'] == vid), None)
        if not vol:
            raise ValueError(f'{evidence_id} has no volume {vid}')
        user = db['users'].find_one({'_id': ObjectId(created_by)}) if ObjectId.is_valid(created_by) else None
        user = user or {'_id': created_by, 'name': 'DFIP', 'role': 'SYSTEM'}
        image = analysis_image(e, create=True, db=db, actor=f'DFIP job {job_id}')
        _set_job(job_id, progress=5, stage='unlocking')
        opened = open_volume(image, vol['partition_offset'], vol['length'], key['kind'], key['method'], decrypt(key['secret']))
        beat = _heartbeat(job_id)
        try:
            folder = derived_dir(evidence_id)
            ensure_space(folder, opened.size, 'the decrypted volume')
            partial = folder / f'{vid}.partial'
            _set_job(job_id, progress=10, stage='decrypting')

            def progress(fraction):
                beat()
                _set_job(job_id, progress=10 + int(80 * fraction), stage='decrypting')
            info = write_raw(opened.read, opened.size, partial, progress=progress, cancelled=lambda: _is_cancelled(job_id))
        finally:
            opened.close()

        now = datetime.now(timezone.utc)
        new_id = f'EVID-{next_sequence("evidence", floor=db["evidence"].count_documents({})):03d}'
        target = folder / f'{new_id}.raw'
        partial.chmod(0o444)
        partial.replace(target)
        partial = None
        how = METHOD_LABELS[key['method']]
        doc = {'evidence_id': new_id, 'case_id': e['case_id'], 'filename': f'{e.get("filename")} {vid} (decrypted {key["kind"]})',
               'format': 'RAW', 'size': info['size'], 'sha256': info['sha256'], 'sha512': info['sha512'], 'storage_path': str(target),
               'verification_status': 'VERIFIED', 'verified_at': now, 'created_at': now, 'updated_at': now, 'created_by': created_by,
               'read_only': True, 'immutable': True, 'demo': False, 'acquisition_status': 'DERIVED', 'integrity_algorithm': 'SHA-256 + SHA-512',
               'derived_from': {'evidence_id': evidence_id, 'volume_id': vid, 'kind': key['kind'], 'method': key['method'], 'key_id': key_id,
                                'source_sha256': e.get('sha256'), 'job_id': job_id}}
        db['evidence'].insert_one(doc)
        db['volume_keys'].update_one({'key_id': key_id}, {'$set': {'last_used_at': now, 'derived_evidence_id': new_id}, '$inc': {'use_count': 1}})
        detail = f'{key["kind"]} volume {vid} of {evidence_id} unlocked with a {how} (stored as {key_id}) and decrypted'
        db['chain_of_custody'].insert_many([
            {'evidence_id': evidence_id, 'case_id': e['case_id'], 'timestamp': now, 'user_id': created_by, 'user_name': user.get('name'),
             'action': 'VOLUME_DECRYPTED', 'derived_evidence_id': new_id, 'sha256': info['sha256'], 'status': 'VERIFIED',
             'detail': f'{detail} to {new_id}; the original is unchanged'},
            {'evidence_id': new_id, 'case_id': e['case_id'], 'timestamp': now, 'user_id': created_by, 'user_name': user.get('name'),
             'action': 'EVIDENCE_DERIVED', 'source_evidence_id': evidence_id, 'sha256': info['sha256'], 'sha512': info['sha512'],
             'result': 'PRESERVED_READONLY', 'detail': detail}])
        log(user, 'VOLUME_KEY_USED', 'evidence', str(e['_id']), {'evidence_id': evidence_id, 'volume_id': vid, 'key_id': key_id,
                                                                  'derived_evidence_id': new_id, 'sha256': info['sha256'], 'job_id': job_id})
        manager.emit_sync('EVIDENCE_REGISTERED', {'evidence_id': new_id, 'case_id': e['case_id'], 'filename': doc['filename'], 'size': info['size'],
                                                  'sha256': info['sha256'], 'format': 'RAW', 'verification_status': 'VERIFIED'})
        analysis = queue.enqueue('FORENSIC_ANALYSIS', {'evidence_id': new_id, 'profile': 'standard', 'modules': None}, created_by)
        result = {'evidence_id': evidence_id, 'volume_id': vid, 'derived_evidence_id': new_id, 'size': info['size'],
                  'sha256': info['sha256'], 'analysis_job_id': analysis}
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete', result=result, finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Volume decrypted', f'{vid} of {evidence_id} is now {new_id}; its analysis ({analysis}) has started.')
        return result
    except Exception as exc:
        if partial is not None:
            partial.unlink(missing_ok=True)
        cancelled = isinstance(exc, InterruptedError)
        _set_job(job_id, status='CANCELLED' if cancelled else 'FAILED', stage='cancelled' if cancelled else 'failed', error=str(exc)[:2000],
                 finished_at=datetime.now(timezone.utc))
        if not cancelled:
            _notify(created_by, 'Volume decryption failed', str(exc)[:300], 'ERROR')
            raise


MAX_IMPORTED_EVENTS = 5_000_000


@celery_app.task(bind=True, name='dfip.timeline_import', max_retries=0,
                 soft_time_limit=settings.analysis_time_limit, time_limit=settings.analysis_time_limit + 600)
def timeline_import_task(self, job_id: str, _subject, created_by: str):
    """Reads an uploaded Plaso timeline into the case timeline as PLASO_EVENT events (see forensic/plaso_import.py)."""
    import hashlib
    from collections import Counter
    from .forensic.plaso_import import iter_events

    job, _ = _claim(job_id)
    if not job:
        return {'job_id': job_id, 'status': 'DUPLICATE_IGNORED'}
    db = get_db()
    import_id = job['payload']['import_id']
    doc = db['timeline_imports'].find_one({'import_id': import_id})
    try:
        if not doc:
            raise ValueError('The import no longer exists')
        db['timeline_imports'].update_one({'import_id': import_id}, {'$set': {'status': 'RUNNING'}})
        db['timeline_events'].delete_many({'import_id': import_id})  # a redelivered job starts again
        beat = _heartbeat(job_id)
        parsers, errors = Counter(), []
        batch, imported, untimed, first, last = [], 0, 0, None, None
        for ev in iter_events(Path(doc['path']), doc['format']):
            if ev.get('error'):
                if len(errors) < 20:
                    errors.append(ev['error'])
                continue
            if ev['timestamp'] is None:
                untimed += 1
                continue
            if imported >= MAX_IMPORTED_EVENTS:
                errors.append(f'Only the first {MAX_IMPORTED_EVENTS:,} events with a time were imported')
                break
            parsers[ev['parser'] or 'unknown'] += 1
            first = ev['timestamp'] if first is None or ev['timestamp'] < first else first
            last = ev['timestamp'] if last is None or ev['timestamp'] > last else last
            what = ev['timestamp_desc'] or 'Time'
            batch.append({'case_id': doc['case_id'], 'evidence_id': doc.get('evidence_id'), 'timestamp': ev['timestamp'], 'type': 'PLASO_EVENT',
                          'description': f'[{what}] {ev["message"] or ev["source_name"] or ""}'[:2000], 'source': 'PLASO',
                          'parser': ev['parser'], 'data_type': ev['data_type'], 'timestamp_desc': ev['timestamp_desc'],
                          'source_name': ev['source_name'], 'path': ev['filename'], 'plaso_inode': ev['inode'], 'macb': ev.get('macb'),
                          'import_id': import_id, 'import_line': ev['line'],
                          'nk': hashlib.sha1(f'{import_id}|{ev["line"]}'.encode()).hexdigest()})
            imported += 1
            if len(batch) >= 5000:
                db['timeline_events'].insert_many(batch, ordered=False)
                batch = []
                beat()
                _set_job(job_id, progress=min(95, 5 + imported // 20000), stage=f'{imported:,} events')
                if _is_cancelled(job_id):
                    raise InterruptedError('Cancelled')
        if batch:
            db['timeline_events'].insert_many(batch, ordered=False)
        result = {'import_id': import_id, 'events': imported, 'events_without_time': untimed, 'parsers': dict(parsers.most_common()),
                  'first': first, 'last': last, 'errors': errors}
        db['timeline_imports'].update_one({'import_id': import_id}, {'$set': dict(result, status='COMPLETED', imported_at=datetime.now(timezone.utc))})
        _set_job(job_id, status='COMPLETED', progress=100, stage='complete', result=result, finished_at=datetime.now(timezone.utc))
        _notify(created_by, 'Timeline imported', f'{imported:,} Plaso events from {doc["filename"]} are on the timeline of {doc["case_id"]}.')
        return {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in result.items()}
    except Exception as exc:
        db['timeline_events'].delete_many({'import_id': import_id})
        cancelled = isinstance(exc, InterruptedError)
        db['timeline_imports'].update_one({'import_id': import_id}, {'$set': {'status': 'CANCELLED' if cancelled else 'FAILED', 'error': str(exc)[:1000]}})
        _set_job(job_id, status='CANCELLED' if cancelled else 'FAILED', stage='cancelled' if cancelled else 'failed', error=str(exc)[:2000],
                 finished_at=datetime.now(timezone.utc))
        if not cancelled:
            _notify(created_by, 'Timeline import failed', str(exc)[:300], 'ERROR')
            raise


TASKS_BY_TYPE = {
    'HASH_VERIFY': hash_verify_task,
    'FORENSIC_ANALYSIS': forensic_analysis_task,
    'HASHSET_IMPORT': hashset_import_task,
    'CLAMAV_UPDATE': clamav_update_task,
    'VOLUME_DECRYPT': volume_decrypt_task,
    'TIMELINE_IMPORT': timeline_import_task,
}


@celery_app.task(name='dfip.retention_check')
def retention_check_task():
    """Daily: notifies administrators of closed cases whose retention period has ended (nothing is deleted)."""
    from .services.retention import run_check
    return run_check()
