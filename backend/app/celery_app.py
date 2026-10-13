"""Celery application for DFIP's asynchronous forensic job pipeline.

Replaces the earlier in-process threading.Thread worker loop. Using Celery + Redis
means jobs survive an API process restart, can be scaled across multiple worker
processes/machines, get real retry/visibility semantics, and don't block or get
lost if the API pod is redeployed mid-analysis.
"""
from celery import Celery
from .core.config import settings

celery_app = Celery('dfip', broker=settings.redis_url, backend=settings.redis_url)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.celery_task_time_limit,
    task_soft_time_limit=settings.celery_task_soft_time_limit,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    # With late acks, Redis hands an unacknowledged task to another worker after the visibility timeout (1 hour
    # by default). An analysis may legitimately run for hours, so the timeout must outlast the longest job;
    # a redelivery after a real worker crash is then taken over through the job's heartbeat (tasks._claim).
    broker_transport_options={'visibility_timeout': settings.analysis_time_limit + 3600},
    result_backend_transport_options={'visibility_timeout': settings.analysis_time_limit + 3600},
    # A worker child that grew past ~2 GB (large parsers, big images) is replaced after its task.
    worker_max_memory_per_child=2_000_000,
    broker_connection_retry_on_startup=True,
    # Route forensic work onto its own queue so it can be scaled/monitored
    # separately from any future lightweight queues (e.g. notifications).
    task_default_queue='dfip_forensics',
)

# The daily retention check (services/retention.py), run by the `celery_beat` service at 02:00 UTC.
from celery.schedules import crontab  # noqa: E402
celery_app.conf.beat_schedule = {
    'retention-check': {'task': 'dfip.retention_check', 'schedule': crontab(hour=2, minute=0), 'options': {'queue': 'dfip_forensics'}},
}

# Ensure task modules are registered when the worker boots.
celery_app.autodiscover_tasks(['app'], related_name='tasks')
