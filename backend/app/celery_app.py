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
    broker_connection_retry_on_startup=True,
    # Route forensic work onto its own queue so it can be scaled/monitored
    # separately from any future lightweight queues (e.g. notifications).
    task_default_queue='dfip_forensics',
)

# Ensure task modules are registered when the worker boots.
celery_app.autodiscover_tasks(['app'], related_name='tasks')
