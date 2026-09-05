"""RedPulse - Celery Application Configuration.

Configures Celery with Redis broker for background scan processing.
Isolated worker queues prevent scan jobs from blocking API requests.
"""
from __future__ import annotations

import os
from celery import Celery

# Broker and backend URLs (defaults to Redis on localhost)
BROKER_URL = os.environ.get("CELERY_BROKER_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/1"))
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", os.environ.get("REDIS_URL", "redis://localhost:6379/2"))

# Create Celery app
celery_app = Celery(
    "redpulse",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=[
        "app.services.tasks",
    ],
)

# Celery configuration
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task execution
    task_soft_time_limit=300,    # 5 min soft limit
    task_time_limit=600,         # 10 min hard limit
    task_acks_late=True,         # Ack after execution (safer)
    task_reject_on_worker_lost=True,

    # Worker settings
    worker_prefetch_multiplier=1,  # One task at a time per worker (scan jobs are heavy)
    worker_max_tasks_per_child=50,  # Recycle workers to prevent memory leaks
    worker_concurrency=int(os.environ.get("WORKER_CONCURRENCY", "2")),

    # Retry policy
    task_default_retry_delay=60,
    task_max_retries=3,

    # Result settings
    result_expires=3600,  # Results expire after 1 hour

    # Queue routing
    task_routes={
        "app.services.tasks.run_scan": {"queue": "scans"},
        "app.services.tasks.run_recon": {"queue": "scans"},
        "app.services.tasks.run_pipeline": {"queue": "scans"},
        "app.services.tasks.run_pentest_report": {"queue": "scans"},
        "app.services.tasks.send_notification": {"queue": "default"},
    },

    # Default queue
    task_default_queue="default",

    # Beat schedule for periodic tasks (if needed)
    beat_schedule={
        "cleanup-expired-results": {
            "task": "app.services.tasks.cleanup_expired_results",
            "schedule": 3600.0,  # Every hour
        },
    },
)
