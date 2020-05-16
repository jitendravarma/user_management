import os

from celery import Celery
from kombu import Exchange, Queue

from django.conf import settings

QUEUE_DEFAULT = 'default'
CELERY_ENABLE_UTC = True
CELERY_ACCEPT_CONTENT = ["pickle"]

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'user_management.settings.local')

app = Celery('user_management')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

app.conf.update(
    CELERY_QUEUES=(
        Queue(QUEUE_DEFAULT, Exchange('default'), routing_key='default'),
    ),
    CELERY_IGNORE_RESULT=True,
    CELERYD_PREFETCH_MULTIPLIER=1,
    CELERY_DEFAULT_QUEUE=QUEUE_DEFAULT,
    CELERY_DEFAULT_EXCHANGE_TYPE='direct',
    CELERY_DEFAULT_ROUTING_KEY='default',
)


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
