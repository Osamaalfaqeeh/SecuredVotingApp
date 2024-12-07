from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')

app = Celery('myproject')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')


app.conf.update(
    worker_pool='solo',
)
# Automatically discover tasks from installed apps
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'manage-inactive-users-every-day': {
        'task': 'myapp.tasks.manage_inactive_users',
        'schedule': crontab(minute=0, hour=0),  # Runs daily at midnight
    },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
