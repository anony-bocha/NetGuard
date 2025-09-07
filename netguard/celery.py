from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netguard.settings')

app = Celery('netguard')

# Load settings from Django
app.config_from_object('django.conf:settings', namespace='CELERY')

# Autodiscover tasks in all apps
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
