import os
from celery import Celery

# Set the default Django settings module for Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'peercast.settings')

# Create the Celery app
app = Celery('peercast')

# Load task settings from Django settings.py, using a 'CELERY_' prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks in installed Django apps
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
