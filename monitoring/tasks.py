from celery import shared_task
from .scan_runner import run_scans

@shared_task
def run_active_scans():
    run_scans()
    return "Active scans completed!"
