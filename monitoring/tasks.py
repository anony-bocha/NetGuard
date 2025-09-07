from celery import shared_task
from .scan_runner import run_scans

@shared_task(bind=True)
def run_active_scans(self):
    """
    Run all active scans and handle errors gracefully.
    """
    try:
        results = run_scans()  # Ensure run_scans returns a list of results
        if not results:
            print("DEBUG: No scans returned results.")
        else:
            for res in results:
                # Optional: log each scan result
                print("Scan result:", res)
        return "Active scans completed successfully!"
    except Exception as e:
        # Log the exception with full detail
        print(f"ERROR in run_active_scans: {e}")
        # Optionally, retry task if needed
        # self.retry(exc=e, countdown=10, max_retries=3)
        return f"Active scans failed: {e}"
