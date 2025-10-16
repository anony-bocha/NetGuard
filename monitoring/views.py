from django.shortcuts import render
from monitoring.models import Scan, Alert

def dashboard(request):
    # Get the latest 10 scans
    scans = Scan.objects.order_by('-start_time')[:10]
    # Get the latest 10 alerts
    alerts = Alert.objects.order_by('-timestamp')[:10]

    context = {
        'scans': scans,
        'alerts': alerts
    }
    return render(request, 'monitoring/dashboard.html', context)
