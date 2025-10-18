from monitoring.models import Asset, Scan, Alert, AttackType
from monitoring.utils.network_utils import ping_host, nmap_scan
from django.utils import timezone
from django.http import HttpResponse
from .scan_runner import run_scans
from .tasks import run_scans_task


def run_scan_view(request):
    run_scans_task.delay()
    return HttpResponse("✅ Scan started in background.")


# Define suspicious ports/services for automatic alerts with descriptions
SUSPICIOUS_SERVICES = {
    21: {"name": "FTP", "desc": "FTP service open – may allow anonymous file transfer"},
    22: {"name": "SSH", "desc": "SSH service open – remote access enabled"},
    23: {"name": "Telnet", "desc": "Telnet service open – unencrypted remote access"},
    445: {"name": "SMB", "desc": "SMB service open – may allow unauthorized file sharing"},
    3389: {"name": "RDP", "desc": "RDP service open – remote desktop accessible"},
}

def run_scans():
    assets = Asset.objects.all()
    all_results = []

    for asset in assets:
        scan_result = {"asset": asset.ip_address, "status": "Unknown", "alerts": []}
        try:
            scan = Scan.objects.create(
                asset=asset,
                scan_type="Active",
                start_time=timezone.now(),
            )

            # Ping
            online = ping_host(asset.ip_address)
            scan_result["status"] = "Online" if online else "Offline"

            # Nmap
            nmap_result = nmap_scan(asset.ip_address)
            scan_result["nmap"] = nmap_result

            # Save scan summary
            scan.result_summary = f"Ping: {scan_result['status']}\nNmap: {nmap_result}"
            scan.end_time = timezone.now()
            scan.save()

            # Alerts
            for port in nmap_result.keys():
                if port in SUSPICIOUS_SERVICES:
                    attack_type, _ = AttackType.objects.get_or_create(
                        name=SUSPICIOUS_SERVICES[port]["name"]
                    )
                    alert = Alert.objects.create(
                        asset=asset,
                        attack_type=attack_type,
                        severity="High",
                        confidence="High",
                        description=f"{SUSPICIOUS_SERVICES[port]['desc']} (port {port})",
                        timestamp=timezone.now()
                    )
                    scan_result["alerts"].append(alert.id)

            all_results.append(scan_result)

        except Exception as e:
            scan_result["error"] = str(e)
            all_results.append(scan_result)

    return all_results