from monitoring.models import Asset, Scan, Alert, AttackType
from monitoring.utils.network_utils import ping_host, nmap_scan
from django.utils import timezone

def run_scans():
    """
    Run scans for all assets, save results, and generate alerts.
    """
    assets = Asset.objects.all()
    
    for asset in assets:
        result_summary = ""
        alert_needed = False
        alert_description = ""
        severity = "Medium"

        # --- Ping Scan ---
        online = ping_host(asset.ip_address)
        asset.status = "Online" if online else "Offline"
        asset.last_seen = timezone.now()
        asset.save()

        result_summary += f"Ping: {'Online' if online else 'Offline'}\n"

        if not online:
            alert_needed = True
            alert_description += "Asset is offline.\n"
            severity = "High"

        # --- Nmap Scan ---
        nmap_result = nmap_scan(asset.ip_address)
        result_summary += f"Nmap: {nmap_result}\n"

        if nmap_result:  # If any ports detected
            alert_needed = True
            alert_description += f"Open ports detected: {nmap_result}\n"
            severity = "Medium"

        # --- Save Scan Record ---
        scan = Scan.objects.create(
            asset=asset,
            scan_type="Active",
            start_time=timezone.now(),
            end_time=timezone.now(),
            result_summary=result_summary
        )

        # --- Create Alert if Needed ---
        if alert_needed:
            attack_type, _ = AttackType.objects.get_or_create(
                name="Suspicious Activity",
                defaults={"description": "Detected suspicious network activity", "severity": severity}
            )
            Alert.objects.create(
                asset=asset,
                attack_type=attack_type,
                severity=severity,
                confidence="High",
                description=alert_description,
                timestamp=timezone.now()
            )
