from monitoring.models import Asset, Scan, Alert, AttackType
from monitoring.utils.network_utils import ping_host, nmap_scan
from django.utils import timezone

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
    for asset in assets:
        # Create a scan record
        scan = Scan.objects.create(
            asset=asset,
            scan_type="Active",
            start_time=timezone.now(),
        )

        result_summary = ""

        # Ping check
        if ping_host(asset.ip_address):
            result_summary += "Ping: Online\n"
        else:
            result_summary += "Ping: Offline\n"

        # Nmap scan
        nmap_result = nmap_scan(asset.ip_address)
        result_summary += f"Nmap Results: {nmap_result}\n"

        # Save scan results
        scan.result_summary = result_summary
        scan.end_time = timezone.now()
        scan.save()

        # Generate alerts for suspicious services
        for port, info in nmap_result.items():
            if port in SUSPICIOUS_SERVICES:
                alert_name = SUSPICIOUS_SERVICES[port]["name"]
                alert_desc = f"{SUSPICIOUS_SERVICES[port]['desc']} on asset {asset}"
                
                Alert.objects.create(
                    asset=asset,
                    scan=scan,
                    attack_type=AttackType.objects.get_or_create(
                        name=alert_name
                    )[0],
                    severity="High",
                    confidence="High",  # Set confidence to High
                    description=alert_desc,
                    timestamp=timezone.now()
                )

        print(f"Scan completed for {asset.ip_address}")
