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
        try:
            # Create a scan record
            scan = Scan.objects.create(
                asset=asset,
                scan_type="Active",
                start_time=timezone.now(),
            )

            result_summary = ""

            # Ping check
            try:
                online = ping_host(asset.ip_address)
                result_summary += f"Ping: {'Online' if online else 'Offline'}\n"
            except Exception as e:
                result_summary += f"Ping: Error ({e})\n"
                print(f"❌ Ping error for {asset.ip_address}: {e}")

            # Nmap scan
            try:
                nmap_result = nmap_scan(asset.ip_address)
                if not isinstance(nmap_result, dict):
                    nmap_result = {}
                result_summary += f"Nmap Results: {nmap_result}\n"
            except Exception as e:
                nmap_result = {}
                result_summary += f"Nmap Results: Error ({e})\n"
                print(f"❌ Nmap error for {asset.ip_address}: {e}")

            # Save scan results
            scan.result_summary = result_summary
            scan.end_time = timezone.now()
            scan.save()

            # Generate alerts for suspicious services
            for port, info in nmap_result.items():
                if port in SUSPICIOUS_SERVICES:
                    try:
                        attack_type, _ = AttackType.objects.get_or_create(
                            name=SUSPICIOUS_SERVICES[port]["name"]
                        )
                        Alert.objects.create(
                            asset=asset,
                            attack_type=attack_type,
                            severity="High",
                            confidence="High",
                            description=f"{SUSPICIOUS_SERVICES[port]['desc']} (port {port})",
                            timestamp=timezone.now()
                        )
                    except Exception as e:
                        print(f"❌ Alert creation failed for {asset.ip_address} port {port}: {e}")

            print(f"✅ Scan completed for {asset.ip_address}")

        except Exception as e:
            print(f"❌ Unexpected error during scan for {asset.ip_address}: {e}")
