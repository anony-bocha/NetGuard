import subprocess
import platform
import nmap
def ping_host(ip, count=1, timeout=1000):  
    """
    Ping a host to check if it's online.
    Returns True if reachable, False otherwise.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, str(count), "-w", str(timeout), ip]

    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.returncode == 0
    except Exception as e:
        print(f"Ping error for {ip}: {e}")
        return False
def nmap_scan(ip_address):
    """
    Scan the target IP and return a dictionary of open ports and services.
    Works reliably on Windows.
    """
    nm = nmap.PortScanner()
    try:
        # Use TCP Connect scan (-sT) for Windows
        nm.scan(ip_address, arguments='-sT -sV -Pn')  
        result = {}

        if ip_address in nm.all_hosts():
            for proto in nm[ip_address].all_protocols():
                ports = nm[ip_address][proto].keys()
                for port in ports:
                    service = nm[ip_address][proto][port]['name']
                    state = nm[ip_address][proto][port]['state']
                    result[port] = {'service': service, 'state': state}

        return result

    except Exception as e:
        print(f"Nmap scan error: {e}")
        return {}