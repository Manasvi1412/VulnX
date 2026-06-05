import socket
import concurrent.futures
from urllib.parse import urlparse

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    27017: "MongoDB"
}

RISK_LEVELS = {
    21: "High", 23: "Critical", 445: "Critical",
    3389: "High", 6379: "High", 27017: "High",
    3306: "Medium", 5432: "Medium", 8888: "Medium",
    22: "Low", 25: "Low", 53: "Low",
    80: "Info", 443: "Info", 8080: "Info", 8443: "Info",
    110: "Low", 143: "Low"
}

def check_port(host, port, timeout=1.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            risk = RISK_LEVELS.get(port, "Info")
            banner = grab_banner(host, port)
            return {
                "port": port,
                "service": service,
                "risk": risk,
                "banner": banner,
                "open": True
            }
    except Exception:
        pass
    return None

def grab_banner(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""

def scan_ports(target_url, max_workers=30):
    parsed = urlparse(target_url)
    host = parsed.netloc or parsed.path
    host = host.replace("www.", "").split(":")[0]

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return [], host, "Could not resolve host"

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_port, host, port): port
            for port in COMMON_PORTS.keys()
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"]), host, ip
