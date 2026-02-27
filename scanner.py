import socket
import ssl
import time
import random
import platform
import subprocess
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init

init(autoreset=True)

# ================= CONFIG ================= #

MAX_THREADS = 100
RATE_LIMIT_MIN = 0.01
RATE_LIMIT_MAX = 0.15

common_ports = {
    21: ("FTP", 5),
    22: ("SSH", 3),
    23: ("Telnet", 9),
    25: ("SMTP", 4),
    53: ("DNS", 2),
    80: ("HTTP", 6),
    110: ("POP3", 5),
    143: ("IMAP", 4),
    443: ("HTTPS", 2),
    3306: ("MySQL", 8)
}

# CVSS-based vulnerability database
vuln_db = {
    "OpenSSH_6": {"cve": "CVE-2018-15473", "cvss": 6.5},
    "Apache/2.4.7": {"cve": "CVE-2017-3169", "cvss": 7.5},
    "vsFTPd 2.3.4": {"cve": "CVE-2011-2523", "cvss": 9.8}
}

lock = threading.Lock()

risk_score = 0
scan_results = []


# ================= OS DETECTION ================= #

def detect_os(target):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", target]
        output = subprocess.check_output(command).decode()

        if "TTL=" in output:
            ttl = int(output.split("TTL=")[1].split()[0])
        elif "ttl=" in output:
            ttl = int(output.split("ttl=")[1].split()[0])
        else:
            return "Unknown"

        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Network Device"

    except:
        return "OS Detection Failed"


# ================= VULNERABILITY CHECK ================= #

def check_vulnerabilities(banner):
    global risk_score
    detected = []

    for signature, data in vuln_db.items():
        if signature in banner:
            with lock:
                risk_score += data["cvss"]

            print(Fore.RED + f"    ⚠ Potential Vulnerability: {data['cve']} (CVSS {data['cvss']})")
            detected.append(data)

    return detected


# ================= SERVICE-SPECIFIC BANNER ================= #

def grab_banner(sock, port, target):
    try:
        if port == 80:
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())
            return sock.recv(1024).decode(errors="ignore")

        elif port == 443:
            context = ssl.create_default_context()
            secure_sock = context.wrap_socket(sock, server_hostname=target)
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            secure_sock.send(request.encode())
            return secure_sock.recv(1024).decode(errors="ignore")

        elif port in [21, 22, 25, 110, 143]:
            return sock.recv(1024).decode(errors="ignore")

        else:
            return None

    except:
        return None


# ================= TCP SCAN ================= #

def tcp_scan(target, port):
    global risk_score

    time.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))

    state = "UNKNOWN"
    banner = None
    vulnerabilities = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        result = sock.connect_ex((target, port))

        if result == 0:
            state = "OPEN"
        elif result in [111, 10061]:
            state = "CLOSED"
        else:
            state = "FILTERED"

        if state == "OPEN":
            service, base_risk = common_ports.get(port, ("Unknown", 1))

            with lock:
                risk_score += base_risk

            print(Fore.GREEN + f"[TCP OPEN] Port {port} ({service})")
            print(Fore.YELLOW + f"    Base Risk: +{base_risk}")

            banner = grab_banner(sock, port, target)

            if banner:
                print(Fore.CYAN + f"    Banner: {banner.strip()}")
                vulnerabilities = check_vulnerabilities(banner)

        sock.close()

    except socket.timeout:
        state = "FILTERED"
    except:
        state = "ERROR"

    with lock:
        scan_results.append({
            "port": port,
            "protocol": "TCP",
            "state": state,
            "service": common_ports.get(port, ("Unknown",))[0],
            "banner": banner,
            "vulnerabilities": vulnerabilities
        })


# ================= UDP SCAN ================= #

def udp_scan(target, port):
    global risk_score

    time.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))

    state = "UNKNOWN"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        sock.sendto(b"", (target, port))

        try:
            sock.recvfrom(1024)
            state = "OPEN"
            with lock:
                risk_score += 2
            print(Fore.MAGENTA + f"[UDP OPEN] Port {port}")
        except socket.timeout:
            state = "FILTERED"

        sock.close()

    except:
        state = "ERROR"

    with lock:
        scan_results.append({
            "port": port,
            "protocol": "UDP",
            "state": state,
            "service": common_ports.get(port, ("Unknown",))[0]
        })


# ================= MAIN ================= #

print(Fore.WHITE + "\n=== Advanced Defensive Network Risk Scanner ===\n")

target = input("Enter target IP or Domain: ")
start_port = int(input("Start port: "))
end_port = int(input("End port: "))

start_time = datetime.now()

print("\n" + "-" * 70)
print(Fore.BLUE + f"Scanning Target: {target}")
print("Scan Started:", start_time)
print("-" * 70)

os_result = detect_os(target)
print(Fore.CYAN + f"Estimated OS: {os_result}")
print("-" * 70)

with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
    for port in range(start_port, end_port + 1):
        executor.submit(tcp_scan, target, port)
        executor.submit(udp_scan, target, port)

# ================= RISK CLASSIFICATION ================= #

if risk_score < 4:
    overall = "LOW"
elif risk_score < 7:
    overall = "MEDIUM"
elif risk_score < 9:
    overall = "HIGH"
else:
    overall = "CRITICAL"

end_time = datetime.now()

print("-" * 70)
print(Fore.RED + f"Total Risk Score: {risk_score}")
print(Fore.WHITE + f"Overall Risk Level: {overall}")
print("Scan Completed:", end_time)
print("-" * 70)

# ================= JSON REPORT ================= #

report = {
    "target": target,
    "os_estimate": os_result,
    "scan_start": str(start_time),
    "scan_end": str(end_time),
    "total_risk_score": risk_score,
    "risk_level": overall,
    "results": scan_results
}

with open("defensive_scan_report.json", "w") as f:
    json.dump(report, f, indent=4)

print(Fore.WHITE + "Report saved to defensive_scan_report.json")
#feat: enhance network scanner with SSL detection, CVSS scoring, JSON reporting, and thread safety

#- Added service-specific banner handling (HTTP, HTTPS, FTP, SSH, SMTP)
#- Implemented SSL detection and proper TLS wrapping for port 443
#- Introduced thread-safe locking for shared resources
#- Replaced manual risk scoring with CVSS-based scoring model
#- Added structured JSON report export
#- Implemented TCP port state categorization (Open, Closed, Filtered)
#- Improved protocol correctness and proper Host header handling#
#- Refactored code for better stability and defensive scanning accuracy