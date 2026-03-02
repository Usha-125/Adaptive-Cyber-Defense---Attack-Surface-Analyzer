import socket
import time
import random
import json
import threading
from colorama import Fore

from core.banner_grabber import grab_banner
from core.risk_engine import calculate_vulnerability_risk
from intelligence.threat_mapper import analyze_attack_surface

lock = threading.Lock()

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


# ================= LOAD VULNERABILITY DB ================= #

def load_vuln_db():
    with open("intelligence/vuln_database.json", "r") as f:
        return json.load(f)


# ================= VULNERABILITY CHECK ================= #

def check_vulnerabilities(banner, vuln_db, risk_score):
    detected = []

    for signature, data in vuln_db.items():
        if signature in banner:
            vuln_risk = calculate_vulnerability_risk(data)

            print(Fore.RED + f"    ⚠ Vulnerability Found: {data['cve']}")
            print(f"       Severity: {data['severity']}")
            print(f"       CVSS: {data['cvss']}")
            print(f"       Exploit Available: {data['exploit_available']}")
            print(f"       Mitigation: {data['mitigation']}")
            print(f"       Risk Added: +{vuln_risk}")

            with lock:
                risk_score[0] += vuln_risk

            detected.append(data)

    return detected


# ================= TCP SCAN ================= #

def tcp_scan(target, port, risk_score, scan_results):

    time.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))

    state = "UNKNOWN"
    banner = None
    vulnerabilities = []
    attack_info = None

    vuln_db = load_vuln_db()

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

        # ================= IF OPEN ================= #

        if state == "OPEN":

            service, base_risk = common_ports.get(port, ("Unknown", 1))

            with lock:
                risk_score[0] += base_risk

            print(Fore.GREEN + f"[TCP OPEN] Port {port} ({service})")
            print(Fore.YELLOW + f"    Base Risk: +{base_risk}")

            # -------- Attack Surface Mapping -------- #
            attack_info = analyze_attack_surface(service)

            if attack_info:
                print("    🎯 Attack Surface Exposure:")
                for attack in attack_info["attacks"]:
                    print(f"       - {attack}")

                print(f"       🛡 Recommended Defense: {attack_info['defense']}")

            # -------- Banner Grabbing -------- #
            banner = grab_banner(sock, port, target)

            if banner:
                print(Fore.CYAN + f"    Banner: {banner.strip()}")
                vulnerabilities = check_vulnerabilities(
                    banner, vuln_db, risk_score
                )

        sock.close()

    except socket.timeout:
        state = "FILTERED"
    except Exception as e:
        state = "ERROR"

    # ================= STORE RESULT ================= #

    with lock:
        scan_results.append({
            "port": port,
            "protocol": "TCP",
            "state": state,
            "service": common_ports.get(port, ("Unknown",))[0],
            "banner": banner,
            "vulnerabilities": vulnerabilities,
            "attack_surface": attack_info
        })