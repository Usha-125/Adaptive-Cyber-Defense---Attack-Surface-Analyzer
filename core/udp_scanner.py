import socket
import time
import random
import threading
from colorama import Fore
import logging

lock = threading.Lock()

RATE_LIMIT_MIN = 0.01
RATE_LIMIT_MAX = 0.15

def udp_scan(target, port, risk_score, scan_results):
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
                risk_score[0] += 2
            print(Fore.MAGENTA + f"[UDP OPEN] Port {port}")
            logging.info(f"UDP OPEN: Port {port}")   # <-- Added logging here

        except socket.timeout:
            state = "FILTERED"

        sock.close()

    except:
        state = "ERROR"

    with lock:
        scan_results.append({
            "port": port,
            "protocol": "UDP",
            "state": state
        })