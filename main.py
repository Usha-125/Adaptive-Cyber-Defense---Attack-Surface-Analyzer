from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

from core.os_detection import detect_os
from core.tcp_scanner import tcp_scan, MAX_THREADS
from core.udp_scanner import udp_scan
from reporting.report_generator import generate_json_report
from core.risk_engine import classify_risk
from core.logger import setup_logger
import logging

init(autoreset=True)

def classify_risk(score):
    if score < 4:
        return "LOW"
    elif score < 7:
        return "MEDIUM"
    elif score < 9:
        return "HIGH"
    else:
        return "CRITICAL"

def main():
    setup_logger()
    logging.info("Application started")  
    print(Fore.WHITE + "\n=== Adaptive Cyber Defense Scanner ===\n")

    target = input("Enter target IP or Domain: ")
    start_port = int(input("Start port: "))
    end_port = int(input("End port: "))
    logging.info(f"Target: {target}, Port Range: {start_port}-{end_port}")
    risk_score = [0]   # list used for mutability across threads
    scan_results = []

    start_time = datetime.now()

    print("-" * 70)
    print(Fore.BLUE + f"Scanning Target: {target}")
    print("Scan Started:", start_time)
    print("-" * 70)

    os_result = detect_os(target)
    print(Fore.CYAN + f"Estimated OS: {os_result}")
    print("-" * 70)
    logging.info(f"Detected OS: {os_result}")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(tcp_scan, target, port, risk_score, scan_results)
            executor.submit(udp_scan, target, port, risk_score, scan_results)

    overall = classify_risk(risk_score[0])
    end_time = datetime.now()
    
    print("-" * 70)
    print(Fore.RED + f"Total Risk Score: {risk_score[0]}")
    print(Fore.WHITE + f"Overall Risk Level: {overall}")
    print("Scan Completed:", end_time)
    print("-" * 70)
    logging.info(f"Total Risk Score: {risk_score[0]}")
    logging.info(f"Risk Level: {overall}")
    logging.info("Scan Completed")
    report = {
        "target": target,
        "os_estimate": os_result,
        "scan_start": str(start_time),
        "scan_end": str(end_time),
        "total_risk_score": risk_score[0],
        "risk_level": overall,
        "results": scan_results
    }

    generate_json_report(report)

if __name__ == "__main__":
    main()