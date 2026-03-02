from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore
import logging

from core.os_detection import detect_os
from core.tcp_scanner import tcp_scan, MAX_THREADS
from core.udp_scanner import udp_scan
from core.risk_engine import classify_risk
from core.logger import setup_logger
from reporting.report_generator import generate_json_report
from reporting.html_report import generate_html_report

init(autoreset=True)


def load_targets():
    try:
        with open("targets.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        target = input("Enter target IP or Domain: ")
        return [target]


def main():
    setup_logger()
    logging.info("Application started")

    targets = load_targets()
    start_port = int(input("Start port: "))
    end_port = int(input("End port: "))

    full_report = []

    for target in targets:

        print(Fore.BLUE + f"\nScanning Target: {target}")
        logging.info(f"Scanning Target: {target}")

        risk_score = [0]
        scan_results = []

        start_time = datetime.now()
        os_result = detect_os(target)

        logging.info(f"Detected OS: {os_result}")

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(tcp_scan, target, port, risk_score, scan_results)
                executor.submit(udp_scan, target, port, risk_score, scan_results)

        overall = classify_risk(risk_score[0])
        end_time = datetime.now()

        logging.info(f"Risk Score: {risk_score[0]}")
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

        full_report.append(report)

    generate_json_report(full_report)
    generate_html_report(full_report)

    print(Fore.GREEN + "\nEnterprise Scan Completed.")


if __name__ == "__main__":
    main()