import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import subprocess
import platform

init(autoreset=True)

open_ports = []
udp_open_ports = []

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL"
}


# ---------------- OS DETECTION ---------------- #

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


# ---------------- TCP SCAN ---------------- #

def tcp_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            service = common_ports.get(port, "Unknown")
            print(Fore.GREEN + f"[TCP OPEN] Port {port} ({service})")

            open_ports.append(port)

            try:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                banner = sock.recv(1024).decode().strip()
                if banner:
                    print(Fore.CYAN + f"    Banner: {banner}")
            except:
                pass

        sock.close()

    except:
        pass


# ---------------- UDP SCAN ---------------- #

def udp_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        sock.sendto(b"", (target, port))

        try:
            data, _ = sock.recvfrom(1024)
            print(Fore.YELLOW + f"[UDP OPEN] Port {port}")
            udp_open_ports.append(port)
        except socket.timeout:
            pass

        sock.close()

    except:
        pass


# ---------------- MAIN ---------------- #

target = input("Enter target IP: ")
start_port = int(input("Start port: "))
end_port = int(input("End port: "))

print("\n" + "-" * 60)
print(Fore.MAGENTA + f"Scanning Target: {target}")
print("Scan started at:", datetime.now())
print("-" * 60)

# OS Detection
os_result = detect_os(target)
print(Fore.BLUE + f"Detected OS (Estimated): {os_result}")
print("-" * 60)

# Thread Pool (MAX 100 threads)
with ThreadPoolExecutor(max_workers=100) as executor:
    for port in range(start_port, end_port + 1):
        executor.submit(tcp_scan, target, port)
        executor.submit(udp_scan, target, port)

print("-" * 60)
print(Fore.GREEN + f"Total TCP Open Ports: {len(open_ports)}")
print(Fore.YELLOW + f"Total UDP Open Ports: {len(udp_open_ports)}")
print("Scan completed at:", datetime.now())
print("-" * 60)

# Save results
with open("advanced_scan_results.txt", "w") as file:
    file.write(f"Target: {target}\n")
    file.write(f"Estimated OS: {os_result}\n")
    file.write(f"TCP Open Ports: {open_ports}\n")
    file.write(f"UDP Open Ports: {udp_open_ports}\n")

print(Fore.WHITE + "Results saved to advanced_scan_results.txt")