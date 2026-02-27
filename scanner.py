import socket
from datetime import datetime
from threading import Thread

def grab_banner(sock, port):
    try:
        # Try sending HTTP request (works for web servers)
        if port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")

        banner = sock.recv(1024).decode().strip()
        return banner
    except:
        return None


def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"[+] Port {port} is OPEN")

            banner = grab_banner(sock, port)
            if banner:
                print(f"    Banner: {banner}")

        sock.close()

    except:
        pass


target = input("Enter target IP: ")

print(f"\nScanning target: {target}")
print("Scanning started at:", datetime.now())
print("-" * 50)

threads = []

for port in range(1, 101):
    thread = Thread(target=scan_port, args=(target, port))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()

print("-" * 50)
print("Scanning completed at:", datetime.now())