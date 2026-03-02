import platform
import subprocess

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