attack_surface_map = {
    "FTP": {
        "attacks": ["Anonymous Login", "Brute Force Attack", "Directory Traversal"],
        "defense": "Disable anonymous login, enforce strong passwords, restrict IP access"
    },
    "SSH": {
        "attacks": ["Credential Stuffing", "Dictionary Attack", "Port Scanning"],
        "defense": "Use key-based authentication, disable root login, enable fail2ban"
    },
    "HTTP": {
        "attacks": ["SQL Injection", "Cross-Site Scripting (XSS)", "Directory Traversal"],
        "defense": "Use input validation, WAF, secure coding practices"
    },
    "HTTPS": {
        "attacks": ["SSL Stripping", "TLS Misconfiguration"],
        "defense": "Enforce TLS 1.2+, disable weak ciphers"
    },
    "MySQL": {
        "attacks": ["Database Dump", "Privilege Escalation"],
        "defense": "Strong credentials, restrict remote access, patch DB engine"
    },
    "SMTP": {
        "attacks": ["Open Relay Abuse", "Email Spoofing"],
        "defense": "Enable SPF, DKIM, disable open relay"
    }
}

def analyze_attack_surface(service_name):
    return attack_surface_map.get(service_name, None)